/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@preconcurrency import Foundation
import JOSESwift
import X509
import SwiftASN1
import CryptoKit

internal actor ClientAuthenticator {

  let config: OpenId4VPConfiguration

  init(config: OpenId4VPConfiguration) {
    self.config = config
  }

  func authenticate(
    fetchRequest: FetchedRequest,
    responseUri: URL?,
    redirectUri: URL?
  ) async throws -> Client {
    switch fetchRequest {
    case .plain(let requestObject):
      guard let clientId = requestObject.clientId else {
        throw ValidationError.validationError("clientId is missing from plain request")
      }
      // For plain requests, use URIs from request object if not provided
      let effectiveResponseUri = responseUri ?? requestObject.responseUri.flatMap { URL(string: $0) }
      let effectiveRedirectUri = redirectUri ?? requestObject.redirectUri.flatMap { URL(string: $0) }
      return try await getClient(
        clientId: clientId,
        responseUri: effectiveResponseUri,
        redirectUri: effectiveRedirectUri,
        config: config
      )
    case .jwtSecured(let clientId, let jwt):
      return try await getClient(
        clientId: clientId,
        jwt: jwt,
        responseUri: responseUri,
        redirectUri: redirectUri,
        config: config
      )
    }
  }
  
  func getClient(
    clientId: String?,
    jwt: JWTString,
    responseUri: URL?,
    redirectUri: URL?,
    config: OpenId4VPConfiguration?
  ) async throws -> Client {

    guard let clientId else {
      throw ValidationError.validationError("clientId is missing")
    }

    guard !clientId.isEmpty else {
      throw ValidationError.validationError("clientId is missing")
    }

    guard
      let verifierId = try? VerifierId.parse(clientId: clientId).get(),
      let scheme = config?.supportedClientIdSchemes.first(
        where: { $0.scheme.rawValue == verifierId.scheme.rawValue }
      )
    else {
      throw ValidationError.validationError("Unsupported client_id scheme: no matching scheme configured")
    }

    // Determine the response destination (response_uri or redirect_uri depending on response mode)
    let responseDestination = responseUri ?? redirectUri

    switch scheme {
    case .preregistered(let clients):
      guard
        let key = clients.keys.first,
        let client = clients[key]
      else {
        throw ValidationError.validationError("preregistered client not found")
      }
      // Preregistered clients are explicitly trusted by wallet configuration
      return .preRegistered(
        clientId: client.clientId,
        legalName: client.legalName
      )

    case .x509Hash:
      guard let jws = try? JWS(compactSerialization: jwt) else {
        throw ValidationError.validationError("Unable to process JWT")
      }

      guard let chain: [String] = jws.header.x5c else {
        throw ValidationError.validationError("No certificate in header")
      }

      let certificates: [Certificate] = parseCertificates(from: chain)
      guard
        let certificate = certificates.first,
        let expectedHash = try? certificate.hashed()
      else {
        throw ValidationError.validationError("No valid certificate in chain")
      }

      guard expectedHash == verifierId.originalClientId else {
        throw ValidationError.validationError("ClientId does not match leaf certificate's SHA-256 hash")
      }

      // For x509_hash, the certificate hash IS the authentication.
      // No additional response_uri binding needed.
      return .x509Hash(
        clientId: verifierId.originalClientId,
        authenticationCertificate: certificate
      )

    case .x509SanDns:
      guard let jws = try? JWS(compactSerialization: jwt) else {
        throw ValidationError.validationError("Unable to process JWT")
      }

      guard let chain: [String] = jws.header.x5c else {
        throw ValidationError.validationError("No certificate in header")
      }

      let certificates: [Certificate] = parseCertificates(from: chain)
      guard let certificate = certificates.first else {
        throw ValidationError.validationError("No certificate in chain")
      }

      // Extract DNS SANs from certificate
      let dnsNames = try certificate.extensions.subjectAlternativeNames?
        .rawSubjectAlternativeNames() ?? []

      guard !dnsNames.isEmpty else {
        throw ValidationError.validationError("Certificate missing DNS names in Subject Alternative Names")
      }

      // Verify client_id (dns name) is in the certificate's DNS SANs
      guard dnsNames.contains(verifierId.originalClientId) else {
        throw ValidationError.validationError(
          "ClientId '\(verifierId.originalClientId)' not found in certificate's subject alternative names"
        )
      }

      // Bind response_uri to the authenticated client_id (dns name)
      try validateResponseUriMatchesClientId(
        responseDestination: responseDestination,
        originalClientId: verifierId.originalClientId
      )

      return .x509SanDns(
        clientId: verifierId.originalClientId,
        certificate: certificate
      )

    case .decentralizedIdentifier(let did, let keyLookup):
      return try await didPublicKeyLookup(
        jws: try JWS(compactSerialization: jwt),
        clientId: did.string,
        keyLookup: keyLookup
      )

    case .verifierAttestation:
      return try verifierAttestation(
        jwt: jwt,
        supportedScheme: scheme,
        clientId: verifierId.originalClientId,
        responseUri: responseUri,
        redirectUri: redirectUri
      )
    case .redirectUri:
      // redirect_uri scheme should not reach here for JWT-secured requests
      // (rejected in AccessValidator), but if it does, validate binding
      try validateRedirectUriSchemeBinding(
        clientId: verifierId.originalClientId,
        responseDestination: responseDestination
      )
      return .redirectUri(
        clientId: verifierId.originalClientId
      )
    }
  }
  
  func getClient(
    clientId: String,
    responseUri: URL?,
    redirectUri: URL?,
    config: OpenId4VPConfiguration?
  ) async throws -> Client {
    guard
      let verifierId = try? VerifierId.parse(clientId: clientId).get(),
      let scheme = config?.supportedClientIdSchemes.first(
        where: { $0.scheme.rawValue == verifierId.scheme.rawValue }
      )
    else {
      throw ValidationError.validationError("Unsupported client_id scheme: no matching scheme configured")
    }

    // Determine the response destination
    let responseDestination = responseUri ?? redirectUri
    
    switch scheme {
    case .preregistered(let clients):
      guard let client = clients[clientId] else {
        throw ValidationError.validationError("preregistered client not found")
      }
      // Preregistered clients are explicitly trusted by wallet configuration
      return .preRegistered(
        clientId: clientId,
        legalName: client.legalName
      )
    case .redirectUri:
      // For redirect_uri scheme, client_id must equal the response destination
      try validateRedirectUriSchemeBinding(
        clientId: verifierId.originalClientId,
        responseDestination: responseDestination
      )
      return .redirectUri(
        clientId: verifierId.originalClientId
      )

    default:
      throw ValidationError.validationError("Scheme \(scheme) not supported for plain (unsigned) requests")
    }
  }
  
  private func verifierAttestation(
    jwt: JWTString,
    supportedScheme: SupportedClientIdPrefix,
    clientId: String,
    responseUri: URL?,
    redirectUri: URL?
  ) throws -> Client {
    guard case let .verifierAttestation(verifier, clockSkew) = supportedScheme else {
      throw ValidationError.validationError("Scheme should be verifier attestation")
    }

    guard let jws = try? JWS(compactSerialization: jwt) else {
      throw ValidationError.validationError("Unable to process JWT")
    }

    let expectedType = JOSEObjectType(rawValue: "verifier-attestation+jwt")
    guard jws.header.typ == expectedType?.rawValue else {
      throw ValidationError.validationError("verifier-attestation+jwt not found in JWT header")
    }

    _ = try jws.validate(using: verifier)
    let claims = try jws.verifierAttestationClaims()

    try TimeChecks(skew: clockSkew)
      .verify(
        claimsSet: .init(
          issuer: claims.iss,
          subject: claims.sub,
          audience: [],
          expirationTime: claims.exp,
          notBeforeTime: Date(),
          issueTime: claims.iat,
          jwtID: nil,
          claims: [:]
        )
      )

    // Validate response_uri/redirect_uri is in attestation's allowed URIs
    try validateVerifierAttestationUriBinding(
      responseUri: responseUri,
      redirectUri: redirectUri,
      allowedResponseUris: claims.responseUris,
      allowedRedirectUris: claims.redirectUris
    )

    return .attested(clientId: clientId)
  }
  
  private func didPublicKeyLookup(
    jws: JWS,
    clientId: String,
    keyLookup: DIDPublicKeyLookupAgentType
  ) async throws -> Client {
    
    guard let kid = jws.header.kid else {
      throw ValidationError.validationError("kid not found in JWT header")
    }
    
    guard
      let keyUrl = AbsoluteDIDUrl.parse(kid),
      keyUrl.string.hasPrefix(clientId)
    else {
      throw ValidationError.validationError("kid not found in JWT header")
    }
    
    guard let clientIdAsDID = DID.parse(clientId) else {
      throw ValidationError.validationError("Invalid DID")
    }
    
    guard let publicKey = await keyLookup.resolveKey(from: clientIdAsDID) else {
      throw ValidationError.validationError("Unable to extract public key from DID")
    }
    
    try jws.verifyJWS(
      publicKey: publicKey
    )

    return .didClient(
      did: clientIdAsDID
    )
  }

  // MARK: - Response URI Binding Validation

  /// Validates that the response destination host matches the authenticated client_id.
  /// For x509_san_dns, the client_id (dns name) is validated against the certificate's
  /// dNSName SANs per RFC5280. The response_uri host must match this authenticated identity.
  private func validateResponseUriMatchesClientId(
    responseDestination: URL?,
    originalClientId: String
  ) throws {
    guard let responseDestination = responseDestination else {
      // No response destination to validate - this will be caught later in the flow
      return
    }

    guard let responseHost = responseDestination.host else {
      throw ValidationError.validationError(
        "response_uri/redirect_uri must have a valid host"
      )
    }

    guard responseHost == originalClientId else {
      throw ValidationError.validationError(
        "response_uri host '\(responseHost)' must match client_id '\(originalClientId)'"
      )
    }
  }

  /// Validates that for redirect_uri scheme, the client_id equals the response destination.
  /// Per OpenID4VP spec, this equality IS the authentication for redirect_uri scheme.
  private func validateRedirectUriSchemeBinding(
    clientId: String,
    responseDestination: URL?
  ) throws {
    guard let responseDestination = responseDestination else {
      throw ValidationError.validationError(
        "redirect_uri scheme requires response_uri or redirect_uri to be present"
      )
    }

    // The client_id (after stripping prefix) should equal the response destination URL
    guard clientId == responseDestination.absoluteString else {
      throw ValidationError.validationError(
        "For redirect_uri scheme, client_id must equal response_uri/redirect_uri. " +
        "client_id: '\(clientId)', response destination: '\(responseDestination.absoluteString)'"
      )
    }
  }

  /// Validates that the response_uri/redirect_uri is in the verifier attestation's allowed URIs.
  private func validateVerifierAttestationUriBinding(
    responseUri: URL?,
    redirectUri: URL?,
    allowedResponseUris: [String]?,
    allowedRedirectUris: [String]?
  ) throws {
    // Check response_uri if present
    if let responseUri = responseUri {
      let responseUriString = responseUri.absoluteString
      if let allowedResponseUris = allowedResponseUris, !allowedResponseUris.isEmpty {
        guard allowedResponseUris.contains(responseUriString) else {
          throw ValidationError.validationError(
            "response_uri '\(responseUriString)' is not in verifier attestation's allowed response_uris"
          )
        }
      }
      // If response_uris claim is nil/empty, we allow any response_uri (per spec flexibility)
    }

    // Check redirect_uri if present
    if let redirectUri = redirectUri {
      let redirectUriString = redirectUri.absoluteString
      if let allowedRedirectUris = allowedRedirectUris, !allowedRedirectUris.isEmpty {
        guard allowedRedirectUris.contains(redirectUriString) else {
          throw ValidationError.validationError(
            "redirect_uri '\(redirectUriString)' is not in verifier attestation's allowed redirect_uris"
          )
        }
      }
      // If redirect_uris claim is nil/empty, we allow any redirect_uri (per spec flexibility)
    }
  }
}

private extension Certificate {
  
  func hashed() throws -> String {
    var serializer = DER.Serializer()
    try serializer
      .serialize(
        self
      )
    let der = Data(
      serializer.serializedBytes
    )
    let digest = SHA256.hash(
      data: der
    )
    return Data(
      digest
    ).base64URLEncodedString
  }
}
