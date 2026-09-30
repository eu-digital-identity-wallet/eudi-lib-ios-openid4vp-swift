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
        throw ValidationError.missingClientId
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
      throw ValidationError.missingClientId
    }

    guard !clientId.isEmpty else {
      throw ValidationError.missingClientId
    }

    guard
      let verifierId = try? VerifierId.parse(clientId: clientId).get(),
      let scheme = config?.supportedClientIdSchemes.first(
        where: { $0.scheme.rawValue == verifierId.scheme.rawValue }
      ) ?? config?.supportedClientIdSchemes.first(where: {
        return switch $0 {
          case .preregistered: true
          case .redirectUri: true
          case .decentralizedIdentifier: true
          default: false
        }
    })
    else {
      throw ValidationError.unsupportedClientIdScheme(clientId)
    }

    // Determine the response destination (response_uri or redirect_uri depending on response mode)
    let responseDestination = responseUri ?? redirectUri

    switch scheme {
    case .preregistered(let clients):
      // Look up client from the pre-registered scheme
      guard let key = clients.keys.first, let client = clients[key] else {
        throw ValidationError.preregisteredClientNotFound(clientId: clientId)
      }
      // Preregistered clients are explicitly trusted by wallet configuration
      return .preRegistered(
        clientId: client.clientId,
        legalName: client.legalName
      )

    case .x509Hash:
      guard let jws = try? JWS(compactSerialization: jwt) else {
        throw ValidationError.invalidRequestSignature("Unable to process JWT")
      }

      guard let chain: [String] = jws.header.x5c else {
        throw ValidationError.missingCertificateInHeader
      }

      let certificates: [Certificate] = try parseCertificates(from: chain)
      guard
        let certificate = certificates.first,
        let expectedHash = try? certificate.hashed()
      else {
        throw ValidationError.untrustedCertificateChain("No valid certificate in chain")
      }

      guard expectedHash == verifierId.originalClientId else {
        throw ValidationError.clientIdCertificateHashMismatch(
          clientId: verifierId.originalClientId,
          expectedHash: expectedHash
        )
      }

      // For x509_hash, the certificate hash IS the authentication.
      // No additional response_uri binding needed.
      return .x509Hash(
        clientId: verifierId.originalClientId,
        authenticationCertificate: certificate
      )

    case .x509SanDns:
      guard let jws = try? JWS(compactSerialization: jwt) else {
        throw ValidationError.invalidRequestSignature("Unable to process JWT")
      }

      guard let chain: [String] = jws.header.x5c else {
        throw ValidationError.missingCertificateInHeader
      }

      let certificates: [Certificate] = try parseCertificates(from: chain)
      guard let certificate = certificates.first else {
        throw ValidationError.untrustedCertificateChain("No certificate in chain")
      }

      // Extract DNS SANs from certificate
      let dnsNames = try certificate.extensions.subjectAlternativeNames?
        .rawSubjectAlternativeNames() ?? []

      guard !dnsNames.isEmpty else {
        throw ValidationError.untrustedCertificateChain("Certificate missing DNS names in Subject Alternative Names")
      }

      // Verify client_id (dns name) is in the certificate's DNS SANs
      guard dnsNames.contains(verifierId.originalClientId) else {
        throw ValidationError.clientIdNotInCertificateSAN(
          clientId: verifierId.originalClientId,
          certificateSANs: dnsNames
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

    case .decentralizedIdentifier(_, let keyLookup):
      // Use the client_id from the request, not from configuration
      return try await didPublicKeyLookup(
        jws: try JWS(compactSerialization: jwt),
        clientId: verifierId.originalClientId,
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
      throw ValidationError.unsupportedClientIdScheme(clientId)
    }

    // Determine the response destination
    let responseDestination = responseUri ?? redirectUri

    // Per OpenID4VP spec, only redirect_uri scheme allows unsigned (plain) requests.
    // All other schemes (preregistered, x509, verifier_attestation, DID) require signed JAR.
    switch scheme {
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
      // Reject unsigned requests for all other schemes
      throw ValidationError.unsignedRequestNotPermitted(scheme: scheme.scheme.rawValue)
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
      throw ValidationError.invalidVerifierAttestation("Scheme should be verifier attestation")
    }

    guard let jws = try? JWS(compactSerialization: jwt) else {
      throw ValidationError.invalidRequestSignature("Unable to process JWT")
    }

    let expectedType = JOSEObjectType(rawValue: "verifier-attestation+jwt")
    guard jws.header.typ == expectedType?.rawValue else {
      throw ValidationError.invalidVerifierAttestation("verifier-attestation+jwt not found in JWT header")
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
      throw ValidationError.invalidDIDUrl("kid not found in JWT header")
    }

    guard let keyUrl = AbsoluteDIDUrl.parse(kid) else {
      throw ValidationError.invalidDIDUrl(kid)
    }

    // Parse the client_id as a DID
    guard let clientIdAsDID = DID.parse(clientId) else {
      throw ValidationError.invalidDIDUrl("client_id '\(clientId)' is not a valid DID")
    }

    // Extract the base DID from the kid URL
    guard let kidBaseDID = keyUrl.did else {
      throw ValidationError.invalidDIDUrl("Could not extract base DID from kid '\(kid)'")
    }

    // The kid's base DID must exactly match the client_id DID
    guard kidBaseDID.string == clientIdAsDID.string else {
      throw ValidationError.didClientIdMismatch(
        kidDID: kidBaseDID.string,
        clientIdDID: clientIdAsDID.string
      )
    }

    // Pass the full AbsoluteDIDUrl (with fragment) to the lookup agent
    // so it can resolve the specific verification method
    guard let publicKey = await keyLookup.resolveKey(from: keyUrl) else {
      throw ValidationError.publicKeyResolutionFailed("Unable to resolve public key from DID URL '\(kid)'")
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
      throw ValidationError.responseUriBindingFailed(
        "response_uri/redirect_uri must have a valid host"
      )
    }

    guard responseHost == originalClientId else {
      throw ValidationError.responseUriBindingFailed(
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
      throw ValidationError.responseUriBindingFailed(
        "redirect_uri scheme requires response_uri or redirect_uri to be present"
      )
    }

    // The client_id (after stripping prefix) should equal the response destination URL
    guard clientId == responseDestination.absoluteString else {
      throw ValidationError.responseUriBindingFailed(
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
          throw ValidationError.responseUriBindingFailed(
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
          throw ValidationError.responseUriBindingFailed(
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
