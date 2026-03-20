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
  
  func authenticate(fetchRequest: FetchedRequest) async throws -> Client {
    switch fetchRequest {
    case .plain(let requestObject):
      guard let clientId = requestObject.clientId else {
        throw ValidationError.validationError("clientId is missing from plain request")
      }
      return try await getClient(
        clientId: clientId,
        config: config
      )
    case .jwtSecured(let clientId, let jwt):
      return try await getClient(
        clientId: clientId,
        jwt: jwt,
        config: config
      )
    }
  }
  
  func getClient(
    clientId: String?,
    jwt: JWTString,
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
      ) ?? config?.supportedClientIdSchemes.first
    else {
      throw ValidationError.validationError("No supported client Id scheme")
    }
    
    switch scheme {
    case .preregistered(let clients):
      guard let client = clients[verifierId.originalClientId] else {
        throw ValidationError.validationError("preregistered client not found")
      }
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
      
      if expectedHash != verifierId.originalClientId {
        throw ValidationError.validationError("ClientId does not match leaf certificate's SHA-256 hash")
      }
      
      return .x509Hash(
        clientId: clientId,
        certificate: certificate
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
      
      return .x509SanDns(
        clientId: clientId,
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
        clientId: clientId
      )
    case .redirectUri:
      return .redirectUri(
        clientId: clientId
      )
    }
  }
  
  func getClient(
    clientId: String,
    config: OpenId4VPConfiguration?
  ) async throws -> Client {
    guard
      let verifierId = try? VerifierId.parse(clientId: clientId).get(),
      let scheme = config?.supportedClientIdSchemes.first(
        where: { $0.scheme.rawValue == verifierId.scheme.rawValue }
      ) ?? config?.supportedClientIdSchemes.first
    else {
      throw ValidationError.validationError("No supported client Id scheme")
    }
    
    switch scheme {
    case .preregistered(let clients):
      guard let client = clients[clientId] else {
        throw ValidationError.validationError("preregistered client not found")
      }
      return .preRegistered(
        clientId: clientId,
        legalName: client.legalName
      )
    case .redirectUri:
      return .redirectUri(
        clientId: clientId
      )
      
    default:
      throw ValidationError.validationError("Scheme \(scheme) not supported")
    }
  }
  
  private func verifierAttestation(
    jwt: JWTString,
    supportedScheme: SupportedClientIdPrefix,
    clientId: String
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
