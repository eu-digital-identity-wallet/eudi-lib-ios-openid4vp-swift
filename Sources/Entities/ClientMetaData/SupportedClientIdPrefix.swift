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
import Foundation
@preconcurrency import JOSESwift

public enum SupportedClientIdPrefix: @unchecked Sendable {
  public var scheme: ClientIdPrefix {
    switch self {

    /**
      * The Client Identifier is known to the Wallet in advance of the Authorization Request.
      */
    case .preregistered:
      return .preRegistered
    case .x509SanDns:
      return .x509SanDns
    case .x509Hash:
      return .x509Hash
    case .decentralizedIdentifier:
      return .decentralizedIdentifier
    case .verifierAttestation:
      return .verifierAttestation
    case .redirectUri:
      return .redirectUri
    }
  }

  public var name: String {
    switch self {

    /**
      * The Client Identifier is known to the Wallet in advance of the Authorization Request.
      */
    case .preregistered:
      return OpenId4VPSpec.clientIdSchemePreRegistered
    case .x509SanDns:
      return OpenId4VPSpec.clientIdSchemeX509SanDns
    case .x509Hash:
      return OpenId4VPSpec.clientIdSchemeX509Hash
    case .decentralizedIdentifier:
      return OpenId4VPSpec.clientIdSchemeDid
    case .verifierAttestation:
      return OpenId4VPSpec.clientIdSchemeVerifierAttestation
    case .redirectUri:
      return OpenId4VPSpec.clientIdSchemeRedirectUri
    }
  }

  case redirectUri
  case preregistered(clients: [OriginalClientId: PreregisteredClient])
  case x509SanDns(trust: CertificateTrust)
  case x509Hash(trust: CertificateTrust)
  case decentralizedIdentifier(did: DID, lookup: DIDPublicKeyLookupAgentType)
  case verifierAttestation(
    trust: Verifier,
    clockSkew: TimeInterval = 15.0
  )
}
