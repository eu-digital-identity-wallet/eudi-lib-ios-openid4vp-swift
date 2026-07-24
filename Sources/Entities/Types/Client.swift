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
import X509
import SwiftASN1

public enum Client: Sendable {
  case preRegistered(
    clientId: OriginalClientId,
    legalName: String
  )

  case redirectUri(
    clientId: OriginalClientId
  )
    
  case x509SanDns(
    clientId: OriginalClientId,
    certificate: Certificate
  )

  case x509Hash(
    clientId: OriginalClientId,
    authenticationCertificate: Certificate
  )
  
  case didClient(
    did: DID
  )

  case attested(
    clientId: OriginalClientId
  )

   /**
    * The id of the client.
    */
  public var id: VerifierId {
    switch self {
    case .preRegistered(let clientId, _):
      return .init(
        scheme: .preRegistered,
        originalClientId: clientId
      )
    case .redirectUri(let clientId):
      return .init(
        scheme: .redirectUri,
        originalClientId: clientId
      )
    case .x509SanDns(let clientId, _):
      return .init(
        scheme: .x509SanDns,
        originalClientId: clientId
      )
    case .x509Hash(let clientId, _):
      return .init(
        scheme: .x509Hash,
        originalClientId: clientId
      )
    case .didClient(let did):
      return .init(
        scheme: .decentralizedIdentifier,
        originalClientId: did.string
      )
    case .attested(let clientId):
      return .init(
        scheme: .verifierAttestation,
        originalClientId: clientId
      )
    }
  }

  public var legalName: String? {
    switch self {
    case .preRegistered(_, let legalName):
      return legalName
    case .redirectUri:
      return nil
    case .x509SanDns(_, let certificate):
      return certificate.legaName
    case .x509Hash(_, let authenticationCertificate):
      return authenticationCertificate.legaName
    case .didClient:
      return nil
    case .attested:
      return nil
    }
  }
}

public extension Certificate {
  var legaName: String {
    let a = GeneralName.directoryName(issuer)
    switch a {
    case .directoryName(let name):
      guard let organizationName = name.lazy.filter({ name in
        name.contains { attribute in
          attribute.type == ASN1ObjectIdentifier.RDNAttributeType.organizationName
        }
      }).first else {
        return ""
      }
      return String(describing: organizationName.description).components(separatedBy: "=").last ?? ""
    default: return ""
    }
  }
}
