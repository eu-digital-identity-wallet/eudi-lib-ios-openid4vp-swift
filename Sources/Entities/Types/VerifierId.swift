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
public struct VerifierId: Sendable {
  public let scheme: ClientIdPrefix
  public let originalClientId: OriginalClientId

  public init(
    scheme: ClientIdPrefix,
    originalClientId: OriginalClientId = ""
  ) {
    self.scheme = scheme
    self.originalClientId = originalClientId
  }
  
  public var clientId: OriginalClientId {
    let prefix: String? = {
      switch scheme {
      case .redirectUri:
        return OpenId4VPSpec.clientIdSchemeRedirectUri
      case .x509SanDns:
        return OpenId4VPSpec.clientIdSchemeX509SanDns
      case .verifierAttestation:
        return OpenId4VPSpec.clientIdSchemeVerifierAttestation
      case .decentralizedIdentifier:
        return OpenId4VPSpec.clientIdSchemeDid
      case .openidFederation:
        return OpenId4VPSpec.clientIdSchemeOpenidFederation
      default:
        return nil
      }
    }()

    var result = ""
    if let prefix = prefix {
      result.append(prefix)
      result.append(OpenId4VPSpec.clientIdSchemeSeparator)
    }
    result.append(originalClientId)
    
    return result
  }

  public func toString() -> String {
    clientId
  }

  public static func parse(clientId: String) -> Result<VerifierId, Error> {
    return Result {
      func invalid(_ message: String) -> Error {
        return ValidationError.validationError(message)
      }

      if !clientId.contains(OpenId4VPSpec.clientIdSchemeSeparator) {
        return VerifierId(scheme: .preRegistered, originalClientId: clientId)

      } else {
        let parts = clientId.split(separator: OpenId4VPSpec.clientIdSchemeSeparator, maxSplits: 1)
        guard parts.count == 2 else {
          throw invalid("Invalid clientId format")
        }
        let schemeString = String(parts[0])
        let originalClientId = String(parts[1])

        guard let scheme = ClientIdPrefix(rawValue: schemeString) else {
          return VerifierId(scheme: .preRegistered, originalClientId: clientId)
        }

        switch scheme {
        case .preRegistered:
          return VerifierId(scheme: .preRegistered, originalClientId: clientId)
        case .redirectUri, .x509SanDns, .x509Hash, .verifierAttestation:
          return VerifierId(scheme: scheme, originalClientId: originalClientId)
        case .openidFederation, .decentralizedIdentifier:
          return VerifierId(scheme: scheme, originalClientId: originalClientId)
        }
      }
    }
  }
}
