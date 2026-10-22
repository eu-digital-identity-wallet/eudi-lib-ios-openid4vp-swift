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
import SwiftyJSON
import JOSESwift

// Function to create wallet metadata
public func walletMetaData(
  config: OpenId4VPConfiguration,
  key: SecKey? = nil
) -> JSON {
  var json = JSON()

  json[REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED] = JSON(
    config.jarConfiguration.supportedAlgorithms.map { $0.name }
  )

  json[VP_FORMATS_SUPPORTED] = config.vpConfiguration.vpFormatsSupported.toJSON()["vp_formats_supported"]
  json[CLIENT_ID_PREFIXES_SUPPORTED] = JSON(
    config.supportedClientIdSchemes.map { $0.name }
  )

  json[RESPONSE_TYPES_SUPPORTED] = JSON(["vp_token"])
  json[RESPONSE_MODES_SUPPORTED] = JSON(["direct_post", "direct_post.jwt"])

  if let issuer = config.issuer?.absoluteString {
    json[ISSUER] = JSON(issuer)
  }
  
  if let options: PostOptions = config.jarConfiguration.supportedRequestUriMethods.isPostSupported() {
    switch options.jarEncryption {
    case .notRequired: break
    case .required(let encryptionRequirementSpecification),
         .supported(let encryptionRequirementSpecification):
      if let key = key,
         let publicKey = try? KeyController.generateECDHPublicKey(from: key),
         let publicJwk = try? ECPublicKey(
           publicKey: publicKey,
           additionalParameters: [
             "use": "enc",
             "kid": UUID().uuidString,
             "alg": encryptionRequirementSpecification.supportedEncryptionAlgorithm.rawValue
           ]
         ),
         let jwkJson = try? JSON(["keys": [publicJwk.toDictionary()]]),
         publicJwk["crv"] == encryptionRequirementSpecification.ephemeralEncryptionKeyCurve.rawValue {

        json[JWKS] = jwkJson
        json[REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED] = JSON(
          [encryptionRequirementSpecification.supportedEncryptionAlgorithm.rawValue]
        )
        json[REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED] = JSON(
          [encryptionRequirementSpecification.supportedEncryptionMethod.rawValue]
        )
        
        // Response Encryption
        let responseEncryptionConfiguration = config.responseEncryptionConfiguration
        switch responseEncryptionConfiguration {
        case .supported(
          let supportedAlgorithms,
          let supportedMethods
        ):
          json[AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED] = JSON(
            supportedAlgorithms.map { $0.name }
          )
          json[AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED] = JSON(
            supportedMethods.map { $0.name }
          )
        default: break
        }
      }
    }
  }

  return json
}

private let REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED = "request_object_signing_alg_values_supported"
private let AUTHORIZATION_SIGNING_ALG_VALUES_SUPPORTED = "authorization_signing_alg_values_supported"

private let AUTHORIZATION_ENCRYPTION_ALG_VALUES_SUPPORTED = "authorization_encryption_alg_values_supported"
private let AUTHORIZATION_ENCRYPTION_ENC_VALUES_SUPPORTED = "authorization_encryption_enc_values_supported"

private let REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED = "request_object_encryption_alg_values_supported"
private let REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED = "request_object_encryption_enc_values_supported"

private let PRESENTATION_DEFINITION_URI_SUPPORTED = "presentation_definition_uri_supported"
private let CLIENT_ID_SCHEMES_SUPPORTED = "client_id_schemes_supported"
private let CLIENT_ID_PREFIXES_SUPPORTED = "client_id_prefixes_supported"
private let VP_FORMATS_SUPPORTED = "vp_formats_supported"
private let RESPONSE_TYPES_SUPPORTED = "response_types_supported"
private let RESPONSE_MODES_SUPPORTED = "response_modes_supported"
internal let JWKS = "jwks"
private let CONTENT_TYPE_JWT = "JWT"

internal let RESPONSE_ENCRYPTION_METHODS_SUPPORTED: String = "encrypted_response_enc_values_supported"
internal let RESPONSE_ENCRYPTION_METHODS_SUPPORTED_DEFAULT: String = "A128GCM"
internal let DEFAULT_RESPONSE_ENCRYPTION_METHODS: [EncryptionMethod] = [EncryptionMethod.parse(RESPONSE_ENCRYPTION_METHODS_SUPPORTED_DEFAULT), .init(name: "A128CBC-HS256")]

internal let ISSUER = "issuer"
internal let AUD = "aud"

private extension JWKSet {
  func toJSON() -> JSON? {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .prettyPrinted

    guard let data = try? encoder.encode(self) else {
      return nil
    }

    return JSON(data)
  }
}
