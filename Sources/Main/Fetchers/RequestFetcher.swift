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
import JOSESwift
import SwiftyJSON

internal actor RequestFetcher {
  
  let config: OpenId4VPConfiguration
  
  init(config: OpenId4VPConfiguration) {
    self.config = config
  }
  
  func fetchRequest(request: UnvalidatedRequest) async throws -> FetchedRequest {
    
    switch request {
    case .plain(let object):
      return .plain(requestObject: object)
    case .jwtSecuredPassByValue(let clientId, let jwt):
      return .jwtSecured(clientId: clientId, jwt: jwt)
    case .jwtSecuredPassByReference(let clientId, let jwtURI, let requestURIMethod):
      let jwt = try await fetchJwt(
        clientId: clientId,
        jwtURI: jwtURI,
        requestURIMethod: requestURIMethod
      )
      return .jwtSecured(clientId: clientId, jwt: jwt)
    }
  }
  
  private func fetchJwt(
    clientId: String,
    jwtURI: URL,
    requestURIMethod: RequestUriMethod?
  ) async throws -> String {
    let method = requestURIMethod ?? .GET
    return try await getJWT(
      requestUriMethod: method,
      config: config,
      requestUrl: jwtURI,
      clientId: clientId
    ).jwt
  }
  
  private func getJWT(
    requestUriMethod: RequestUriMethod = .GET,
    config: OpenId4VPConfiguration?,
    requestUrl: URL,
    clientId: String?
  ) async throws -> (jwt: String, walletNonce: String?) {
    switch requestUriMethod {
    case .GET:
      let jwt = try await getJwtViaGET(
        config: config,
        clientId: clientId,
        requestUrl: requestUrl
      )
      return (jwt, nil)
    case .POST:
      if config?.jarConfiguration.supportedRequestUriMethods.isPostSupported() == nil {
        let jwt = try await getJwtViaGET(
          config: config,
          clientId: clientId,
          requestUrl: requestUrl
        )
        return (jwt, nil)
      }
        
      let (jwt, nonce) = try await getJwtViaPOST(
        config: config,
        requestUrl: requestUrl,
        clientId: clientId
      )
      return (jwt, nonce)
    }
  }
  
  private func getJwtViaGET(
    config: OpenId4VPConfiguration?,
    clientId: String?,
    requestUrl: URL
  ) async throws -> String {
    let jwt = try await getJwtString(
      fetcher: Fetcher(
        session: config?.session ?? URLSession.shared
      ),
      requestUrl: requestUrl
    )
    
    let expectedWalletAudience: String? = OpenId4VPConfiguration.SelfIssued?.absoluteString
    try config?.ensureJWTValid(
      expectedClient: clientId,
      nonceOption: .doNotUse,
      expectedWalletNonce: nil,
      expectedWalletAudience: expectedWalletAudience,
      jwt: jwt
    )
    
    return jwt
  }
  
  fileprivate struct ResultType: Codable {}
  fileprivate func getJwtString(
    fetcher: Fetcher<ResultType> = Fetcher(),
    requestUrl: URL
  ) async throws -> String {
    let jwtResult = try await fetcher.fetchString(url: requestUrl)
    switch jwtResult {
    case .success(let string):
      return try extractJWT(string)
    case .failure: throw ValidationError.invalidJwtPayload
    }
  }
  
  private func getJwtViaPOST(
    config: OpenId4VPConfiguration?,
    requestUrl: URL,
    clientId: String?
  ) async throws -> (jwt: String, nonce: String?) {
    guard let supportedMethods = config?.jarConfiguration.supportedRequestUriMethods else {
      throw AuthorizationError.invalidRequestUriMethod
    }
    
    guard let options = supportedMethods.isPostSupported() else {
      throw AuthorizationError.invalidRequestUriMethod
    }
    
    let isNotRequired = options.jarEncryption.isNotRequired
    let nonce = try generateNonce(from: options)
    let keys: (
      key: SecKey,
      jwk: ECPrivateKey
    )? = !isNotRequired ? (
      try? generateKeysIfNeeded(
        for: supportedMethods
      )
    ) : nil
    
    let walletMetadata = generateWalletMetadataIfNeeded(
      config: config,
      key: keys?.key,
      include: options.includeWalletMetadata
    )
    
    let jwt = try await postJwtString(
      walletMetaData: walletMetadata,
      nonce: nonce,
      requestUrl: requestUrl
    )
    
    let finalJwt = try decryptIfNeeded(
      config: config,
      jwt: jwt,
      keys: keys
    )
    
    let expectedWalletAudience: String? = walletMetadata != nil
      ? config?.issuer?.absoluteString
      : OpenId4VPConfiguration.SelfIssued?.absoluteString
    let nonceOption = config?.jarConfiguration.nonceOption
    try config?.ensureJWTValid(
      expectedClient: clientId,
      nonceOption: nonceOption,
      expectedWalletNonce: nonce,
      expectedWalletAudience: expectedWalletAudience,
      jwt: finalJwt
    )
    
    return (finalJwt, nonce)
  }
  
  fileprivate func postJwtString(
    poster: Poster = Poster(),
    walletMetaData: JSON?,
    nonce: String?,
    requestUrl: URL
  ) async throws -> String {
    
    // Building a combined JSON object
    var combined: [String: Any] = [:]
    
    guard let walletMetaData = walletMetaData else {
      throw ValidationError.validationError("Invalid wallet metadata")
    }
    
    if let metaData = walletMetaData.dictionaryObject?.toJSONData() {
      let metadataString = String(decoding: metaData, as: UTF8.self)
      combined[Constants.WALLET_METADATA_FORM_PARAM] = metadataString
    }
    
    // Convert nonce to JSON and add to combined JSON
    if let nonce = nonce {
      combined[Constants.WALLET_NONCE_FORM_PARAM] = nonce
    }
    
    var request = URLRequest(url: requestUrl)
    request.httpMethod = RequestUriMethod.POST.description
    try request.setFormURLEncodedBody(combined)
    
    request.allHTTPHeaderFields = [
      "Content-Type": ContentType.form.rawValue
    ]
    
    let jwtResult: Result<String, PostError> = await poster.postString(
      request: request
    )
    
    switch jwtResult {
    case .success(let string):
      return try extractJWT(string)
    case .failure: throw ValidationError.invalidJwtPayload
    }
  }
  
  private func generateNonce(from options: PostOptions) throws -> String? {
    return switch options.useWalletNonce {
    case .doNotUse: nil
    case .use(let byteLength): try NonceGenerator.generate(length: byteLength)
    }
  }
  
  private func generateKeysIfNeeded(
    for method: SupportedRequestUriMethod
  ) throws -> (key: SecKey, jwk: ECPrivateKey)? {
    switch method {
    case .post, .both: break
    default:
      return nil
    }
    let key = try KeyController.generateECDHPrivateKey()
    let jwk = try ECPrivateKey(privateKey: key)
    return (key, jwk)
  }
  
  private func generateWalletMetadataIfNeeded(
    config: OpenId4VPConfiguration?,
    key: SecKey?,
    include: Bool
  ) -> JSON? {
    guard include, let config else { return nil }
    return walletMetaData(
      config: config,
      key: key
    )
  }
  
  private func decryptIfNeeded(
    config: OpenId4VPConfiguration?,
    jwt: String,
    keys: (key: SecKey, jwk: ECPrivateKey)?
  ) throws -> String {
    guard let jwk = keys?.jwk else {
      return jwt
    }
    
    do {
      let encryptedJwe = try JWE(compactSerialization: jwt)
        
      let supportedEncryptionAlgorithms: [KeyManagementAlgorithm] = config?.responseEncryptionConfiguration.supportedAlgorithms.compactMap { algorithm in
          return KeyManagementAlgorithm(algorithm: algorithm)
      } ?? []
      
      guard let headerKeyManagementAlgorithm = encryptedJwe.header.keyManagementAlgorithm else {
        throw ValidationError.validationError(
          "JWE header does not contain key management algorithm"
        )
      }
      
      if !supportedEncryptionAlgorithms.contains(headerKeyManagementAlgorithm) {
        throw ValidationError.validationError(
          "JWEObject must contain a supported encryption algorithm"
        )
      }
      
      let supportedEncryptionMethods: [ContentEncryptionAlgorithm] = config?.responseEncryptionConfiguration.supportedMethods.compactMap { method in
        return ContentEncryptionAlgorithm(encryptionMethod: method)
      } ?? []
      
      guard let headerContentEncryptionAlgorithm = encryptedJwe.header.contentEncryptionAlgorithm else {
        throw ValidationError.validationError(
          "JWE header does not contain key management algorithm"
        )
      }
      
      if !supportedEncryptionMethods.contains(headerContentEncryptionAlgorithm) {
        throw ValidationError.validationError(
          "JWEObject must contain a supported encryption method"
        )
      }
        
      guard let decrypter = Decrypter(
        keyManagementAlgorithm: headerKeyManagementAlgorithm,
        contentEncryptionAlgorithm: headerContentEncryptionAlgorithm,
        decryptionKey: jwk
      ) else {
        throw AuthorizationError.jwtDecryptionFailed
      }
      
      let payloadData = try encryptedJwe.decrypt(using: decrypter).data()
      guard
        let decoded = payloadData.base64EncodedString().base64Decoded(),
        let jwtString = String(data: decoded, encoding: .utf8) else {
        throw AuthorizationError.jwtDecryptionFailed
      }
      return jwtString
      
    } catch {
      return jwt
    }
  }
  
  /// Extracts the JWT token from a given JSON string or JWT string.
  /// - Parameter string: The input string containing either a JSON object with a JWT field or a JWT string.
  /// - Returns: The extracted JWT token.
  /// - Throws: An error of type `ValidatedAuthorizationError` if the input string is not a valid JSON or JWT, or if there's a decoding error.
  private func extractJWT(_ string: String) throws -> String {
    if string.isValidJSONString {
      if let jsonData = string.data(using: .utf8) {
        do {
          let decodedObject = try JSONDecoder().decode(RemoteJWT.self, from: jsonData)
          return decodedObject.jwt
        } catch {
          throw error
        }
      } else {
        throw ValidationError.invalidJwtPayload
      }
    } else {
      return string
    }
  }
}

internal extension OpenId4VPConfiguration {
  
  func ensureJWTValid(
    expectedClient: String?,
    nonceOption: NonceOption?,
    expectedWalletNonce: String?,
    expectedWalletAudience: String?,
    jwt: JWTString
  ) throws {
    
    let jws = try JWS(compactSerialization: jwt)
    
    switch nonceOption {
    case .use:
      guard let expectedWalletNonce = expectedWalletNonce else {
        throw ValidationError.validationError("expected wallet_nonce is missing")
      }

      guard let jwsNonce = getValueForKey(
        from: jwt,
        key: Constants.WALLET_NONCE_FORM_PARAM
      ) as? String else {
        throw ValidationError.validationError("wallet_nonce missing in JWT")
      }

      guard jwsNonce == expectedWalletNonce else {
        throw ValidationError.validationError("wallet_nonce mismatch")
      }
    default:
      break
    }
    guard let expectedClient = expectedClient else {
      throw ValidationError.validationError("expectedClient should not be nil")
    }
    
    guard let jwsClientID = getValueForKey(
      from: jwt,
      key: "client_id"
    ) as? String else {
      throw ValidationError.validationError("client_id should not be nil")
    }
    
    let id = try? VerifierId.parse(clientId: jwsClientID).get()
    let expectedId = try? VerifierId.parse(clientId: expectedClient).get()
    guard id?.originalClientId == expectedId?.originalClientId else {
      throw ValidationError.validationError("client_id's do not match")
    }
    
    if expectedWalletNonce != nil, let jwsNonce = getValueForKey(
      from: jwt,
      key: Constants.WALLET_NONCE_FORM_PARAM
    ) as? String {
      
      guard jwsNonce == expectedWalletNonce else {
        throw ValidationError.validationError("nonce's do not match")
      }
    }
    
    guard
      let algorithm = jws.header.algorithm,
      algorithm.rawValue != "none"
    else {
      throw ValidationError.validationError("algorithm should not be nil")
    }
    
    guard jarConfiguration.supportedAlgorithms.contains(where: { $0.name == algorithm.rawValue }) else {
      throw ValidationError.validationError("nonce's do not match")
    }
  }
  
  func getValueForKey(from jwtString: String, key: String) -> Any? {
    do {
      let jwt = try JWS(compactSerialization: jwtString)
      let payloadData = jwt.payload.data()
      
      let jsonObject = try JSONSerialization.jsonObject(with: payloadData, options: [])
      guard let payloadDict = jsonObject as? [String: Any] else {
        return nil
      }
      return payloadDict[key]
      
    } catch {
      return nil
    }
  }
}

extension URLRequest {
  /// Sets the body as application/x-www-form-urlencoded from key/value pairs.
  /// Values of type String/Int/Bool will be stringified.
  /// Values of type [String: Any] or [Any] will be JSON-serialized.
  mutating func setFormURLEncodedBody(_ fields: [String: Any]) throws {
    self.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

    func stringify(_ value: Any) throws -> String {
      switch value {
      case let str as String:
        return str
      case let num as NSNumber:
        return num.stringValue
      case let bool as Bool:
        return bool ? "true" : "false"
      case let dict as [String: Any]:
        let data = try JSONSerialization.data(withJSONObject: dict, options: [])
        return String(decoding: data, as: UTF8.self)
      case let array as [Any]:
        let data = try JSONSerialization.data(withJSONObject: array, options: [])
        return String(decoding: data, as: UTF8.self)
      default:
        return String(describing: value)
      }
    }

    // Allowed set for x-www-form-urlencoded components (unreserved per RFC 3986)
    // We intentionally exclude ':', ',', '=', '&', '+' so they are percent-encoded.
    let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    func formEncode(_ s: String) -> String {
      let encoded = s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? ""
      // Convert %20 to '+' as per x-www-form-urlencoded
      return encoded.replacingOccurrences(of: "%20", with: "+")
    }

    var parts: [String] = []
    parts.reserveCapacity(fields.count)

    for (key, value) in fields {
      let rawValue = try stringify(value)
      let encodedKey = formEncode(key)
      let encodedValue = formEncode(rawValue)
      parts.append("\(encodedKey)=\(encodedValue)")
    }

    let bodyString = parts.joined(separator: "&")
    self.httpBody = bodyString.data(using: .utf8)
  }
}

