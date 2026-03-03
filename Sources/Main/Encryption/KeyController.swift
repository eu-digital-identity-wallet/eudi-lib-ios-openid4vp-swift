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
import Security
import JOSESwift

public class KeyController {

  public static func generateRSAPrivateKey() throws -> SecKey {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits as String: 2048
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw error!.takeRetainedValue() as Error
    }
    return privateKey
  }

  public static func generateRSAPublicKey(from privateKey: SecKey) throws -> SecKey {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw JOSEError.invalidPublicKey
    }
    return publicKey
  }

  public static func generateECDHPrivateKey() throws -> SecKey {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw error!.takeRetainedValue() as Error
    }
    return privateKey
  }

  public static func generateECDHPublicKey(from privateKey: SecKey) throws -> SecKey {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw NSError(domain: "YourDomain", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to generate public key"])
    }
    return publicKey
  }

  public static func convertPEMToPublicKey(
    _ pem: String,
    algorithm: SignatureAlgorithm = .RS256
  ) -> SecKey? {
    switch algorithm {
    case .RS256, .RS384, .RS512:
      return try? Self.convertRSAPEMToPublicKey(pem)
    case .ES256, .ES384, .ES512:
      return try? ECPublicKeyConverter.secKey(fromPEM: pem)
    case .HS256, .HS384, .HS512:
      return nil
    case .PS256, .PS384, .PS512:
      return nil
    }
  }

  public static func convertRSAPEMToPublicKey(_ pem: String) throws -> SecKey? {

    let key = pem
      .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
      .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
      .split(separator: "\n").joined()

    // Define the key attributes
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: kSecAttrKeyClassPublic
    ]

    guard let privateKeyData = Data(
      base64Encoded: key,
      options: .ignoreUnknownCharacters
    ) else {
      return nil
    }

    // Create the SecKey object
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(privateKeyData as CFData, attributes as CFDictionary, &error) else {
      if let error = error?.takeRetainedValue() {
        print("Failed to create SecKey:", error)
      }
      return nil
    }
    return secKey
  }
}

private extension String {
  func chunked(length: Int) -> [String] {
    var index = startIndex
    var chunks = [String]()
    while index < endIndex {
      let endIndex = self.index(index, offsetBy: length, limitedBy: self.endIndex) ?? self.endIndex
      let chunk = self[index..<endIndex]
      chunks.append(String(chunk))
      index = endIndex
    }
    return chunks
  }
}
