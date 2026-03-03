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

public enum KeyControllerError: Error {
  case containsPrivateKeyMaterial
  case unsupportedPEMFormat
  case invalidBase64
  case secKeyCreationFailed
  case notRSAPublicKey
}

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

    // 1) Fail closed if PEM contains any private key blocks
    // (covers PKCS#1, PKCS#8, encrypted PKCS#8, EC, etc.)
    let upper = pem.uppercased()
    if upper.contains("BEGIN PRIVATE KEY") ||
       upper.contains("BEGIN RSA PRIVATE KEY") ||
       upper.contains("BEGIN ENCRYPTED PRIVATE KEY") ||
       upper.contains("BEGIN EC PRIVATE KEY") {
      throw KeyControllerError.containsPrivateKeyMaterial
    }

    // 2) Accept only known public-key PEM labels
    // - "PUBLIC KEY" (SubjectPublicKeyInfo / SPKI) is the standard
    // - "RSA PUBLIC KEY" (PKCS#1 public key) exists in the wild
    let isSPKI = upper.contains("BEGIN PUBLIC KEY") && upper.contains("END PUBLIC KEY")
    let isRSAPublic = upper.contains("BEGIN RSA PUBLIC KEY") && upper.contains("END RSA PUBLIC KEY")

    guard isSPKI || isRSAPublic else {
      throw KeyControllerError.unsupportedPEMFormat
    }

    // 3) Extract ONLY the base64 inside the public key block we support
    let keyBody: String
    if isSPKI {
      keyBody = pem
        .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
    } else {
      keyBody = pem
        .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
        .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----", with: "")
    }

    // Remove whitespace/newlines
    let b64 = keyBody
      .components(separatedBy: .whitespacesAndNewlines)
      .joined()

    // 4) Strict base64 decode (no ignoreUnknownCharacters)
    guard let keyData = Data(base64Encoded: b64) else {
      throw KeyControllerError.invalidBase64
    }

    // 5) Create SecKey with strict attributes (RSA + public)
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass: kSecAttrKeyClassPublic
    ]

    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
      // Don’t print; surface a controlled error
      throw KeyControllerError.secKeyCreationFailed
    }

    // 6) Verify it really is an RSA public key
    guard
      let attrs = SecKeyCopyAttributes(secKey) as? [CFString: Any],
      let keyType = attrs[kSecAttrKeyType] as? String,
      let keyClass = attrs[kSecAttrKeyClass] as? String,
      keyType == (kSecAttrKeyTypeRSA as String),
      keyClass == (kSecAttrKeyClassPublic as String)
    else {
      throw KeyControllerError.notRSAPublicKey
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
