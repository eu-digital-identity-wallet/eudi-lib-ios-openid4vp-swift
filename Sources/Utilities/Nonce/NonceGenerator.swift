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
import CryptoKit

/// A utility struct for generating secure random nonces for use in cryptographic and unique identifier contexts.
public struct NonceGenerator {
  
  /// Recommended minimums. Tune to your threat model, but keep them non-trivial.
  public static let minimumAlphanumericLength = 32
  public static let minimumSecureByteLength = 16   // 128 bits minimum; 32 bytes (256 bits) is commonly used.
  
  /// Generates a nonce of the specified length using alphanumeric characters.
  ///
  /// This method creates a nonce using a character set consisting of lowercase letters,
  /// uppercase letters, and numbers. It is suitable for nonces that need to be URL-safe and human-readable.
  ///
  /// - Parameter length: The length of the nonce to be generated. Defaults to 32 characters.
  /// - Returns: A random alphanumeric string of the specified length.
  /// - Throws: `NonceError.invalidLength` if the provided length is less than or equal to zero.
  public static func generate(length: Int = 32) throws -> String {
    guard length >= minimumAlphanumericLength else {
      throw NonceError.invalidLength(minimum: minimumAlphanumericLength)
    }
    return try secureRandomString(length: length, charset: Self.alphanumericCharset)
  }
  
  /// Generates a cryptographically secure nonce as Base64URL (no padding).
  ///
  /// This is appropriate for OpenID4VP `wallet_nonce` as it is base64url-encoded and cryptographically random. :contentReference[oaicite:1]{index=1}
  ///
  /// - Parameter byteLength: Number of random bytes (must be >= `minimumSecureByteLength`).
  /// - Returns: Base64URL-encoded string without padding.
  public static func generateSecureNonce(byteLength: Int = 32) throws -> String {
    guard byteLength >= minimumSecureByteLength else {
      throw NonceError.invalidByteLength(minimum: minimumSecureByteLength)
    }
    let bytes = try secureRandomBytes(count: byteLength)
    return base64URLEncode(Data(bytes))
  }
  
  private static let alphanumericCharset: [UInt8] = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".utf8)
  
  private static func secureRandomBytes(count: Int) throws -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    guard status == errSecSuccess else {
      throw NonceError.randomGenerationFailed(status)
    }
    return bytes
  }
  
  /// Generates a CSPRNG string from a charset using rejection sampling to avoid modulo bias.
  private static func secureRandomString(length: Int, charset: [UInt8]) throws -> String {
    precondition(!charset.isEmpty)
    
    // Rejection sampling threshold: largest multiple of charset.count less than 256.
    let n = charset.count
    let maxUnbiased = (256 / n) * n  // e.g. if n=62 => 248
    
    var out = [UInt8]()
    out.reserveCapacity(length)
    
    while out.count < length {
      // Pull a chunk to reduce SecRandom calls
      let chunk = try secureRandomBytes(count: max(16, length - out.count))
      for b in chunk {
        if Int(b) < maxUnbiased {
          out.append(charset[Int(b) % n])
          if out.count == length { break }
        }
      }
    }
    
    return String(decoding: out, as: UTF8.self)
  }
  
  /// Base64URL encoding without padding per JOSE usage (RFC 7515 §2), referenced by OpenID4VP. :contentReference[oaicite:2]{index=2}
  private static func base64URLEncode(_ data: Data) -> String {
    return data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
