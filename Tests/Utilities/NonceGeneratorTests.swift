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
import XCTest
import Foundation

@testable import OpenID4VP

final class NonceGeneratorTests: XCTestCase {
  
  func testGenerateNonceWhenLengthBelowMinimumThrows() {
    XCTAssertThrowsError(try NonceGenerator.generate(length: 0)) { error in
      XCTAssertEqual(error as? NonceError,
                     .invalidLength(minimum: NonceGenerator.minimumAlphanumericLength))
    }
    
    XCTAssertThrowsError(try NonceGenerator.generate(length: NonceGenerator.minimumAlphanumericLength - 1)) { error in
      XCTAssertEqual(error as? NonceError,
                     .invalidLength(minimum: NonceGenerator.minimumAlphanumericLength))
    }
  }
  
  func testGenerateDefaultLength() throws {
    let nonce = try NonceGenerator.generate()
    XCTAssertEqual(nonce.count, 32)
  }
  
  func testGenerateCustomLengthAtMinimum() throws {
    let nonce = try NonceGenerator.generate(length: NonceGenerator.minimumAlphanumericLength)
    XCTAssertEqual(nonce.count, NonceGenerator.minimumAlphanumericLength)
  }
  
  func testGenerateCustomLengthAboveMinimum() throws {
    let nonce = try NonceGenerator.generate(length: NonceGenerator.minimumAlphanumericLength + 10)
    XCTAssertEqual(nonce.count, NonceGenerator.minimumAlphanumericLength + 10)
  }
  
  func testGenerateContainsOnlyAlphanumericCharacters() throws {
    let nonce = try NonceGenerator.generate(length: NonceGenerator.minimumAlphanumericLength + 100)
    let allowedChars = CharacterSet.alphanumerics
    XCTAssertTrue(nonce.unicodeScalars.allSatisfy { allowedChars.contains($0) })
  }
  
  func testGenerateRandomness() throws {
    let nonce1 = try NonceGenerator.generate()
    let nonce2 = try NonceGenerator.generate()
    XCTAssertNotEqual(nonce1, nonce2)
  }
  
  // MARK: - generateSecureNonceBase64URL(byteLength:)
  
  func testGenerateSecureNonceBase64URLWhenByteLengthBelowMinimumThrows() {
    XCTAssertThrowsError(try NonceGenerator.generateSecureNonce(byteLength: 0)) { error in
      XCTAssertEqual(error as? NonceError,
                     .invalidByteLength(minimum: NonceGenerator.minimumSecureByteLength))
    }
    
    XCTAssertThrowsError(try NonceGenerator.generateSecureNonce(byteLength: NonceGenerator.minimumSecureByteLength - 1)) { error in
      XCTAssertEqual(error as? NonceError,
                     .invalidByteLength(minimum: NonceGenerator.minimumSecureByteLength))
    }
  }
  
  func testGenerateSecureNonceBase64URLDefaultByteLength() throws {
    let secureNonce = try NonceGenerator.generateSecureNonce()
    XCTAssertTrue(Self.isBase64URLNoPadding(secureNonce))
    
    let data = Self.base64URLDecode(secureNonce)
    XCTAssertNotNil(data)
    XCTAssertEqual(data?.count, 32)
  }
  
  func testGenerateSecureNonceBase64URLCustomByteLength() throws {
    let secureNonce = try NonceGenerator.generateSecureNonce(byteLength: 64)
    XCTAssertTrue(Self.isBase64URLNoPadding(secureNonce))
    
    let data = Self.base64URLDecode(secureNonce)
    XCTAssertNotNil(data)
    XCTAssertEqual(data?.count, 64)
  }
  
  func testGenerateSecureNonceBase64URLRandomness() throws {
    let nonce1 = try NonceGenerator.generateSecureNonce()
    let nonce2 = try NonceGenerator.generateSecureNonce()
    XCTAssertNotEqual(nonce1, nonce2)
  }
  
  private static func isBase64URLNoPadding(_ s: String) -> Bool {
    // Base64URL alphabet: A-Z a-z 0-9 - _
    // No "=" padding expected.
    guard !s.contains("=") else { return false }
    return s.unicodeScalars.allSatisfy { scalar in
      switch scalar.value {
      case 0x41...0x5A,  // A-Z
        0x61...0x7A,  // a-z
        0x30...0x39,  // 0-9
        0x2D,         // -
        0x5F:         // _
        return true
      default:
        return false
      }
    }
  }
  
  private static func base64URLDecode(_ s: String) -> Data? {
    // Convert Base64URL -> Base64
    var base64 = s
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    
    // Add padding back if needed
    let remainder = base64.count % 4
    if remainder != 0 {
      base64.append(String(repeating: "=", count: 4 - remainder))
    }
    
    return Data(base64Encoded: base64)
  }
}
