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

enum ECPemError: Error {
  case invalidPEM
  case invalidDER
  case unsupportedCurveOID(String)
  case asn1Unexpected
  case secKeyCreationFailed(CFError?)
}

struct ECPublicKeyConverter {
  
  /// Converts an EC PEM "BEGIN PUBLIC KEY" (SPKI) to a SecKey.
  /// Supports P-256, P-384, P-521.
  static func secKey(fromPEM pem: String) throws -> SecKey {
    let der = try derDataFromPublicKeyPEM(pem)
    
    // Parse SPKI:
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm         AlgorithmIdentifier,
    //   subjectPublicKey  BIT STRING
    // }
    //
    // AlgorithmIdentifier ::= SEQUENCE {
    //   algorithm   OBJECT IDENTIFIER (should be id-ecPublicKey 1.2.840.10045.2.1),
    //   parameters  OBJECT IDENTIFIER (named curve OID)
    // }
    
    var idx = 0
    let spki = try ASN1.readTLV(der, &idx, expectedTag: 0x30) // SEQUENCE
    var spkiIdx = 0
    
    let algId = try ASN1.readTLV(spki.value, &spkiIdx, expectedTag: 0x30) // SEQUENCE
    var algIdx = 0
    
    let algorithmOID = try ASN1.readOID(algId.value, &algIdx)
    
    guard algorithmOID == "1.2.840.10045.2.1" else {
      throw ECPemError.asn1Unexpected
    }
    
    let curveOID = try ASN1.readOID(algId.value, &algIdx)
    let keySizeBits = try keySizeBits(forCurveOID: curveOID)
    
    let bitString = try ASN1.readTLV(spki.value, &spkiIdx, expectedTag: 0x03) // BIT STRING
    guard bitString.value.count >= 2 else { throw ECPemError.invalidDER }
    
    // BIT STRING format: first byte is "unused bits" count (expect 0), then the actual bytes.
    var pubKeyBytes = bitString.value
    if pubKeyBytes.first == 0x00 {
      pubKeyBytes = pubKeyBytes.dropFirst()
    }
    
    // Some encoders may still have a leading 0x00 before 0x04; be defensive.
    while pubKeyBytes.first == 0x00 && pubKeyBytes.count > 1 {
      pubKeyBytes = pubKeyBytes.dropFirst()
    }
    
    // X9.63 uncompressed should start with 0x04
    guard pubKeyBytes.first == 0x04 else {
      throw ECPemError.asn1Unexpected
    }
    
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits: keySizeBits
    ]
    
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(pubKeyBytes as CFData, attributes as CFDictionary, &error) else {
      throw ECPemError.secKeyCreationFailed(error?.takeRetainedValue())
    }
    
    return secKey
  }
  
  private static func derDataFromPublicKeyPEM(_ pem: String) throws -> Data {
    // Accept PEM with whitespace/newlines.
    let stripped = pem
      .replacingOccurrences(of: "\r", with: "")
      .trimmingCharacters(in: .whitespacesAndNewlines)
    
    guard stripped.contains("-----BEGIN PUBLIC KEY-----"),
          stripped.contains("-----END PUBLIC KEY-----") else {
      throw ECPemError.invalidPEM
    }
    
    let base64 = stripped
      .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
      .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
      .components(separatedBy: .whitespacesAndNewlines)
      .joined()
    
    guard let der = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
      throw ECPemError.invalidPEM
    }
    return der
  }
  
  private static func keySizeBits(forCurveOID oid: String) throws -> Int {
    switch oid {
    case "1.2.840.10045.3.1.7": // prime256v1 / secp256r1
      return 256
    case "1.3.132.0.34":        // secp384r1
      return 384
    case "1.3.132.0.35":        // secp521r1
      return 521
    default:
      throw ECPemError.unsupportedCurveOID(oid)
    }
  }
}

/// Minimal ASN.1 DER reader for exactly what we need (SEQUENCE, BIT STRING, OID)
internal enum ASN1 {
  
  struct TLV {
    let tag: UInt8
    let length: Int
    let value: Data
  }
  
  static func readTLV(_ data: Data, _ idx: inout Int, expectedTag: UInt8? = nil) throws -> TLV {
    guard idx < data.count else { throw ECPemError.invalidDER }
    
    let tag = data[idx]
    idx += 1
    
    if let expectedTag, tag != expectedTag { throw ECPemError.asn1Unexpected }
    
    let length = try readLength(data, &idx)
    guard idx + length <= data.count else { throw ECPemError.invalidDER }
    
    let value = data.subdata(in: idx ..< idx + length)
    idx += length
    
    return TLV(tag: tag, length: length, value: value)
  }
  
  static func readLength(_ data: Data, _ idx: inout Int) throws -> Int {
    guard idx < data.count else { throw ECPemError.invalidDER }
    let first = data[idx]
    idx += 1
    
    if first & 0x80 == 0 {
      return Int(first)
    }
    
    let count = Int(first & 0x7F)
    guard count > 0, count <= 4, idx + count <= data.count else {
      throw ECPemError.invalidDER
    }
    
    var length = 0
    for _ in 0..<count {
      length = (length << 8) | Int(data[idx])
      idx += 1
    }
    return length
  }
  
  static func readOID(_ data: Data, _ idx: inout Int) throws -> String {
    let tlv = try readTLV(data, &idx, expectedTag: 0x06) // OBJECT IDENTIFIER
    let bytes = [UInt8](tlv.value)
    guard !bytes.isEmpty else { throw ECPemError.invalidDER }
    
    // OID decoding: first byte = 40*X + Y
    let first = Int(bytes[0])
    let x = first / 40
    let y = first % 40
    
    var arcs = [x, y]
    var value = 0
    
    for b in bytes.dropFirst() {
      value = (value << 7) | Int(b & 0x7F)
      if (b & 0x80) == 0 {
        arcs.append(value)
        value = 0
      }
    }
    
    return arcs.map(String.init).joined(separator: ".")
  }
}
