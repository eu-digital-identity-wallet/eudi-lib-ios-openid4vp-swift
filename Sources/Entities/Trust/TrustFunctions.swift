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

/// Parses all certificates from the x5c chain.
/// Throws an error if any certificate fails to parse - fail closed to prevent
/// attacks that inject malformed certificates to manipulate which cert is treated as the leaf.
internal func parseCertificates(from chain: [String]) throws -> [Certificate] {
  try chain.enumerated().map { index, serializedCertificate in
    guard let serializedData = Data(base64Encoded: serializedCertificate) else {
      throw ValidationError.validationError(
        "Certificate at index \(index) in x5c chain is not valid base64"
      )
    }

    if let string = String(data: serializedData, encoding: .utf8) {
      guard let data = Data(base64Encoded: string.removeCertificateDelimiters()) else {
        throw ValidationError.validationError(
          "Certificate at index \(index) in x5c chain has invalid PEM encoding"
        )
      }
      let derBytes = [UInt8](data)
      do {
        return try Certificate(derEncoded: derBytes)
      } catch {
        throw ValidationError.validationError(
          "Certificate at index \(index) in x5c chain failed to parse: \(error.localizedDescription)"
        )
      }
    } else {
      let derBytes = [UInt8](serializedData)
      do {
        return try Certificate(derEncoded: derBytes)
      } catch {
        throw ValidationError.validationError(
          "Certificate at index \(index) in x5c chain failed to parse: \(error.localizedDescription)"
        )
      }
    }
  }
}

func parseCertificateData(from chain: [String]) -> [Data] {
  chain.compactMap { serializedCertificate in
    guard let serializedData = Data(base64Encoded: serializedCertificate) else {
      return nil
    }

    return serializedData
  }
}
