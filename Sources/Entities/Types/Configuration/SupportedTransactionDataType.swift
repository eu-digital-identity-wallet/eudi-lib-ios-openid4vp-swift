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

public struct SupportedTransactionDataType: Codable, Sendable {
  public let type: TransactionDataType
  public let hashAlgorithms: Set<HashAlgorithm>
  
  public init(type: TransactionDataType, hashAlgorithms: Set<HashAlgorithm> = .init([.sha256])) throws {
    guard !hashAlgorithms.isEmpty else {
      throw ValidationError.validationError(
        "SupportedTransactionDataTypeError hashAlgorithms cannot be empty"
      )
    }

    guard hashAlgorithms.contains(HashAlgorithm.sha256) else {
      throw ValidationError.validationError(
        "SupportedTransactionDataTypeError  'sha-256' must be a supported hash algorithm"
      )
    }

    self.type = type
    self.hashAlgorithms = hashAlgorithms
  }

  public static func `default`() -> SupportedTransactionDataType {
    try! .init(
      type: .init(value: "transaction_data"),
    )
  }
}
