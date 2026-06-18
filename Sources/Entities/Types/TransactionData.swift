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

// MARK: - TransactionData

public struct TransactionData: Codable, Sendable {
  public var value: String
  
  public init(value: String) {
    self.value = value
  }

  public init(
    type: TransactionDataType,
    credentialIds: [QueryId]
  ) {
    self = Self.create(
      type: type,
      credentialIds: credentialIds
    )
  }

  public func type() throws -> TransactionDataType {
    try decode().type()
  }

  public func credentialIds() throws -> [QueryId] {
    try decode().credentialIds()
  }
  
  public func hashAlgorithms() throws -> [HashAlgorithm] {
    try decode().hashAlgorithms()
  }
  
  /// Get type specific parameters from TransactionData
  public func specificParameters() throws -> [String: Any] {
    var jsonDictionary = try decode().dictionaryObject
    
    jsonDictionary?.removeValue(forKey: OpenId4VPSpec.TRANSACTION_DATA_TYPE)
    jsonDictionary?.removeValue(forKey: OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    jsonDictionary?.removeValue(forKey: OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)

    return jsonDictionary ?? [:]
  }
  
  /// Decodes the base64-encoded string to JSON.
  public func decode() throws -> JSON {
    let decodedData = try Base64UrlNoPadding.decodeToByteString(value)
    guard
      let decodedString = String(data: decodedData, encoding: .utf8),
      let jsonData = decodedString.data(using: .utf8) else {
      throw ValidationError.validationError("Unable to decode transaction data")
    }
    return try JSON(data: jsonData)
  }

  /// Parses a TransactionData from a string, validating against supported types and the presentation query.
  public static func parse(
    _ s: String,
    supportedTypes: [SupportedTransactionDataType],
    presentationQuery: PresentationQuery
  ) -> Result<TransactionData, Error> {
    Result {
      let ids: [String] = switch presentationQuery {
      case .byDigitalCredentialsQuery(let dcql):
        dcql.credentials.map { $0.id.value }
      }

      let transactionData = TransactionData(value: s)
      try transactionData.isSupported(supportedTypes)
      try transactionData.hasCorrectIds(ids)
      return transactionData
    }
  }

  /// Validates if the transaction data type is supported.
  private func isSupported(_ supportedTypes: [SupportedTransactionDataType]) throws {
    let actualType = try self.type()                // evaluate once

    let isTypeSupported = supportedTypes.contains { $0.type == actualType }
    guard isTypeSupported else {
      throw ValidationError.validationError(
        "Unsupported transaction data type: \(actualType)"
      )
    }
  }

  /// Validates if the transaction data has the correct credential IDs as per the ids.
  private func hasCorrectIds(_ ids: [String]) throws {
    let requestedCredentialIds = try ids.map {
      try QueryId(value: $0)
    }
    guard requestedCredentialIds.containsAll(try self.credentialIds()) else {
      throw ValidationError.validationError(
        "Invalid credential IDs: \(String(describing: self.credentialIds))"
      )
    }
  }
  
  /// Convenience initializer to build a JSON from components.
  internal static func json(
    type: TransactionDataType,
    credentialIds: [QueryId]
  ) -> JSON {

    var json = JSON()
    json[OpenId4VPSpec.TRANSACTION_DATA_TYPE].string = type.value
    json[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS].arrayObject = credentialIds.map { $0.value }

    return json
  }

  /// Convenience initializer to build a TransactionData from components.
  public static func create(
    type: TransactionDataType,
    credentialIds: [QueryId],
    hashAlgorithms: [HashAlgorithm]? = nil,
    builder: (inout JSON) -> Void = { _ in }
  ) -> TransactionData {

    var json = JSON()
    json[OpenId4VPSpec.TRANSACTION_DATA_TYPE].string = type.value
    json[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS].arrayObject = credentialIds.map { $0.value }

    if let hashAlgorithms = hashAlgorithms, !hashAlgorithms.isEmpty {
      json[OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS].arrayObject = hashAlgorithms.map { $0.name }
    }

    builder(&json)

    // Serialize the JSON and encode it to base64.
    guard
      let serialized = json.rawString(),
      let data = serialized.data(using: .utf8) else {
      fatalError("Failed to serialize JSON")
    }

    return TransactionData(
      value: data.base64URLEncodedString()
    )
  }
}

// MARK: - JSON Helper Extensions for TransactionData

internal extension JSON {

  func type() throws -> TransactionDataType {
    let typeValue = try self.requiredString(OpenId4VPSpec.TRANSACTION_DATA_TYPE)
    return try TransactionDataType(value: typeValue)
  }

  func hashAlgorithms() -> [HashAlgorithm] {
    if let algorithms = self.optionalStringArray(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS) {
      return algorithms.map { HashAlgorithm(name: $0) }
    } else {
      return [HashAlgorithm.sha256]
    }
  }

  func credentialIds() throws -> [QueryId] {
    let ids = try self.requiredStringArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    return try ids.map { try QueryId(value: $0) }
  }
}

/// A utility to encode and decode base64 strings using URL-safe characters and without padding.
struct Base64UrlNoPadding {
  /// Decodes a URL-safe base64 string without padding back to Data.
  static func decodeToByteString(_ string: String) throws -> Data {

    guard let data = Data(base64UrlEncoded: string) else {
      throw ValidationError.validationError("Invalid base64 string")
    }

    return data
  }
}

extension Sequence where Element: Hashable {
  /// Returns true if this sequence contains all elements of another sequence.
  func containsAll<S: Sequence>(_ other: S) -> Bool where S.Element == Element {
    let selfSet = Set(self)
    return Set(other).isSubset(of: selfSet)
  }
}
