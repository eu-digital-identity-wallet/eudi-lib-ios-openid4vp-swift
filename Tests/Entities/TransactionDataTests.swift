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
import SwiftyJSON

@testable import OpenID4VP

final class TransactionDataTests: XCTestCase {

  func testCreateTransactionData() throws {

    // Given transaction data
    let transactionData = TransactionData.create(
      type: try .init(value: "example-type"),
      credentialIds: [
        try .init(value: "cred1"),
        try .init(value: "cred2")
      ],
      hashAlgorithms: [HashAlgorithm.sha256]
    )

    // Decode the transaction data and check the JSON content.
    let decodedJSON = try transactionData.decode(transactionData.value)

    // Check that the type, credential IDs, and hash algorithms are as expected.
    let typeFromJSON = try decodedJSON.type().value
    XCTAssertEqual(typeFromJSON, "example-type")

    let credentialIdsFromJSON = try decodedJSON.credentialIds().map { $0.value }
    XCTAssertEqual(Set(credentialIdsFromJSON), Set(["cred1", "cred2"]))

    let hashAlgorithmsFromJSON = decodedJSON.hashAlgorithms().map { $0.name }
    XCTAssertEqual(hashAlgorithmsFromJSON, ["sha-256"])
  }

  func testParseValidTransactionData() throws {

    // Given transaction data
    let transactionData = TransactionData.create(
      type: try .init(value: "example-type"),
      credentialIds: [
        try .init(value: "query_0"),
      ],
      hashAlgorithms: [HashAlgorithm.sha256]
    )

    // Create a supported type that matches the sample transaction data.
    let supportedType: SupportedTransactionDataType = try .init(
      type: .init(value: "example-type"),
      hashAlgorithms: Set([HashAlgorithm.sha256])
    )

    // Parse the transaction data.
    let result = TransactionData.parse(
      transactionData.value,
      supportedTypes: [supportedType],
      presentationQuery: .byDigitalCredentialsQuery(try! .init(credentials: [
        .init(
          id: .init(value: "query_0"),
          format: .init(format: "sd-jwt"),
          meta: [:]
        )
      ]))
    )

    switch result {
    case .success(let parsedData):
      // Validate that the parsed data has the expected type.
      let parsedType = try parsedData.type().value
      XCTAssertEqual(parsedType, "example-type")
    case .failure(let error):
      XCTFail("Parsing failed with error: \(error)")
    }
  }
  
  func testParseTransactionWithTypeSpecificParameters() throws {

    // Given transaction data
    let transactionData = TransactionData.create(
      type: try .init(value: "example-type"),
      credentialIds: [
        try .init(value: "query_0"),
      ],
      hashAlgorithms: nil,
      builder: { (json: inout JSON) in
        json["example-parameter-0"] = "value_0"
        json["example-parameter-1"] = "value_1"
      }
    )

    // Create a supported type that matches the sample transaction data.
    let supportedType: SupportedTransactionDataType = try .init(
      type: .init(value: "example-type"),
    )

    // Parse the transaction data.
    let result = TransactionData.parse(
      transactionData.value,
      supportedTypes: [supportedType],
      presentationQuery: .byDigitalCredentialsQuery(try! .init(credentials: [
        .init(
          id: .init(value: "query_0"),
          format: .init(format: "mso_mdoc"),
          meta: [:]
        )
      ]))
    )

    switch result {
    case .success(let parsedData):
      // Validate that the parsed data has the expected type.
      let parsedType = try parsedData.type().value
      XCTAssertEqual(parsedType, "example-type")
      
      let specificParameters = try parsedData.specificParameters()
      XCTAssertEqual(specificParameters["example-parameter-0"] as! String, "value_0")
      XCTAssertEqual(specificParameters["example-parameter-1"] as! String, "value_1")
      XCTAssertNil(specificParameters[OpenId4VPSpec.TRANSACTION_DATA_TYPE])
      XCTAssertNil(specificParameters[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS])
      XCTAssertNil(specificParameters[OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS])
    case .failure(let error):
      XCTFail("Parsing failed with error: \(error)")
    }
  }

  func testParsingFailsWhenTransactionDataContainsUnsupportedType() throws {

    // Given transaction data
    let transactionData = TransactionData.create(
      type: try .init(value: "example-type"),
      credentialIds: [
        try .init(value: "cred1"),
        try .init(value: "cred2")
      ],
      hashAlgorithms: [HashAlgorithm.sha256]
    )

    // Create a supported type with a different type value.
    let unsupportedType = try SupportedTransactionDataType(
      type: TransactionDataType(value: "different-type"),
      hashAlgorithms: Set([HashAlgorithm.sha256])
    )

    let result = TransactionData.parse(
      transactionData.value,
      supportedTypes: [unsupportedType],
      presentationQuery: .byDigitalCredentialsQuery(try! .init(credentials: [
        .init(
          id: .init(value: "query_0"),
          format: .init(format: "sd-jwt"),
          meta: [:]
        )
      ]))
    )

    switch result {
    case .success:
      XCTFail("Parsing should have failed due to unsupported type")
    case .failure(let error):
      // Check that error is a validation error (optionally, check the error message).
      XCTAssertTrue((error as? ValidationError) != nil)
    }
  }

  func testParsingFailsWhenCredentialIDsNotMatch() throws {

    // Given transaction data
    let transactionData = TransactionData.create(
      type: try .init(value: "example-type"),
      credentialIds: [
        try .init(value: "cred11"),
        try .init(value: "cred22")
      ],
      hashAlgorithms: [HashAlgorithm.sha256]
    )

    // Create a supported type that matches.
    let supportedType = try SupportedTransactionDataType(
      type: TransactionDataType(value: "example-type"),
      hashAlgorithms: Set([HashAlgorithm.sha256])
    )

    let result = TransactionData.parse(
      transactionData.value,
      supportedTypes: [supportedType],
      presentationQuery: .byDigitalCredentialsQuery(try! .init(credentials: [
        .init(
          id: .init(value: "query_0"),
          format: .init(format: "sd-jwt"),
          meta: [:]
        )
      ]))
    )

    switch result {
    case .success:
      XCTFail("Parsing should have failed due to missing credential IDs")
    case .failure(let error):
      XCTAssertTrue((error as? ValidationError) != nil)
    }
  }

  // Test that decoding fails when given an invalid base64 string.
  func testInvalidBase64Decoding() {

    // Given a TransactionData instance with an invalid base64 string.
    let invalidTransactionData = TransactionData(value: "invalid-base64-string")

    XCTAssertThrowsError(
      try invalidTransactionData.type(),
      "Expected an error when decoding invalid base64"
    ) { error in
      // Optionally, check that error is of the expected type.
      XCTAssertTrue((error as? ValidationError) != nil)
    }
  }

  func testTransactionDataFromCreateBase64Url() throws {

    // Create the TransactionData using the create function.
    let transactionData = TransactionData.create(
      type: try .init(value: "test-type"),
      credentialIds: [
        try .init(value: "id1"),
        try .init(value: "id2")
      ],
      hashAlgorithms: [HashAlgorithm.sha256]
    )

    // Now, decode the base64url string to JSON using the internal decode method.
    let json = try transactionData.decode(transactionData.value)

    // Verify the JSON fields.
    XCTAssertEqual(try json.requiredString(OpenId4VPSpec.TRANSACTION_DATA_TYPE), "test-type")

    let credentials = try json.requiredStringArray(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)
    XCTAssertEqual(Set(credentials), Set(["id1", "id2"]))

    let algorithms = json.optionalStringArray(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS) ?? []
    XCTAssertEqual(algorithms, ["sha-256"])
  }

  func testTransactionDataFromManualBase64UrlString() throws {

    // Create a JSON object with required properties.
    var json = JSON()
    json[OpenId4VPSpec.TRANSACTION_DATA_TYPE].string = "manual-type"
    json[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS].arrayObject = ["credA", "credB"]
    json[OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS].arrayObject = ["sha-256"]

    // Serialize JSON to string.
    guard
      let jsonString = json.rawString(),
      let data = jsonString.data(using: .utf8) else {
      XCTFail("Failed to serialize JSON")
      return
    }

    // Encode the data to a base64url string.
    let base64UrlString = data.base64URLEncodedString()

    // Create TransactionData from the manually created base64url string.
    let transactionData = TransactionData(value: base64UrlString)

    // Verify the computed properties.
    let decodedType = try transactionData.type().value
    XCTAssertEqual(decodedType, "manual-type")

    let decodedCredentialIds = try transactionData.credentialIds().map { $0.value }
    XCTAssertEqual(Set(decodedCredentialIds), Set(["credA", "credB"]))
  }
}
