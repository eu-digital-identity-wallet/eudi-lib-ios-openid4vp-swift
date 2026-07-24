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

@testable import OpenID4VP

class TestsHelpers {
  static func transactionDataBase64String() -> String {

    var json = JSON()
    json[OpenId4VPSpec.TRANSACTION_DATA_TYPE].string = "manual-type"
    json[OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS].arrayObject = ["wa_driver_license"]
    json[OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS].arrayObject = ["sha-256"]

    // Serialize JSON to string.
    guard
      let jsonString = json.rawString(),
      let data = jsonString.data(using: .utf8) else {
      fatalError("Failed to serialize JSON")
    }

    return data.base64URLEncodedString()
  }

  static func getDirectPostJwtSession(
    nonce: String,
    format: String = "mso_mdoc",
    transactionData: JSON,
    intendedUseId: String
  ) async throws -> [String: Any] {

    // Replace this URL with the endpoint you want to send the POST request to
    let url = URL(string: "\(TestsConstants.host)/ui/presentations")!

    // Create a POST request
    var request = URLRequest(url: url)
    request.httpMethod = "POST"

    // Set the request body data (e.g., JSON data)
    let jsonBody = [
      "type": "vp_token",
      "response_mode": "direct_post.jwt",
      "nonce": nonce,
      "transaction_data": transactionData,
      "intended_use_id": intendedUseId,
      "dcql_query": [
        "credentials": [
          [
            "id": "query_0",
              "format": format,
              "meta": [
                "doctype_value": "eu.europa.ec.eudi.pid.1"
              ]
          ]
        ]
      ],
    ] as JSON

    let jsonData = try JSONSerialization.data(withJSONObject: jsonBody.object, options: [])
    request.httpBody = jsonData
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")

    let (data, _) = try await URLSession.shared.data(for: request)
    return try JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
  }

  static func getDirectPostJwtSession(
    nonce: String,
    format: String = "mso_mdoc",
    intendedUseId: String
  ) async throws -> [String: Any] {

    // Replace this URL with the endpoint you want to send the POST request to
    let url = URL(string: "\(TestsConstants.host)/ui/presentations")!

    // Create a POST request
    var request = URLRequest(url: url)
    request.httpMethod = "POST"

    // Set the request body data (e.g., JSON data)
    let jsonBody = [
      "type": "vp_token",
      "response_mode": "direct_post.jwt",
      "nonce": nonce,
      "intended_use_id": intendedUseId,
      "dcql_query": [
        "credentials": [
          [
            "id": "query_0",
              "format": format,
              "meta": [
                "doctype_value": "eu.europa.ec.eudi.pid.1"
              ]
          ]
        ]
      ],
    ] as [String: Any]

    let jsonData = try JSONSerialization.data(withJSONObject: jsonBody, options: [])
    request.httpBody = jsonData
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")

    let (data, _) = try await URLSession.shared.data(for: request)
    return try JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
  }

  static func getDirectPostJwtSessionAcceptRequestURI(
    nonce: String
  ) async throws -> [String: Any] {

    // Replace this URL with the endpoint you want to send the POST request to
    let url = URL(string: "\(TestsConstants.host)/ui/presentations")!

    // Create a POST request
    var request = URLRequest(url: url)
    request.httpMethod = "POST"

    // Set the request body data (e.g., JSON data)
    let jsonBody = [
      "type": "vp_token",
      "response_mode": "direct_post.jwt",
      "nonce": nonce,
      "presentation_definition_mode": "by_reference",
      "wallet_response_redirect_uri_template": "https://eudi.netcompany-intrasoft.com/san-dns/get-wallet-code?response_code={RESPONSE_CODE}",
      "presentation_definition": [
        "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "input_descriptors": [
          [
            "id": "wa_driver_license",
            "name": "Washington State Business License",
            "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
            "constraints": [
              "fields": [
                [
                  "path": [
                    "$.credentialSubject.dateOfBirth",
                    "$.credentialSubject.dob",
                    "$.vc.credentialSubject.dateOfBirth",
                    "$.vc.credentialSubject.dob"
                  ]
                ]
              ]
            ]
          ]
        ]
      ]
    ] as [String: Any]

    let jsonData = try JSONSerialization.data(withJSONObject: jsonBody, options: [])
    request.httpBody = jsonData
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")

    let (data, _) = try await URLSession.shared.data(for: request)
    return try JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
  }

  static func getDirectPostVpTokenSession(
    nonce: String
  ) async throws -> [String: Any] {

    // Replace this URL with the endpoint you want to send the POST request to
    let url = URL(string: "\(TestsConstants.host)/ui/presentations")!

    // Create a POST request
    var request = URLRequest(url: url)
    request.httpMethod = "POST"

    // Set the request body data (e.g., JSON data)
    let jsonBody = [
      "type": "vp_token",
      "response_mode": "direct_post",
      "nonce": nonce,
      "presentation_definition_mode": "by_reference",
      "presentation_definition": [
        "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "name": "name",
        "purpose": "purpose",
        "input_descriptors": []
      ]
    ] as [String: Any]

    let jsonData = try JSONSerialization.data(withJSONObject: jsonBody, options: [])
    request.httpBody = jsonData
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")

    let (data, _) = try await URLSession.shared.data(for: request)
    return try JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
  }

  static func pollVerifier(transactionId: String, nonce: String) async throws -> Result<String, FetchError> {
    let fetcher = Fetcher<String>()
    let pollingUrl = URL(string: "\(TestsConstants.host)/ui/presentations/\(transactionId)?nonce=\(nonce)")!
    return try await fetcher.fetchString(url: pollingUrl)
  }
}
