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

/// Represents an unvalidated authorization request.
public enum UnvalidatedRequest: Sendable {

  case plain(UnvalidatedRequestObject)
  case jwtSecuredPassByValue(
    clientId: String,
    jwt: JWTString
  )
  case jwtSecuredPassByReference(
    clientId: String,
    jwtURI: URL,
    requestURIMethod: RequestUriMethod?
  )

  /// Attempts to parse a URI string into an `UnvalidatedRequest`.
  /// - Parameter uriStr: The authorization request URI as a string.
  /// - Returns: A `Result` containing either a valid `UnvalidatedRequest` or an error.
  public static func make(from uriStr: String) -> Result<UnvalidatedRequest, Error> {
    Result {
      guard
        let components = URLComponents(string: uriStr)
      else {
        throw ValidationError.invalidUri
      }

      let helper = QueryHelper(components)

      let request = helper.string("request")
      let requestURI = helper.string("request_uri")
      let method = try helper.requestUriMethod()

      switch (request?.isEmpty == false, requestURI?.isEmpty == false) {
      case (true, false):
        guard method == nil else {
          throw ValidationError.invalidRequestUriMethod
        }
        return .jwtSecuredPassByValue(
          clientId: try helper.required("client_id"),
          jwt: request!
        )

      case (false, true):
        guard let uri = URL(string: requestURI!) else {
          throw ValidationError.invalidUri
        }
        guard uri.scheme?.lowercased() == "https" else {
          throw ValidationError.insecureUrlScheme(
            field: "request_uri",
            scheme: uri.scheme ?? "none"
          )
        }
        return .jwtSecuredPassByReference(
          clientId: try helper.required("client_id"),
          jwtURI: uri,
          requestURIMethod: method
        )

      case (false, false):
        return .plain(try helper.parseUnsecured())

      default:
        throw ValidationError.invalidUseOfBothRequestAndRequestUri
      }
    }
  }
}

// MARK: - Helper for Query Parsing

internal struct QueryHelper {
  let components: URLComponents

  init(_ components: URLComponents) {
    self.components = components
  }

  func string(_ name: String) -> String? {
    components.queryItems?.first(where: { $0.name == name })?.value
  }

  func required(_ name: String) throws -> String {
    guard let value = string(name) else {
      throw ValidationError.missingClientId
    }
    return value
  }

  func json(_ name: String) -> JSON? {
    string(name).map { JSON(parseJSON: $0) }
  }

  func jsonArray(_ name: String) -> [String]? {
    json(name)?.array?.compactMap { $0.string }
  }
  
  func jsonArrayObject(_ name: String) -> [JSON]? {
    json(name)?.array
  }

  func requestUriMethod() throws -> RequestUriMethod? {
    guard let raw = string("request_uri_method")?.lowercased() else { return nil }
    switch raw {
    case "get": return .GET
    case "post": return .POST
    default: throw ValidationError.invalidRequestUriMethod
    }
  }

  func parseUnsecured() throws -> UnvalidatedRequestObject {
    let clientMetaData = json("client_metadata")?.dictionaryObject?.toJSONString() ?? json("client_metadata")?.string
    return .init(
      responseType: string("response_type"),
      responseUri: string(Constants.RESPONSE_URI),
      redirectUri: string("redirect_uri"),
      dcqlQuery: json(Constants.DCQL_QUERY),
      clientMetaData: clientMetaData,
      clientId: string("client_id"),
      nonce: string("nonce"),
      scope: string("scope"),
      responseMode: string("response_mode"),
      state: string("state"),
      transactionData: json(Constants.TRANSACTION_DATA)?.arrayObject as? [String],
      verifierInfo: jsonArrayObject(Constants.VERIFIER_INFO),
      malformedTransactionData: string(Constants.TRANSACTION_DATA) != nil && (json(Constants.TRANSACTION_DATA)?.arrayObject as? [String]) == nil
    )
  }

  internal func jsonString(from dictionary: [String: Any]?) -> String? {
    guard let dictionary = dictionary,
          JSONSerialization.isValidJSONObject(dictionary),
          let data = try? JSONSerialization.data(withJSONObject: dictionary, options: []),
          let jsonString = String(data: data, encoding: .utf8) else {
      return nil
    }
    return jsonString
  }
}
