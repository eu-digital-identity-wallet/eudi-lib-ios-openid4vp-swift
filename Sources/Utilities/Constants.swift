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

public struct Constants {

  public static let WALLET_NONCE_FORM_PARAM = "wallet_nonce"
  public static let WALLET_METADATA_FORM_PARAM = "wallet_metadata"

  public static let CLIENT_ID = "client_id"
  public static let NONCE = "nonce"
  public static let SCOPE = "scope"
  public static let STATE = "state"
  public static let HTTPS = "https"
  public static let CLIENT_ID_SCHEME = "client_id_scheme"
  public static let PRESENTATION_DEFINITION = "presentation_definition"
  public static let DCQL_QUERY = "dcql_query"
  public static let VERIFIER_INFO = "verifier_info"
  public static let PRESENTATION_DEFINITION_URI = "presentation_definition_uri"
  public static let REQUEST_URI_METHOD = "request_url_method"
  public static let CLIENT_METADATA = "client_metadata"
  public static let TRANSACTION_DATA = "transaction_data"
  public static let RESPONSE_URI = "response_uri"

  static let presentationSubmissionKey = "presentation_submission"
}
