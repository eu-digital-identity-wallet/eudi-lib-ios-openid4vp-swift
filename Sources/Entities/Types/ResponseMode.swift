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

public enum ResponseMode: Sendable {
  case directPost(responseURI: URL)
  case directPostJWT(responseURI: URL)
  case query(responseURI: URL)
  case fragment(responseURI: URL)
  case none

  /// Initializes a `ResponseMode` instance with the given authorization request object.
  ///
  /// - Parameter authorizationRequestObject: The authorization request object.
  /// - Throws: A `ValidatedAuthorizationError.missingRequiredField` if the required fields are missing,
  ///           or a `ValidatedAuthorizationError.unsupportedResponseMode` if the response mode is unsupported.
  public init(authorizationRequestObject: JSON) throws {
    guard let responseMode = authorizationRequestObject["response_mode"].string else {
      throw ValidationError.missingRequiredField(".responseMode")
    }

    let hasResponseUri = authorizationRequestObject["response_uri"].string != nil
    let hasRedirectUri = authorizationRequestObject["redirect_uri"].string != nil

    switch responseMode {
    case "direct_post":
      guard !hasRedirectUri else {
        throw ValidationError.invalidRequest
      }
      if let responseUri = authorizationRequestObject["response_uri"].string,
         let uri = URL(string: responseUri) {
        self = .directPost(responseURI: uri)
      } else {
        throw ValidationError.missingRequiredField(".responseUri")
      }
    case "direct_post.jwt":
      guard !hasRedirectUri else {
        throw ValidationError.invalidRequest
      }
      if let responseUri = authorizationRequestObject["response_uri"].string,
         let uri = URL(string: responseUri) {
        self = .directPostJWT(responseURI: uri)
      } else {
        throw ValidationError.missingRequiredField(".responseUri")
      }
    case "query":
      guard !hasResponseUri else {
        throw ValidationError.invalidRequest
      }
      if let redirectUri = authorizationRequestObject["redirect_uri"].string,
         let uri = URL(string: redirectUri) {
        self = .query(responseURI: uri)
      } else {
        throw ValidationError.missingRequiredField(".redirectUri")
      }
    case "fragment":
      guard !hasResponseUri else {
        throw ValidationError.invalidRequest
      }
      if let redirectUri = authorizationRequestObject["redirect_uri"].string,
         let uri = URL(string: redirectUri) {
        self = .fragment(responseURI: uri)
      } else {
        throw ValidationError.missingRequiredField(".redirectUri")
      }
    default:
      throw ValidationError.unsupportedResponseMode(responseMode)
    }
  }

  /// Initializes a `ResponseMode` instance with the given authorization request data.
  ///
  /// - Parameter authorizationRequestData: The authorization request data.
  /// - Throws: A `ValidatedAuthorizationError.missingRequiredField` if the required fields are missing,
  ///           or a `ValidatedAuthorizationError.unsupportedResponseMode` if the response mode is unsupported.
  public init(authorizationRequestData: UnvalidatedRequestObject) throws {
    guard let responseMode = authorizationRequestData.responseMode else {
      throw ValidationError.missingRequiredField(".responseMode")
    }

    let hasResponseUri = authorizationRequestData.responseUri != nil
    let hasRedirectUri = authorizationRequestData.redirectUri != nil

    switch responseMode {
    case "direct_post":
      guard !hasRedirectUri else {
        throw ValidationError.invalidRequest
      }
      if let responseUri = authorizationRequestData.responseUri,
         let uri = URL(string: responseUri) {
        self = .directPost(responseURI: uri)
      } else {
        throw ValidationError.missingRequiredField(".responseUri")
      }
    case "direct_post.jwt":
      guard !hasRedirectUri else {
        throw ValidationError.invalidRequest
      }
      if let responseUri = authorizationRequestData.responseUri,
         let uri = URL(string: responseUri) {
        self = .directPostJWT(responseURI: uri)
      } else {
        throw ValidationError.missingRequiredField(".responseUri")
      }
    case "query":
      guard !hasResponseUri else {
        throw ValidationError.invalidRequest
      }
      if let redirectUri = authorizationRequestData.redirectUri,
         let uri = URL(string: redirectUri) {
        self = .query(responseURI: uri)
      } else {
        throw ValidationError.missingRequiredField(".redirectUri")
      }
    case "fragment":
      guard !hasResponseUri else {
        throw ValidationError.invalidRequest
      }
      if let redirectUri = authorizationRequestData.redirectUri,
         let uri = URL(string: redirectUri) {
        self = .fragment(responseURI: uri)
      } else {
        throw ValidationError.missingRequiredField(".redirectUri")
      }
    default:
      throw ValidationError.unsupportedResponseMode(responseMode)
    }
  }
}

internal extension ResponseMode {
  
  func requiresEncryption() -> Bool {
    switch self {
    case .directPostJWT:
      return true
    default:
      return false
    }
  }
  
  func isJarm() -> Bool {
    switch self {
    case .directPost:
      return false
    case .directPostJWT:
      return true
    case .query:
      return false
    case .fragment:
      return false
    case .none:
      return false
    }
  }
}

internal extension UnvalidatedRequestObject {
  var validatedResponseMode: ResponseMode? {

    let hasResponseUri = self.responseUri != nil
    let hasRedirectUri = self.redirectUri != nil

    func responseUriURL() -> URL? {
      guard let responseUri = self.responseUri else { return nil }
      return URL(string: responseUri)
    }

    func redirectUriURL() -> URL? {
      guard let redirectUri = self.redirectUri else { return nil }
      return URL(string: redirectUri)
    }

    switch self.responseMode {
    case "direct_post":
      guard !hasRedirectUri else { return nil }
      return responseUriURL().map { .directPost(responseURI: $0) }
    case "direct_post.jwt":
      guard !hasRedirectUri else { return nil }
      return responseUriURL().map { .directPostJWT(responseURI: $0) }
    case "query":
      guard !hasResponseUri else { return nil }
      return redirectUriURL().map { .query(responseURI: $0) }
    case nil, "fragment":
      guard !hasResponseUri else { return nil }
      return redirectUriURL().map { .fragment(responseURI: $0) }
    default:
      return nil
    }
  }
}
