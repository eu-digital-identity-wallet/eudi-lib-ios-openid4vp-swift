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
import SwiftyJSON
@testable import OpenID4VP

class ResponseModeTests: XCTestCase {
  func testInitWithValidDirectPostJSON() throws {
    let url = "https://openID4VP.com/callback"
    let json: JSON = [
      "response_mode": "direct_post",
      "response_uri": url
    ]

    let responseMode = try ResponseMode(authorizationRequestObject: json)

    if case let .directPost(responseURI) = responseMode {
      XCTAssertEqual(responseURI.absoluteString, url)
    } else {
      XCTFail("Expected .directPost but got \(responseMode)")
    }
  }

  func testInitWithValidQueryJSON() throws {
    let url = "https://openID4VP.com/redirect"
    let json: JSON = [
      "response_mode": "query",
      "redirect_uri": url
    ]

    let responseMode = try ResponseMode(authorizationRequestObject: json)

    if case let .query(responseURI) = responseMode {
      XCTAssertEqual(responseURI.absoluteString, url)
    } else {
      XCTFail("Expected .query but got \(responseMode)")
    }
  }

  func testInitWithMissingResponseMode() {
    let json: JSON = [
      "redirect_uri": "https://openID4VP.com/redirect"
    ]

    XCTAssertThrowsError(try ResponseMode(authorizationRequestObject: json)) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError")
      }
      XCTAssertEqual(validationError, .missingRequiredField(".responseMode"))
    }
  }

  func testInitWithUnsupportedResponseMode() {
    let json: JSON = [
      "response_mode": "unsupported_mode"
    ]

    XCTAssertThrowsError(try ResponseMode(authorizationRequestObject: json)) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError")
      }
      XCTAssertEqual(validationError, .unsupportedResponseMode("unsupported_mode"))
    }
  }

  func testIsJarmWhenDirectPostJWT() {
    let url = URL(string: "https://openID4VP.com")!
    let mode = ResponseMode.directPostJWT(responseURI: url)
    XCTAssertTrue(mode.isJarm())
  }

  func testIsJarmWhenDirectPost() {
    let url = URL(string: "https://openID4VP.com")!
    let mode = ResponseMode.directPost(responseURI: url)
    XCTAssertFalse(mode.isJarm())
  }

  func testValidatedResponseModeWithValidData() {
    let data = UnvalidatedRequestObject(
      responseUri: nil,
      redirectUri: "https://openID4VP.com",
      responseMode: "query"
    )

    let mode = data.validatedResponseMode
    if case let .query(responseURI)? = mode {
      XCTAssertEqual(responseURI.absoluteString, "https://openID4VP.com")
    } else {
      XCTFail("Expected .query but got nil or another value")
    }
  }

  // MARK: - Tests for rejecting requests with both response_uri and redirect_uri

  func testInitDirectPostWithBothUrisThrowsInvalidRequest() {
    let json: JSON = [
      "response_mode": "direct_post",
      "response_uri": "https://openID4VP.com/callback",
      "redirect_uri": "https://openID4VP.com/redirect"
    ]

    XCTAssertThrowsError(try ResponseMode(authorizationRequestObject: json)) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  func testInitDirectPostJwtWithBothUrisThrowsInvalidRequest() {
    let json: JSON = [
      "response_mode": "direct_post.jwt",
      "response_uri": "https://openID4VP.com/callback",
      "redirect_uri": "https://openID4VP.com/redirect"
    ]

    XCTAssertThrowsError(try ResponseMode(authorizationRequestObject: json)) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  func testInitQueryWithBothUrisThrowsInvalidRequest() {
    let json: JSON = [
      "response_mode": "query",
      "response_uri": "https://openID4VP.com/callback",
      "redirect_uri": "https://openID4VP.com/redirect"
    ]

    XCTAssertThrowsError(try ResponseMode(authorizationRequestObject: json)) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  func testInitFragmentWithBothUrisThrowsInvalidRequest() {
    let json: JSON = [
      "response_mode": "fragment",
      "response_uri": "https://openID4VP.com/callback",
      "redirect_uri": "https://openID4VP.com/redirect"
    ]

    XCTAssertThrowsError(try ResponseMode(authorizationRequestObject: json)) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  func testInitWithUnvalidatedRequestObjectDirectPostWithBothUrisThrowsInvalidRequest() {
    let data = UnvalidatedRequestObject(
      responseUri: "https://openID4VP.com/callback",
      redirectUri: "https://openID4VP.com/redirect",
      responseMode: "direct_post"
    )

    XCTAssertThrowsError(try ResponseMode(authorizationRequestData: data)) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  func testInitWithUnvalidatedRequestObjectQueryWithBothUrisThrowsInvalidRequest() {
    let data = UnvalidatedRequestObject(
      responseUri: "https://openID4VP.com/callback",
      redirectUri: "https://openID4VP.com/redirect",
      responseMode: "query"
    )

    XCTAssertThrowsError(try ResponseMode(authorizationRequestData: data)) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  func testValidatedResponseModeDirectPostWithBothUrisReturnsNil() {
    let data = UnvalidatedRequestObject(
      responseUri: "https://openID4VP.com/callback",
      redirectUri: "https://openID4VP.com/redirect",
      responseMode: "direct_post"
    )

    XCTAssertNil(data.validatedResponseMode)
  }

  func testValidatedResponseModeQueryWithBothUrisReturnsNil() {
    let data = UnvalidatedRequestObject(
      responseUri: "https://openID4VP.com/callback",
      redirectUri: "https://openID4VP.com/redirect",
      responseMode: "query"
    )

    XCTAssertNil(data.validatedResponseMode)
  }
}
