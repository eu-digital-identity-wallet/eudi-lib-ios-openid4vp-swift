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
import XCTest

@testable import OpenID4VP

/// Networking stub that always answers with the given status code and body.
private struct StatusNetworking: Networking {
  let statusCode: Int
  let body: Data

  init(statusCode: Int, body: String = "{\"error\":\"unauthorized\"}") {
    self.statusCode = statusCode
    self.body = Data(body.utf8)
  }

  init(statusCode: Int, bytes: [UInt8]) {
    self.statusCode = statusCode
    self.body = Data(bytes)
  }

  func data(from url: URL) async throws -> (Data, URLResponse) {
    let response = HTTPURLResponse(url: url, statusCode: statusCode, httpVersion: nil, headerFields: nil)!
    return (body, response)
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    try await data(from: request.url!)
  }
}

/// Networking stub that never gets a response.
private struct TransportFailureNetworking: Networking {
  let code: URLError.Code

  func data(from url: URL) async throws -> (Data, URLResponse) {
    throw URLError(code)
  }

  func data(for request: URLRequest) async throws -> (Data, URLResponse) {
    throw URLError(code)
  }
}

final class NetworkFailureTests: DiXCTest {

  private let url = URL(string: "https://verifier.example/request.jwt/abc")!
  private let verifierBody = "{\"error\":\"unauthorized\"}"

  // MARK: - Fetcher

  func testFetchString_WhenNon2xx_ThrowsInvalidStatusCodeWithBody() async {
    let fetcher = Fetcher<String>(session: StatusNetworking(statusCode: 401))

    do {
      _ = try await fetcher.fetchString(url: url)
      XCTFail("Expected FetchError")
    } catch FetchError.invalidStatusCode(let failedUrl, let code, let body) {
      XCTAssertEqual(failedUrl, url)
      XCTAssertEqual(code, 401)
      XCTAssertEqual(body.map { String(decoding: $0, as: UTF8.self) }, verifierBody)
    } catch {
      XCTFail("Expected invalidStatusCode, got \(error)")
    }
  }

  func testFetchString_WhenTransportFails_ThrowsNetworkErrorWithURLError() async {
    let fetcher = Fetcher<String>(session: TransportFailureNetworking(code: .timedOut))

    do {
      _ = try await fetcher.fetchString(url: url)
      XCTFail("Expected FetchError")
    } catch FetchError.networkError(let underlying) {
      XCTAssertEqual((underlying as? URLError)?.code, .timedOut)
    } catch {
      XCTFail("Expected networkError, got \(error)")
    }
  }

  func testFetch_WhenNon2xx_ReturnsInvalidStatusCodeNotDecodingError() async {
    let fetcher = Fetcher<[String: String]>(session: StatusNetworking(statusCode: 500))

    let result = await fetcher.fetch(url: url)

    guard case .failure(.invalidStatusCode(let failedUrl, let code, let body)) = result else {
      return XCTFail("Expected invalidStatusCode, got \(result)")
    }
    XCTAssertEqual(failedUrl, url)
    XCTAssertEqual(code, 500)
    XCTAssertEqual(body.map { String(decoding: $0, as: UTF8.self) }, verifierBody)
  }

  func testFetchError_InvalidStatusCodeDescription_ContainsCodeAndUrl() {
    let error = FetchError.invalidStatusCode(url, 404, nil)
    XCTAssertEqual(error.errorDescription, ".invalidStatusCode 404 \(url)")
  }

  // MARK: - Poster

  func testPostString_WhenNon2xx_ReturnsInvalidStatusCodeWithBody() async {
    let poster = Poster(session: StatusNetworking(statusCode: 400))

    let result = await poster.postString(request: URLRequest(url: url))

    guard case .failure(.invalidStatusCode(let failedUrl, let code, let body)) = result else {
      return XCTFail("Expected invalidStatusCode, got \(result)")
    }
    XCTAssertEqual(failedUrl, url)
    XCTAssertEqual(code, 400)
    XCTAssertEqual(body.map { String(decoding: $0, as: UTF8.self) }, verifierBody)
  }

  func testPostString_WhenTransportFails_ReturnsNetworkError() async {
    let poster = Poster(session: TransportFailureNetworking(code: .notConnectedToInternet))

    let result = await poster.postString(request: URLRequest(url: url))

    guard case .failure(.networkError(let underlying)) = result else {
      return XCTFail("Expected networkError, got \(result)")
    }
    XCTAssertEqual((underlying as? URLError)?.code, .notConnectedToInternet)
  }

  // MARK: - NetworkFailure

  func testNetworkFailure_FromFetchErrorStatusCode_KeepsStatusAndBody() {
    let body = Data(verifierBody.utf8)
    let failure = NetworkFailure(stage: .GET, url: url, fetchError: .invalidStatusCode(url, 403, body))

    XCTAssertEqual(failure.stage, .GET)
    XCTAssertEqual(failure.url, url)
    XCTAssertEqual(failure.statusCode, 403)
    XCTAssertEqual(failure.responseBody, body)
    XCTAssertNil(failure.underlying)
    XCTAssertTrue(failure.isServerResponse)
  }

  func testNetworkFailure_FromFetchErrorTransport_KeepsNativeError() {
    let failure = NetworkFailure(stage: .GET, url: url, fetchError: .networkError(URLError(.cannotFindHost)))

    XCTAssertNil(failure.statusCode)
    XCTAssertFalse(failure.isServerResponse)
    XCTAssertEqual(failure.urlError?.code, .cannotFindHost)
  }

  func testNetworkFailure_FromPostError_UsesRequestUrlWhenMissing() {
    let failure = NetworkFailure(stage: .POST, url: url, postError: .invalidStatusCode(nil, 400, nil))

    XCTAssertEqual(failure.stage, .POST)
    XCTAssertEqual(failure.url, url)
    XCTAssertEqual(failure.statusCode, 400)
  }

  func testNetworkFailure_Equality_IgnoresBodyAndComparesErrorDomainAndCode() {
    let withBody = NetworkFailure(stage: .GET, url: url, statusCode: 401, responseBody: Data([1, 2]))
    let withoutBody = NetworkFailure(stage: .GET, url: url, statusCode: 401, responseBody: nil)
    let otherStatus = NetworkFailure(stage: .GET, url: url, statusCode: 500)
    let timedOut = NetworkFailure(stage: .GET, url: url, underlying: URLError(.timedOut))
    let timedOutAgain = NetworkFailure(stage: .GET, url: url, underlying: URLError(.timedOut))
    let offline = NetworkFailure(stage: .GET, url: url, underlying: URLError(.notConnectedToInternet))

    XCTAssertEqual(withBody, withoutBody)
    XCTAssertNotEqual(withBody, otherStatus)
    XCTAssertEqual(timedOut, timedOutAgain)
    XCTAssertNotEqual(timedOut, offline)
    XCTAssertNotEqual(withoutBody, timedOut)
  }

  // MARK: - ValidationError

  func testValidationError_NetworkError_DescriptionAndErrorCode() {
    let serverError = ValidationError.networkError(.init(stage: .GET, url: url, statusCode: 401))
    let transportError = ValidationError.networkError(
      .init(stage: .POST, url: url, underlying: URLError(.timedOut))
    )

    XCTAssertEqual(serverError.errorDescription, ".networkError GET \(url): status 401")
    XCTAssertTrue(transportError.errorDescription?.hasPrefix(".networkError POST \(url): ") ?? false)
    XCTAssertEqual(AuthorizationRequestErrorCode.fromError(serverError), .invalidRequest)
    XCTAssertEqual(AuthorizationRequestErrorCode.fromError(transportError), .invalidRequest)
  }

  // MARK: - Resolver (request_uri by reference)

  func testResolve_WhenRequestUriGetReturns401_PropagatesTypedNetworkError() async throws {
    let session = StatusNetworking(statusCode: 401)
    let error = try await resolve(session: session, requestUrl: TestsConstants.requestExpiredUrlString)

    guard case .networkError(let failure) = error else {
      return XCTFail("Expected networkError, got \(String(describing: error))")
    }
    XCTAssertEqual(failure.stage, .GET)
    XCTAssertEqual(failure.statusCode, 401)
    XCTAssertEqual(failure.responseBody.map { String(decoding: $0, as: UTF8.self) }, verifierBody)
    XCTAssertNil(failure.underlying)
  }

  func testResolve_WhenRequestUriGetIsOffline_PropagatesURLError() async throws {
    let session = TransportFailureNetworking(code: .notConnectedToInternet)
    let error = try await resolve(session: session, requestUrl: TestsConstants.requestExpiredUrlString)

    guard case .networkError(let failure) = error else {
      return XCTFail("Expected networkError, got \(String(describing: error))")
    }
    XCTAssertEqual(failure.stage, .GET)
    XCTAssertNil(failure.statusCode)
    XCTAssertEqual(failure.urlError?.code, .notConnectedToInternet)
  }

  func testResolve_WhenRequestUriPostReturns400_PropagatesTypedNetworkError() async throws {
    let requestUrl = TestsConstants.requestExpiredUrlString + "&request_uri_method=post"
    let error = try await resolve(session: StatusNetworking(statusCode: 400), requestUrl: requestUrl)

    guard case .networkError(let failure) = error else {
      return XCTFail("Expected networkError, got \(String(describing: error))")
    }
    XCTAssertEqual(failure.stage, .POST)
    XCTAssertEqual(failure.statusCode, 400)
    XCTAssertEqual(failure.responseBody.map { String(decoding: $0, as: UTF8.self) }, verifierBody)
  }

  func testResolve_WhenRequestUriBodyIsNotUtf8_StaysInvalidJwtPayload() async throws {
    let session = StatusNetworking(statusCode: 200, bytes: [0xFF, 0xFE])
    let error = try await resolve(session: session, requestUrl: TestsConstants.requestExpiredUrlString)

    XCTAssertEqual(error, .invalidJwtPayload)
  }

  func testResolve_WhenRequestUriPostBodyIsNotUtf8_StaysInvalidJwtPayload() async throws {
    let requestUrl = TestsConstants.requestExpiredUrlString + "&request_uri_method=post"
    let session = StatusNetworking(statusCode: 200, bytes: [0xFF, 0xFE])
    let error = try await resolve(session: session, requestUrl: requestUrl)

    XCTAssertEqual(error, .invalidJwtPayload)
  }

  // MARK: - Helpers

  private func resolve(session: Networking, requestUrl: String) async throws -> ValidationError? {
    let configuration = try OpenID4VPTests.preRegisteredWalletConfigurationWithKnownClientID("Verifier")
    let request = try UnvalidatedRequest.make(from: requestUrl).get()

    let result = await AuthorizationRequestResolver().resolve(
      walletConfiguration: configuration,
      unvalidatedRequest: request,
      fetcher: Fetcher<String>(session: session),
      poster: Poster(session: session)
    )

    guard case .invalidResolution(let error, let dispatchDetails) = result else {
      XCTFail("Expected invalidResolution, got \(result)")
      return nil
    }
    XCTAssertNil(dispatchDetails, "request_uri fetch failures must stay non-dispatchable")
    return error as? ValidationError
  }
}
