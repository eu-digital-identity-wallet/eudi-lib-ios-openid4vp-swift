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
import JOSESwift

@testable import OpenID4VP

/// Tests for error dispatch security - ensuring that response_uri is not extracted
/// from unverified JWTs for pre-authentication errors.
final class ErrorDispatchSecurityTests: XCTestCase {

  var resolver: AuthorizationRequestResolver!
  var config: OpenId4VPConfiguration!

  override func setUp() async throws {
    overrideDependencies()
    try await super.setUp()
    resolver = AuthorizationRequestResolver()
    config = try createTestConfiguration()
  }

  override func tearDown() {
    DependencyContainer.shared.removeAll()
    resolver = nil
    config = nil
    super.tearDown()
  }

  // MARK: - Pre-Authentication Error Dispatch Tests

  /// JWT-secured requests should NOT return dispatch details before authentication
  /// This prevents attackers from receiving error callbacks at attacker-controlled endpoints
  func testPreAuthJwtSecuredRequest_ReturnsNilDispatchDetails() async {
    // Create a JWT-secured request with response_uri in the payload
    let jwtPayload = """
    {
      "client_id": "https://attacker.com",
      "response_uri": "https://attacker.com/callback",
      "response_mode": "direct_post",
      "nonce": "test-nonce",
      "state": "test-state"
    }
    """
    let jwt = createUnsignedJWT(payload: jwtPayload)
    let fetchedRequest = FetchedRequest.jwtSecured(
      clientId: "https://attacker.com",
      jwt: jwt
    )

    // Call the function that extracts dispatch details before authentication
    let dispatchDetails = await resolver.optionalDispatchDetails(
      config: config,
      fetchedRequest: fetchedRequest
    )

    // Should be nil - we don't want to send errors to unverified endpoints
    XCTAssertNil(dispatchDetails, "JWT-secured requests should not return dispatch details before authentication")
  }

  /// Plain requests CAN return dispatch details before authentication
  /// because the response_uri is in query parameters, not in a signed JWT
  func testPreAuthPlainRequest_WithDirectPost_ReturnsDispatchDetails() async {
    let requestObject = UnvalidatedRequestObject(
      responseType: "vp_token",
      responseUri: "https://verifier.example.com/callback",
      redirectUri: nil,
      dcqlQuery: nil,
      request: nil,
      requestUri: nil,
      requestUriMethod: nil,
      clientMetaData: nil,
      clientId: "https://verifier.example.com",
      clientMetadataUri: nil,
      clientIdScheme: "redirect_uri",
      nonce: "test-nonce",
      scope: nil,
      responseMode: "direct_post",
      state: "test-state",
      supportedAlgorithm: nil,
      transactionData: nil,
      verifierInfo: nil
    )
    let fetchedRequest = FetchedRequest.plain(requestObject: requestObject)

    let dispatchDetails = await resolver.optionalDispatchDetails(
      config: config,
      fetchedRequest: fetchedRequest
    )

    // Should return dispatch details for plain requests
    XCTAssertNotNil(dispatchDetails, "Plain requests should return dispatch details")
    XCTAssertEqual(dispatchDetails?.state, "test-state")
    XCTAssertEqual(dispatchDetails?.nonce, "test-nonce")
  }

  /// Plain requests with fragment response mode should work
  func testPreAuthPlainRequest_WithFragment_ReturnsDispatchDetails() async {
    let requestObject = UnvalidatedRequestObject(
      responseType: "vp_token",
      responseUri: nil,
      redirectUri: "https://verifier.example.com/callback",
      dcqlQuery: nil,
      request: nil,
      requestUri: nil,
      requestUriMethod: nil,
      clientMetaData: nil,
      clientId: "https://verifier.example.com/callback",
      clientMetadataUri: nil,
      clientIdScheme: "redirect_uri",
      nonce: "test-nonce",
      scope: nil,
      responseMode: "fragment",
      state: "test-state",
      supportedAlgorithm: nil,
      transactionData: nil,
      verifierInfo: nil
    )
    let fetchedRequest = FetchedRequest.plain(requestObject: requestObject)

    let dispatchDetails = await resolver.optionalDispatchDetails(
      config: config,
      fetchedRequest: fetchedRequest
    )

    // Should return dispatch details for plain requests with fragment mode
    XCTAssertNotNil(dispatchDetails, "Plain requests with fragment mode should return dispatch details")
  }

  /// Plain requests without valid response mode should return nil
  func testPreAuthPlainRequest_WithInvalidResponseMode_ReturnsNil() async {
    let requestObject = UnvalidatedRequestObject(
      responseType: "vp_token",
      responseUri: nil,
      redirectUri: nil,
      dcqlQuery: nil,
      request: nil,
      requestUri: nil,
      requestUriMethod: nil,
      clientMetaData: nil,
      clientId: "https://verifier.example.com",
      clientMetadataUri: nil,
      clientIdScheme: nil,
      nonce: "test-nonce",
      scope: nil,
      responseMode: "invalid_mode",
      state: "test-state",
      supportedAlgorithm: nil,
      transactionData: nil,
      verifierInfo: nil
    )
    let fetchedRequest = FetchedRequest.plain(requestObject: requestObject)

    let dispatchDetails = await resolver.optionalDispatchDetails(
      config: config,
      fetchedRequest: fetchedRequest
    )

    // Should be nil for invalid response mode
    XCTAssertNil(dispatchDetails, "Invalid response mode should return nil dispatch details")
  }

  // MARK: - Post-Authentication Error Dispatch Tests

  /// After authentication, using the authenticated request object should work
  func testPostAuthRequestObject_WithDirectPost_ReturnsDispatchDetails() async {
    let requestObject = UnvalidatedRequestObject(
      responseType: "vp_token",
      responseUri: "https://verifier.example.com/callback",
      redirectUri: nil,
      dcqlQuery: nil,
      request: nil,
      requestUri: nil,
      requestUriMethod: nil,
      clientMetaData: nil,
      clientId: "https://verifier.example.com",
      clientMetadataUri: nil,
      clientIdScheme: nil,
      nonce: "test-nonce",
      scope: nil,
      responseMode: "direct_post",
      state: "test-state",
      supportedAlgorithm: nil,
      transactionData: nil,
      verifierInfo: nil
    )

    // This simulates the post-authentication path where we use requestObject directly
    let dispatchDetails = await resolver.optionalDispatchDetails(
      config: config,
      requestObject: requestObject
    )

    XCTAssertNotNil(dispatchDetails, "Post-auth request object should return dispatch details")
    XCTAssertEqual(dispatchDetails?.state, "test-state")
    XCTAssertEqual(dispatchDetails?.nonce, "test-nonce")
  }

  /// JARM response modes should not return dispatch details (handled differently)
  func testPostAuthRequestObject_WithJARM_ReturnsNil() async {
    let requestObject = UnvalidatedRequestObject(
      responseType: "vp_token",
      responseUri: "https://verifier.example.com/callback",
      redirectUri: nil,
      dcqlQuery: nil,
      request: nil,
      requestUri: nil,
      requestUriMethod: nil,
      clientMetaData: nil,
      clientId: "https://verifier.example.com",
      clientMetadataUri: nil,
      clientIdScheme: nil,
      nonce: "test-nonce",
      scope: nil,
      responseMode: "direct_post.jwt",
      state: "test-state",
      supportedAlgorithm: nil,
      transactionData: nil,
      verifierInfo: nil
    )

    let dispatchDetails = await resolver.optionalDispatchDetails(
      config: config,
      requestObject: requestObject
    )

    // JARM modes are handled separately, this function returns nil for them
    XCTAssertNil(dispatchDetails, "JARM response modes should return nil from this function")
  }

  // MARK: - Helper Methods

  private func createUnsignedJWT(payload: String) -> String {
    let header = #"{"alg":"RS256","typ":"JWT"}"#
    let headerBase64 = Data(header.utf8).base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    let payloadBase64 = Data(payload.utf8).base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    // Unsigned JWT (just for testing - signature is fake)
    return "\(headerBase64).\(payloadBase64).fake_signature"
  }

  private func createTestConfiguration() throws -> OpenId4VPConfiguration {
    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)

    let alg = JWSAlgorithm(.RS256)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])

    let keySet = try WebKeySet([
      "keys": [publicKeyJWK.jsonString()?.convertToDictionary()]
    ])

    return OpenId4VPConfiguration(
      privateKey: privateKey,
      publicWebKeySet: keySet,
      supportedClientIdSchemes: [
        .redirectUri
      ],
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: .noEncryptionOption,
      vpConfiguration: VPConfiguration.default(),
      errorDispatchPolicy: .allClients,  // Use allClients to test the security fix
      responseEncryptionConfiguration: .unsupported
    )
  }
}

private extension ErrorDispatchSecurityTests {
  func overrideDependencies() {
    DependencyContainer.shared.register(type: Reporting.self, dependency: {
      MockReporter()
    })
  }
}
