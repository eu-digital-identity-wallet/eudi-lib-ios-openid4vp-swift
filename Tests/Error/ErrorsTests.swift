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
@testable import OpenID4VP

class ErrorTests: XCTestCase {

  func testUnsupportedResponseType() {
    let error = AuthorizationError.unsupportedResponseType(type: "code")
    XCTAssertEqual(error.errorDescription, ".unsupportedResponseType code")
  }

  func testMissingResponseType() {
    let error = AuthorizationError.missingResponseType
    XCTAssertEqual(error.errorDescription, ".invalidScopes")
  }

  func testUnsupportedURLScheme() {
    let error = AuthorizationError.unsupportedURLScheme
    XCTAssertEqual(error.errorDescription, ".unsupportedURLScheme")
  }

  func testUnsupportedResolution() {
    let error = AuthorizationError.unsupportedResolution
    XCTAssertEqual(error.errorDescription, ".unsupportedResolution")
  }

  func testInvalidState() {
    let error = AuthorizationError.invalidState
    XCTAssertEqual(error.errorDescription, ".invalidState")
  }

  func testInvalidResponseMode() {
    let error = AuthorizationError.invalidResponseMode
    XCTAssertEqual(error.errorDescription, ".invalidResponseMode")
  }

  func testUnsupportedClientIdScheme() {
    let error = ValidationError.unsupportedClientIdScheme("http")
    XCTAssertEqual(error.errorDescription, ".unsupportedClientIdScheme http")
  }

  func testValidationUnsupportedResponseType() {
    let error = ValidationError.unsupportedResponseType("token")
    XCTAssertEqual(error.errorDescription, ".unsupportedResponseType Optional(\"token\")")
  }

  func testUnsupportedResponseMode() {
    let error = ValidationError.unsupportedResponseMode(nil)
    XCTAssertEqual(error.errorDescription, ".unsupportedResponseMode ")
  }

  func testInvalidResponseType() {
    let error = ValidationError.invalidResponseType
    XCTAssertEqual(error.errorDescription, "")
  }

  func testNoAuthorizationData() {
    let error = ValidationError.noAuthorizationData
    XCTAssertEqual(error.errorDescription, ".noAuthorizationData")
  }

  func testInvalidAuthorizationData() {
    let error = ValidationError.invalidAuthorizationData
    XCTAssertEqual(error.errorDescription, "invalidAuthorizationData")
  }

  func testInvalidClientMetadata() {
    let error = ValidationError.invalidClientMetadata
    XCTAssertEqual(error.errorDescription, ".invalidClientMetadata")
  }

  func testMissingRequiredField() {
    let error = ValidationError.missingRequiredField("scope")
    XCTAssertEqual(error.errorDescription, ".missingRequiredField scope")
  }

  func testInvalidJwtPayload() {
    let error = ValidationError.invalidJwtPayload
    XCTAssertEqual(error.errorDescription, ".invalidJwtPayload")
  }

  func testInvalidRequestUri() {
    let error = ValidationError.invalidRequestUri("http://example.com")
    XCTAssertEqual(error.errorDescription, ".invalidRequestUri http://example.com")
  }

  func testConflictingData() {
    let error = ValidationError.conflictingData
    XCTAssertEqual(error.errorDescription, ".conflictingData")
  }

  func testInvalidRequest() {
    let error = ValidationError.invalidRequest
    XCTAssertEqual(error.errorDescription, ".invalidRequest")
  }

  func testNotSupportedOperation() {
    let error = ValidationError.notSupportedOperation
    XCTAssertEqual(error.errorDescription, ".notSupportedOperation")
  }

  func testInvalidFormat() {
    let error = ValidationError.invalidFormat
    XCTAssertEqual(error.errorDescription, ".invalidFormat")
  }

  func testUnsupportedConsent() {
    let error = ValidationError.unsupportedConsent
    XCTAssertEqual(error.errorDescription, ".unsupportedConsent")
  }

  func testNegativeConsent() {
    let error = ValidationError.negativeConsent
    XCTAssertEqual(error.errorDescription, ".negativeConsent")
  }

  func testInvalidSource() {
    let error = ResolvingError.invalidSource
    XCTAssertEqual(error.errorDescription, ".invalidSource")
  }

  func testInvalidScopes() {
    let error = ResolvingError.invalidScopes
    XCTAssertEqual(error.errorDescription, ".invalidScopes")
  }

  func testInvalidClientData() {
    let error = ResolvedAuthorisationError.invalidClientData
    XCTAssertEqual(error.errorDescription, ".invalidClientData")
  }

  func testResolvedUnsupportedResponseType() {
    let error = ResolvedAuthorisationError.unsupportedResponseType("code")
    XCTAssertEqual(error.errorDescription, ".unsupportedResponseType code")
  }

  func testErrorDescription() {
    // .invalidUrl
    let invalidUrlError = FetchError.invalidUrl
    XCTAssertEqual(invalidUrlError.errorDescription, ".invalidUrl")

    // .networkError
    let networkError = NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Network error occurred"])
    let networkFetchError = FetchError.networkError(networkError)
    XCTAssertEqual(networkFetchError.errorDescription, ".networkError Network error occurred")

    // .invalidResponse
    let invalidResponseError = FetchError.invalidResponse
    XCTAssertEqual(invalidResponseError.errorDescription, ".invalidResponse")

    // .decodingError
    let decodingError = NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Decoding error occurred"])
    let decodingFetchError = FetchError.decodingError(decodingError)
    XCTAssertEqual(decodingFetchError.errorDescription, ".decodingError Decoding error occurred")
  }
}

class JOSEErrorTests: XCTestCase {

  func testErrorDescription() {
    XCTAssertEqual(JOSEError.notSupportedRequest.errorDescription, ".notSupportedRequest")
    XCTAssertEqual(JOSEError.invalidPublicKey.errorDescription, ".invalidPublicKey")
    XCTAssertEqual(JOSEError.invalidJWS.errorDescription, ".invalidJWS")
    XCTAssertEqual(JOSEError.invalidSigner.errorDescription, ".invalidSigner")
    XCTAssertEqual(JOSEError.invalidVerifier.errorDescription, ".invalidVerifier")
  }
}

class AuthorizationRequestErrorCodeTest: XCTestCase {

  // MARK: - Client-related errors → invalid_client

  func testUnsupportedClientIdScheme_MapsToInvalidClient() {
    let error: ValidationError = .unsupportedClientIdScheme("unknown")
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidClient)
    XCTAssertEqual(result.rawValue, "invalid_client")
  }

  func testInvalidClientMetadata_MapsToInvalidClient() {
    let error: ValidationError = .invalidClientMetadata
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidClient)
  }

  func testClientIdMismatch_MapsToInvalidClient() {
    let error: ValidationError = .clientIdMismatch("expected", "actual")
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidClient)
  }

  func testMissingClientId_MapsToInvalidClient() {
    let error: ValidationError = .missingClientId
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidClient)
  }

  func testInvalidVerifierAttestationFormat_MapsToInvalidClient() {
    let error: ValidationError = .invalidVerifierAttestationFormat
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidClient)
  }

  // MARK: - Request URI errors → invalid_request_uri

  func testInvalidRequestUri_MapsToInvalidRequestURI() {
    let error: ValidationError = .invalidRequestUri("https://example.com")
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequestURI)
    XCTAssertEqual(result.rawValue, "invalid_request_uri")
  }

  func testInvalidUri_MapsToInvalidRequestURI() {
    let error: ValidationError = .invalidUri
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequestURI)
  }

  func testInvalidRequestUriMethod_MapsToInvalidRequestURIMethod() {
    let error: ValidationError = .invalidRequestUriMethod
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequestURIMethod)
    XCTAssertEqual(result.rawValue, "invalid_request_uri_method")
  }

  // MARK: - Request object errors (JAR) → invalid_request_object

  func testInvalidJwtPayload_MapsToInvalidRequestObject() {
    let error: ValidationError = .invalidJwtPayload
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequestObject)
    XCTAssertEqual(result.rawValue, "invalid_request_object")
  }

  func testUnsupportedAlgorithm_MapsToInvalidRequestObject() {
    let error: ValidationError = .unsupportedAlgorithm("RS256")
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequestObject)
  }

  func testInvalidKey_MapsToInvalidRequestObject() {
    let error: ValidationError = .invalidKey
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequestObject)
  }

  // MARK: - Format errors → vp_formats_not_supported

  func testInvalidFormat_MapsToVpFormatsNotSupported() {
    let error: ValidationError = .invalidFormat
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .vpFormatsNotSupported)
    XCTAssertEqual(result.rawValue, "vp_formats_not_supported")
  }

  // MARK: - Consent errors → access_denied

  func testNegativeConsent_MapsToAccessDenied() {
    let error: ValidationError = .negativeConsent
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .accessDenied)
    XCTAssertEqual(result.rawValue, "access_denied")
  }

  func testUnsupportedConsent_MapsToAccessDenied() {
    let error: ValidationError = .unsupportedConsent
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .accessDenied)
  }

  // MARK: - Non-dispatchable errors → processing_error

  func testNonDispatchable_MapsToProcessingFailure() {
    let error: ValidationError = .nonDispatchable(.invalidRequest)
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .processingFailure)
    XCTAssertEqual(result.rawValue, "processing_error")
  }

  // MARK: - Generic validation errors → invalid_request

  func testInvalidRequest_MapsToInvalidRequest() {
    let error: ValidationError = .invalidRequest
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequest)
    XCTAssertEqual(result.rawValue, "invalid_request")
  }

  func testMissingNonce_MapsToInvalidRequest() {
    let error: ValidationError = .missingNonce
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequest)
  }

  func testMissingResponseType_MapsToInvalidRequest() {
    let error: ValidationError = .missingResponseType
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequest)
  }

  func testValidationErrorGeneric_MapsToInvalidRequest() {
    let error: ValidationError = .validationError("Some validation failed")
    let result = AuthorizationRequestErrorCode.fromError(error)
    XCTAssertEqual(result, .invalidRequest)
  }

  // MARK: - Raw value verification

  func testAllErrorCodesHaveCorrectRawValues() {
    XCTAssertEqual(AuthorizationRequestErrorCode.invalidScope.rawValue, "invalid_scope")
    XCTAssertEqual(AuthorizationRequestErrorCode.invalidRequest.rawValue, "invalid_request")
    XCTAssertEqual(AuthorizationRequestErrorCode.accessDenied.rawValue, "access_denied")
    XCTAssertEqual(AuthorizationRequestErrorCode.invalidClient.rawValue, "invalid_client")
    XCTAssertEqual(AuthorizationRequestErrorCode.vpFormatsNotSupported.rawValue, "vp_formats_not_supported")
    XCTAssertEqual(AuthorizationRequestErrorCode.invalidRequestURIMethod.rawValue, "invalid_request_uri_method")
    XCTAssertEqual(AuthorizationRequestErrorCode.invalidTransactionData.rawValue, "invalid_transaction_data")
    XCTAssertEqual(AuthorizationRequestErrorCode.userCancelled.rawValue, "user_cancelled")
    XCTAssertEqual(AuthorizationRequestErrorCode.invalidRequestURI.rawValue, "invalid_request_uri")
    XCTAssertEqual(AuthorizationRequestErrorCode.invalidRequestObject.rawValue, "invalid_request_object")
    XCTAssertEqual(AuthorizationRequestErrorCode.processingFailure.rawValue, "processing_error")
  }

}

class DispatchOutcomeTests: XCTestCase {

  func testInit() {
    let outcome = DispatchOutcome()
    XCTAssertEqual(outcome, .accepted(redirectURI: nil))
  }

  func testInitFromDecoder_accepted() throws {
    let json = """
    { "accepted": "https://www.example.com" }
    """
    let data = Data(json.utf8)
    let decoder = JSONDecoder()

    let outcome = try decoder.decode(DispatchOutcome.self, from: data)
    XCTAssertEqual(outcome, .accepted(redirectURI: URL(string: "https://www.example.com")))
  }

  func testInitFromDecoder_rejected() throws {
    let json = """
    { "rejected": "reason" }
    """
    let data = Data(json.utf8)
    let decoder = JSONDecoder()

    let outcome = try decoder.decode(DispatchOutcome.self, from: data)
    XCTAssertEqual(outcome, .rejected(reason: "reason"))
  }

  func testInitFromDecoder_invalid() throws {
    let json = """
    { "unknown": "value" }
    """
    let data = Data(json.utf8)
    let decoder = JSONDecoder()

    XCTAssertThrowsError(try decoder.decode(DispatchOutcome.self, from: data))
  }

  func testEncode() throws {
    let outcome = DispatchOutcome.accepted(redirectURI: URL(string: "https://www.example.com"))
    let encoder = JSONEncoder()

    let data = try encoder.encode(outcome)
    let decodedOutcome = try JSONDecoder().decode(DispatchOutcome.self, from: data)

    XCTAssertEqual(decodedOutcome, outcome)
  }
}
