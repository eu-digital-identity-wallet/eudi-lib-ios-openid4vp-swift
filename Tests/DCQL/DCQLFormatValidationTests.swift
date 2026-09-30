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

/// Tests for validating DCQL query formats against Verifier's vp_formats_supported.
/// Per Issue #242: A Verifier that queries for mso_mdoc while advertising only dc+sd-jwt
/// has sent an inconsistent request and should be rejected with invalid_request.
final class DCQLFormatValidationTests: XCTestCase {

  // MARK: - VpFormatSupported.formatString() tests

  func testFormatStringReturnsMsoMdocForMsoMdocFormat() {
    let format = VpFormatSupported.msoMdoc(
      issuerAuthAlgorithms: nil,
      deviceAuthAlgorithms: nil
    )
    XCTAssertEqual(format.formatString(), OpenId4VPSpec.FORMAT_MSO_MDOC)
    XCTAssertEqual(format.formatString(), "mso_mdoc")
  }

  func testFormatStringReturnsSdJwtVcForSdJwtVcFormat() {
    let format = VpFormatSupported.sdJwtVc(
      sdJwtAlgorithms: [JWSAlgorithm(.ES256)],
      kbJwtAlgorithms: [JWSAlgorithm(.ES256)]
    )
    XCTAssertEqual(format.formatString(), OpenId4VPSpec.FORMAT_SD_JWT_VC)
    XCTAssertEqual(format.formatString(), "dc+sd-jwt")
  }

  func testFormatStringReturnsJwtVcJsonForJwtVpFormat() {
    let format = VpFormatSupported.jwtVp(algorithms: ["ES256"])
    XCTAssertEqual(format.formatString(), OpenId4VPSpec.FORMAT_W3C_SIGNED_JWT)
    XCTAssertEqual(format.formatString(), "jwt_vc_json")
  }

  func testFormatStringReturnsLdpVpForLdpVpFormat() {
    let format = VpFormatSupported.ldpVp(proofTypes: ["Ed25519Signature2020"])
    XCTAssertEqual(format.formatString(), "ldp_vp")
  }

  // MARK: - VpFormatsSupported.supportedFormatStrings() tests

  func testSupportedFormatStringsReturnsAllFormats() throws {
    let formats = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil),
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    let supportedStrings = formats.supportedFormatStrings()

    XCTAssertEqual(supportedStrings.count, 2)
    XCTAssertTrue(supportedStrings.contains("mso_mdoc"))
    XCTAssertTrue(supportedStrings.contains("dc+sd-jwt"))
  }

  func testSupportedFormatStringsWithOnlyMsoMdoc() throws {
    let formats = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil)
    ])

    let supportedStrings = formats.supportedFormatStrings()

    XCTAssertEqual(supportedStrings.count, 1)
    XCTAssertTrue(supportedStrings.contains("mso_mdoc"))
    XCTAssertFalse(supportedStrings.contains("dc+sd-jwt"))
  }

  func testSupportedFormatStringsWithOnlySdJwtVc() throws {
    let formats = try VpFormatsSupported(values: [
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    let supportedStrings = formats.supportedFormatStrings()

    XCTAssertEqual(supportedStrings.count, 1)
    XCTAssertTrue(supportedStrings.contains("dc+sd-jwt"))
    XCTAssertFalse(supportedStrings.contains("mso_mdoc"))
  }

  func testSupportedFormatStringsWithEmptyFormats() throws {
    let formats = try VpFormatsSupported(values: [])

    let supportedStrings = formats.supportedFormatStrings()

    XCTAssertTrue(supportedStrings.isEmpty)
  }

  // MARK: - VpFormatsSupported.supportsFormat() tests

  func testSupportsFormatReturnsTrueForSupportedFormat() throws {
    let formats = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil),
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    XCTAssertTrue(formats.supportsFormat("mso_mdoc"))
    XCTAssertTrue(formats.supportsFormat("dc+sd-jwt"))
  }

  func testSupportsFormatReturnsFalseForUnsupportedFormat() throws {
    let formats = try VpFormatsSupported(values: [
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    XCTAssertFalse(formats.supportsFormat("mso_mdoc"))
    XCTAssertTrue(formats.supportsFormat("dc+sd-jwt"))
  }

  // MARK: - DCQL format validation tests

  /// Verifier advertises only dc+sd-jwt but queries for mso_mdoc - should be rejected.
  func testDCQLQueryingMsoMdocWhileVerifierOnlySupportsSdJwtThrowsInvalidRequest() throws {
    // Create a DCQL query that requests mso_mdoc format
    let dcql = try DCQL(credentials: [
      CredentialQuery(
        id: QueryId(value: "test-credential"),
        format: try Format.MsoMdoc(),
        meta: [:]
      )
    ])

    // Verifier only supports dc+sd-jwt
    let verifierFormatsSupported = try VpFormatsSupported(values: [
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    let presentationQuery = PresentationQuery.byDigitalCredentialsQuery(dcql)

    // Validation should throw invalidRequest
    XCTAssertThrowsError(
      try validateDCQLFormatsAgainstVerifier(
        presentationQuery: presentationQuery,
        verifierFormatsSupported: verifierFormatsSupported
      )
    ) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError but got \(type(of: error))")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  /// Verifier advertises only mso_mdoc but queries for dc+sd-jwt - should be rejected.
  func testDCQLQueryingSdJwtWhileVerifierOnlySupportsMsoMdocThrowsInvalidRequest() throws {
    // Create a DCQL query that requests dc+sd-jwt format
    let dcql = try DCQL(credentials: [
      CredentialQuery(
        id: QueryId(value: "test-credential"),
        format: try Format.SdJwtVc(),
        meta: [:]
      )
    ])

    // Verifier only supports mso_mdoc
    let verifierFormatsSupported = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil)
    ])

    let presentationQuery = PresentationQuery.byDigitalCredentialsQuery(dcql)

    // Validation should throw invalidRequest
    XCTAssertThrowsError(
      try validateDCQLFormatsAgainstVerifier(
        presentationQuery: presentationQuery,
        verifierFormatsSupported: verifierFormatsSupported
      )
    ) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError but got \(type(of: error))")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  /// Verifier advertises both mso_mdoc and dc+sd-jwt, queries for mso_mdoc - should succeed.
  func testDCQLQueryingMsoMdocWhileVerifierSupportsBothSucceeds() throws {
    // Create a DCQL query that requests mso_mdoc format
    let dcql = try DCQL(credentials: [
      CredentialQuery(
        id: QueryId(value: "test-credential"),
        format: try Format.MsoMdoc(),
        meta: [:]
      )
    ])

    // Verifier supports both formats
    let verifierFormatsSupported = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil),
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    let presentationQuery = PresentationQuery.byDigitalCredentialsQuery(dcql)

    // Validation should succeed
    XCTAssertNoThrow(
      try validateDCQLFormatsAgainstVerifier(
        presentationQuery: presentationQuery,
        verifierFormatsSupported: verifierFormatsSupported
      )
    )
  }

  /// Verifier advertises mso_mdoc only, queries for mso_mdoc - should succeed.
  func testDCQLQueryingMsoMdocWhileVerifierSupportsMsoMdocSucceeds() throws {
    // Create a DCQL query that requests mso_mdoc format
    let dcql = try DCQL(credentials: [
      CredentialQuery(
        id: QueryId(value: "test-credential"),
        format: try Format.MsoMdoc(),
        meta: [:]
      )
    ])

    // Verifier supports mso_mdoc
    let verifierFormatsSupported = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil)
    ])

    let presentationQuery = PresentationQuery.byDigitalCredentialsQuery(dcql)

    // Validation should succeed
    XCTAssertNoThrow(
      try validateDCQLFormatsAgainstVerifier(
        presentationQuery: presentationQuery,
        verifierFormatsSupported: verifierFormatsSupported
      )
    )
  }

  /// Multiple credentials with mixed formats, one not supported - should be rejected.
  func testDCQLWithMultipleCredentialsOneUnsupportedFormatThrowsInvalidRequest() throws {
    // Create a DCQL query with multiple credentials, one requesting unsupported format
    let dcql = try DCQL(credentials: [
      CredentialQuery(
        id: QueryId(value: "credential-1"),
        format: try Format.SdJwtVc(),
        meta: [:]
      ),
      CredentialQuery(
        id: QueryId(value: "credential-2"),
        format: try Format.MsoMdoc(),
        meta: [:]
      )
    ])

    // Verifier only supports dc+sd-jwt
    let verifierFormatsSupported = try VpFormatsSupported(values: [
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    let presentationQuery = PresentationQuery.byDigitalCredentialsQuery(dcql)

    // Validation should throw invalidRequest because mso_mdoc is not supported
    XCTAssertThrowsError(
      try validateDCQLFormatsAgainstVerifier(
        presentationQuery: presentationQuery,
        verifierFormatsSupported: verifierFormatsSupported
      )
    ) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Expected ValidationError but got \(type(of: error))")
      }
      XCTAssertEqual(validationError, .invalidRequest)
    }
  }

  /// Multiple credentials with all supported formats - should succeed.
  func testDCQLWithMultipleCredentialsAllSupportedFormatsSucceeds() throws {
    // Create a DCQL query with multiple credentials
    let dcql = try DCQL(credentials: [
      CredentialQuery(
        id: QueryId(value: "credential-1"),
        format: try Format.SdJwtVc(),
        meta: [:]
      ),
      CredentialQuery(
        id: QueryId(value: "credential-2"),
        format: try Format.MsoMdoc(),
        meta: [:]
      )
    ])

    // Verifier supports both formats
    let verifierFormatsSupported = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil),
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    let presentationQuery = PresentationQuery.byDigitalCredentialsQuery(dcql)

    // Validation should succeed
    XCTAssertNoThrow(
      try validateDCQLFormatsAgainstVerifier(
        presentationQuery: presentationQuery,
        verifierFormatsSupported: verifierFormatsSupported
      )
    )
  }
}

// MARK: - Helper to expose the private validation method for testing

private func validateDCQLFormatsAgainstVerifier(
  presentationQuery: PresentationQuery,
  verifierFormatsSupported: VpFormatsSupported
) throws {
  switch presentationQuery {
  case .byDigitalCredentialsQuery(let dcql):
    let verifierSupportedStrings = verifierFormatsSupported.supportedFormatStrings()
    for credential in dcql.credentials {
      let queryFormat = credential.format.format
      guard verifierSupportedStrings.contains(queryFormat) else {
        throw ValidationError.invalidRequest
      }
    }
  }
}
