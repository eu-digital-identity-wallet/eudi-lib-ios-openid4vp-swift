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

/// Tests for `RequestAuthorizer` with a policy and a request that has no WRPRC.
final class RequestAuthorizerMissingCertificateTests: XCTestCase {

  func testDefaultPolicyRejectsMissingCertificate() async throws {
    let policy = RegistrationCertificatePolicy(
      validatePolicy: { _, _, _ in .granted() }
    )
    let authorizer = RequestAuthorizer(policy: policy)

    do {
      _ = try await authorizer.authorize(resolvedRequest: try await resolvedRequestWithoutCertificate())
      XCTFail("Expected authorization to fail when no WRPRC is available")
    } catch let error as ValidationError {
      guard case .authorizationPolicyNotMet(let violation) = error else {
        return XCTFail("Unexpected error \(error)")
      }
      XCTAssertTrue(violation.violation.contains("WRPRC"))
    }
  }

  func testPolicyCanAcceptMissingCertificateWithWarnings() async throws {
    let warnings = ["": [PolicyViolation("verifier_info has no WRPRC")]]
    let policy = RegistrationCertificatePolicy(
      validatePolicy: { _, _, _ in
        XCTFail("validatePolicy must not run without a WRPRC")
        return .granted()
      },
      missingCertificate: { .granted(warnings: warnings) }
    )
    let authorizer = RequestAuthorizer(policy: policy)

    let result = try await authorizer.authorize(resolvedRequest: try await resolvedRequestWithoutCertificate())

    XCTAssertNil(result.registrationCertificate)
    XCTAssertEqual(result.warnings, warnings)
  }

  func testPolicyCanRejectMissingCertificateWithOwnReason() async throws {
    let policy = RegistrationCertificatePolicy(
      validatePolicy: { _, _, _ in .granted() },
      missingCertificate: { .notGranted(error: PolicyViolation("registration required")) }
    )
    let authorizer = RequestAuthorizer(policy: policy)

    do {
      _ = try await authorizer.authorize(resolvedRequest: try await resolvedRequestWithoutCertificate())
      XCTFail("Expected authorization to fail")
    } catch let error as ValidationError {
      guard case .authorizationPolicyNotMet(let violation) = error else {
        return XCTFail("Unexpected error \(error)")
      }
      XCTAssertEqual(violation.violation, "registration required")
    }
  }

  private func resolvedRequestWithoutCertificate() async throws -> ResolvedRequestData {
    let validator = ClientMetaDataValidator()
    let metaData = try await validator.validate(
      clientMetaData: TestsConstants.testClientMetaData(),
      responseMode: nil,
      responseEncryptionConfiguration: .unsupported
    )
    return .init(
      request: .init(
        presentationQuery: .byDigitalCredentialsQuery(
          try .init(credentials: [
            .init(
              id: .init(value: "query_0"),
              format: .init(format: "sd-jwt"),
              meta: [:]
            )
          ])
        ),
        clientMetaData: metaData,
        client: .x509SanDns(
          clientId: "test-client",
          certificate: TestsConstants.testLeafCertificate
        ),
        nonce: TestsConstants.testNonce,
        responseMode: TestsConstants.testResponseMode,
        state: TestsConstants.generateRandomBase64String(),
        vpFormatsSupported: try .default(),
        responseEncryptionSpecification: nil,
        verifierInfo: nil,
        registrationCertificate: nil
      )
    )
  }
}
