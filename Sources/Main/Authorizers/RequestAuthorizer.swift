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
import X509

/// Result of request authorization containing any policy warnings.
public struct AuthorizationResult: Sendable {
  /// Policy warnings that do not stop processing.
  /// Callers should handle these appropriately (e.g., display to user).
  public let warnings: [PolicyViolationWarning]

  /// The validated WRPRC if present and valid.
  public let registrationCertificate: WRPRegistrationCertificate?

  public init(
    warnings: [PolicyViolationWarning] = [],
    registrationCertificate: WRPRegistrationCertificate? = nil
  ) {
    self.warnings = warnings
    self.registrationCertificate = registrationCertificate
  }
}

/// Authorizes requests by validating WRP Registration Certificate (WRPRC) policies.
/// Per ETSI TS 119 475 V1.2.1, the WRPRC conveys the WRP's declared use cases
/// and data access policies within the EUDIW ecosystem.
///
/// This component performs **policy validation only**. The structural validation,
/// certificate trust verification, and signature verification are performed earlier
/// during request authentication (in `RequestAuthenticator`).
///
/// Authorization is only performed if:
/// 1. A `RegistrationCertificatePolicy` is configured, AND
/// 2. A pre-validated `WRPRegistrationCertificate` is available in the resolved request
///
/// If no policy is configured, authorization is skipped and an empty result is returned.
public actor RequestAuthorizer {
  private let policy: RegistrationCertificatePolicy?

  /// Initializes the authorizer with an optional policy.
  /// - Parameter policy: The registration certificate policy. If nil, authorization is skipped.
  public init(policy: RegistrationCertificatePolicy? = nil) {
    self.policy = policy
  }

  /// Authorizes a resolved request by applying WRPRC policy validation.
  ///
  /// The WRPRC has already been validated (structure, trust, signature) during
  /// request authentication. This method only applies the policy validation
  /// comparing the WRPRC permissions against the DCQL request.
  ///
  /// - Parameter resolvedRequest: The resolved request data to authorize
  /// - Returns: Authorization result containing any warnings
  /// - Throws: `ValidationError` if policy validation fails with errors
  public func authorize(resolvedRequest: ResolvedRequestData) async throws -> AuthorizationResult {
    // If no policy is configured, skip authorization
    guard let policy = policy else {
      return AuthorizationResult()
    }

    // Get the pre-validated WRPRC from the resolved request
    // This was validated during request authentication
    guard let wrprc = resolvedRequest.registrationCertificate else {
      // If policy is configured but no WRPRC was validated,
      // the request authentication should have failed.
      // This is a defensive check.
      throw ValidationError.validationError(
        "WRPRC policy is configured but no validated WRPRC is available"
      )
    }

    // Extract WRPAC (authentication certificate) from client
    guard let wrpac = extractWRPAC(from: resolvedRequest.client) else {
      throw ValidationError.validationError(
        "WRPRC policy is configured but client does not have an authentication certificate"
      )
    }

    // Get DCQL for policy validation
    guard let dcql = resolvedRequest.dcql else {
      throw ValidationError.validationError("DCQL is required for WRPRC policy validation")
    }

    // Apply policy validation - compare WRPRC permissions against DCQL request
    let violations = await policy.validatePolicy(wrpac, wrprc, dcql)

    // Check for error-level violations
    if violations.hasErrors {
      let errorMessages = violations.errors.map { "\($0.code): \($0.message)" }.joined(separator: "; ")
      throw ValidationError.validationError("WRPRC policy violations: \(errorMessages)")
    }

    return AuthorizationResult(
      warnings: violations.warnings,
      registrationCertificate: wrprc
    )
  }

  // MARK: - Private Methods

  /// Extracts the WRPAC (authentication certificate) from the client.
  private func extractWRPAC(from client: Client) -> Certificate? {
    switch client {
    case .x509Hash(_, let authenticationCertificate):
      return authenticationCertificate
    case .x509SanDns(_, let certificate):
      return certificate
    default:
      return nil
    }
  }
}
