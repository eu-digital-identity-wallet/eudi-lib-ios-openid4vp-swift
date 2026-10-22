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

/// Result of request authorization: the policy accepted the request, optionally
/// returning warnings the caller should surface.
public struct AuthorizationResult: Sendable {
  /// Warnings returned by the policy alongside a `granted` outcome.
  public let warnings: [String: [PolicyViolation]]

  /// The WRPRC raw value if present.
  public let registrationCertificate: String?

  public init(
    warnings: [String: [PolicyViolation]] = [:],
    registrationCertificate: String? = nil
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
/// 2. A pre-validated WRPRC (raw `String`) is available in the resolved request
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
  /// - Parameter resolvedRequest: The resolved request data to authorize
  /// - Returns: `AuthorizationResult` carrying any warnings from a `.granted` outcome.
  /// - Throws: `ValidationError.authorizationPolicyNotMet` if the policy returns `.notGranted`,
  ///   or if the request has no WRPRC and `policy.missingCertificate` rejects it.
  public func authorize(resolvedRequest: ResolvedRequestData) async throws -> AuthorizationResult {
    // If no policy is configured, skip authorization
    guard let policy = policy else {
      return AuthorizationResult()
    }

    guard let wrprc = resolvedRequest.registrationCertificate else {
      switch await policy.missingCertificate() {
      case .granted(let warnings):
        return AuthorizationResult(warnings: warnings, registrationCertificate: nil)
      case .notGranted(let error):
        throw ValidationError.authorizationPolicyNotMet(error)
      }
    }

    guard let wrpac = extractWRPAC(from: resolvedRequest.client) else {
      throw ValidationError.validationError(
        "WRPRC policy is configured but client does not have an authentication certificate"
      )
    }

    guard let dcql = resolvedRequest.dcql else {
      throw ValidationError.validationError("DCQL is required for WRPRC policy validation")
    }

    switch await policy.validatePolicy(wrpac, wrprc, dcql) {
    case .granted(let warnings):
      return AuthorizationResult(
        warnings: warnings,
        registrationCertificate: wrprc
      )
    case .notGranted(let error):
      throw ValidationError.authorizationPolicyNotMet(error)
    }
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
