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

/// Configuration for WRP Registration Certificate (WRPRC) policy validation.
public struct RegistrationCertificatePolicy: @unchecked Sendable {
  /// Policy validation function that evaluates the WRPRC against the request context.
  /// - Parameters:
  ///   - wrpac: The WRP Authentication Certificate
  ///   - wrprc: The WRP Registration Certificate (raw serialized value as delivered in `verifier_info`)
  ///   - dcql: The DCQL (Digital Credentials Query Language) from the request
  /// - Returns: `Authorization.granted(warnings:)` to accept the request (any warnings are
  ///   forwarded to the caller), or `Authorization.notGranted(error:)` to reject it — in
  ///   which case the resolver fails with `ValidationError.authorizationPolicyNotMet`.
  public let validatePolicy: @Sendable (
    _ wrpac: Certificate,
    _ wrprc: String,
    _ dcql: DCQL
  ) async -> Authorization

  /// The outcome for a request that has no WRPRC in `verifier_info`.
  /// Return `.granted(warnings:)` to accept the request. Return `.notGranted(error:)`
  /// to reject it. The default rejects the request.
  public let missingCertificate: @Sendable () async -> Authorization

  public init(
    validatePolicy: @escaping @Sendable (
      _ wrpac: Certificate,
      _ wrprc: String,
      _ dcql: DCQL
    ) async -> Authorization,
    missingCertificate: @escaping @Sendable () async -> Authorization = {
      .notGranted(error: PolicyViolation("WRPRC policy is configured but no WRPRC found in verifier_info"))
    }
  ) {
    self.validatePolicy = validatePolicy
    self.missingCertificate = missingCertificate
  }
}
