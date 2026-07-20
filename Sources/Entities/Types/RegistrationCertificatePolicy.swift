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
/// Per ETSI TS 119 475 V1.2.1, the WRPRC conveys the WRP's declared use cases
/// and data access policies to both the EUDIW and the end user.
public struct RegistrationCertificatePolicy: @unchecked Sendable {
  /// Trust validator for the WRPRC signing certificate.
  /// Implements the logic to secure trust to the signing certificate of the WRPRC.
  public let certificateTrust: CertificateTrust

  /// Policy validation function that evaluates the WRPRC against the request context.
  /// - Parameters:
  ///   - wrpac: The WRP Authentication Certificate
  ///   - wrprc: The WRP Registration Certificate (as a signed JWT)
  ///   - dcql: The DCQL (Digital Credentials Query Language) from the request
  /// - Returns: A list of policy violations (errors and/or warnings)
  public let validatePolicy: @Sendable (
    _ wrpac: Certificate,
    _ wrprc: WRPRegistrationCertificate,
    _ dcql: DCQL
  ) async -> [PolicyViolation]

  public init(
    certificateTrust: @escaping CertificateTrust,
    validatePolicy: @escaping @Sendable (
      _ wrpac: Certificate,
      _ wrprc: WRPRegistrationCertificate,
      _ dcql: DCQL
    ) async -> [PolicyViolation]
  ) {
    self.certificateTrust = certificateTrust
    self.validatePolicy = validatePolicy
  }
}

// MARK: - Default Policy

public extension RegistrationCertificatePolicy {
  /// Creates a policy that only validates certificate trust without additional policy checks.
  /// - Parameter certificateTrust: The trust validator for the WRPRC signing certificate
  /// - Returns: A policy that returns no violations if the certificate is trusted
  static func trustOnly(
    certificateTrust: @escaping CertificateTrust
  ) -> RegistrationCertificatePolicy {
    RegistrationCertificatePolicy(
      certificateTrust: certificateTrust,
      validatePolicy: { _, _, _ in [] }
    )
  }
}
