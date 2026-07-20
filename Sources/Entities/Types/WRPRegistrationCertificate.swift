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
import JOSESwift
@preconcurrency import SwiftyJSON

/// WRP Registration Certificate (WRPRC) per ETSI TS 119 475.
/// Communicates declared use cases and data policies within the EUDIW ecosystem.
public struct WRPRegistrationCertificate: Sendable, Equatable {
  /// The X.509 certificate containing the registration information
  public let certificate: Certificate

  /// The raw certificate chain data in Base64 encoding
  public let certificateChain: [Base64Certificate]

  /// The raw JWT string containing the WRPRC attestation
  public let jwt: String

  public init(
    certificate: Certificate,
    certificateChain: [Base64Certificate],
    jwt: String
  ) {
    self.certificate = certificate
    self.certificateChain = certificateChain
    self.jwt = jwt
  }

  /// Extracts WRPRC from an array of VerifierInfo objects.
  /// The WRPRC is expected to be a JWT in the `data` field with the certificate chain in the x5c header.
  /// Returns nil if no WRPRC is present in the verifier info.
  ///
  /// Per OpenID4VP spec: "If the Wallet uses information from verifier_info,
  /// the Wallet MUST validate the signature and ensure binding."
  /// Signature validation is performed by the caller using registrationCertificateTrust.
  public static func from(verifierInfo: [VerifierInfo]?) throws -> WRPRegistrationCertificate? {
    guard let verifierInfo = verifierInfo else { return nil }

    // Find the WRPRC entry in verifier_info
    guard let wrprcInfo = verifierInfo.first(where: {
      $0.format == OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC
    }) else {
      return nil
    }

    // The data field contains a JWT string per OpenID4VP spec
    guard let jwtString = wrprcInfo.data.string else {
      throw ValidationError.validationError("WRPRC verifier_info data must be a JWT string")
    }

    // Parse the JWT to extract the x5c certificate chain from the header
    guard let jws = try? JWS(compactSerialization: jwtString) else {
      throw ValidationError.validationError("Invalid WRPRC JWT format")
    }

    guard let certificateChain: [String] = jws.header.x5c, !certificateChain.isEmpty else {
      throw ValidationError.validationError("WRPRC JWT header missing x5c certificate chain")
    }

    // Parse the leaf certificate
    let certificates = parseCertificates(from: certificateChain)
    guard let leafCertificate = certificates.first else {
      throw ValidationError.validationError("Failed to parse WRPRC certificate from x5c")
    }

    return WRPRegistrationCertificate(
      certificate: leafCertificate,
      certificateChain: certificateChain,
      jwt: jwtString
    )
  }
}
