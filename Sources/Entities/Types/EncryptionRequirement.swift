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
@preconcurrency import JOSESwift

public struct EncryptionRequirementSpecification: Equatable, Sendable {
  public let supportedEncryptionAlgorithm: KeyManagementAlgorithm
  public let supportedEncryptionMethod: ContentEncryptionAlgorithm
  public let ephemeralEncryptionKeyCurve: ECCurveType

  public init(
    supportedEncryptionAlgorithm: KeyManagementAlgorithm = .ECDH_ES,
    supportedEncryptionMethod: ContentEncryptionAlgorithm = .A128CBCHS256,
    ephemeralEncryptionKeyCurve: ECCurveType = .P256
  ) throws {
    self.supportedEncryptionAlgorithm = supportedEncryptionAlgorithm
    self.supportedEncryptionMethod = supportedEncryptionMethod
    self.ephemeralEncryptionKeyCurve = ephemeralEncryptionKeyCurve

    if supportedEncryptionAlgorithm != .ECDH_ES {
      throw ValidationError.validationError("Unsupported encryption algorithm \(supportedEncryptionAlgorithm.rawValue)")
    }

    if supportedEncryptionMethod != .A128GCM {
      throw ValidationError.validationError("Unsupported encryption method \(supportedEncryptionMethod.rawValue)")
    }

    if ephemeralEncryptionKeyCurve != .P256 {
      throw ValidationError.validationError("Unsupported ephemeral encryption key curve \(ephemeralEncryptionKeyCurve.rawValue)")
    }
  }
}

public enum EncryptionRequirement: Equatable, Sendable {
  /**
    * Encryption is not required.
    */
  case notRequired

  /**
    * Encryption is required.
    *
    * @property EncryptionRequirementSpecification: encryption algorithms supported by the Wallet, only asymmetric
    * KeyManagementAlgorithm are supported, supportedEncryptionMethods encryption methods supported by the Wallet,
    * the [ECCurveType] to use for generating the ephemeral encryption key
    */
  case required(
    encryptionRequirementSpecification: EncryptionRequirementSpecification
  )

  /**
    * Encryption is supported but not required.
    *
    * The Wallet generates an ephemeral key and advertises it in its metadata, exactly as
    * for `required`. A Verifier that encrypts the Request Object gets it decrypted; a
    * Verifier that only signs it is accepted as well. This is the OpenID4VP 1.0 position:
    * encrypting the Request Object is the Verifier's choice.
    */
  case supported(
    encryptionRequirementSpecification: EncryptionRequirementSpecification
  )

  public var isNotRequired: Bool {
    return switch self {
    case .notRequired: true
    case .required, .supported: false
    }
  }

  /// Whether an unencrypted (signed-only) Request Object must be rejected.
  public var isRequired: Bool {
    return switch self {
    case .required: true
    case .notRequired, .supported: false
    }
  }

  /// The specification the Wallet advertises, when it offers encryption at all.
  public var specification: EncryptionRequirementSpecification? {
    return switch self {
    case .notRequired: nil
    case .required(let spec), .supported(let spec): spec
    }
  }
}
