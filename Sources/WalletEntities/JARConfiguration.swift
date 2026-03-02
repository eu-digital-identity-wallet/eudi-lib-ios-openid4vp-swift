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
import JOSESwift

public struct JARConfiguration: Sendable {
  public let supportedAlgorithms: [JWSAlgorithm]
  public let supportedRequestUriMethods: SupportedRequestUriMethod

  /// Initializer with validation to ensure supportedAlgorithms is not empty
  public init(
    supportedAlgorithms: [JWSAlgorithm],
    supportedRequestUriMethods: SupportedRequestUriMethod
  ) {
    precondition(!supportedAlgorithms.isEmpty, "JAR signing algorithms cannot be empty")

    self.supportedAlgorithms = supportedAlgorithms
    self.supportedRequestUriMethods = supportedRequestUriMethods
  }

  /// Default JAR configuration with trusted algorithms ES256
  public static let encryptionOption: JARConfiguration = .init(
    supportedAlgorithms: [
      JWSAlgorithm(
        .ES256
      )
    ],
    supportedRequestUriMethods: .encryptionOption
  )

  public static let noEncryptionOption: JARConfiguration = .init(
    supportedAlgorithms: [
      JWSAlgorithm(
        .ES256
      )
    ],
    supportedRequestUriMethods: .noEncryptionOption
  )

  public var supportedEncryption: EncryptionRequirementSpecification? {
    return switch supportedRequestUriMethods {
    case .get: nil
    case .post(let postOptions), .both(let postOptions):
      switch postOptions.jarEncryption {
      case .notRequired: nil
      case .required(let spec): spec
      }
    }
  }
  
  public var nonceOption: NonceOption {
    switch supportedRequestUriMethods {
    case .get:
      return .doNotUse
    case .post(let options):
      return options.useWalletNonce
    case .both(let options):
      return options.useWalletNonce
    }
  }
}
