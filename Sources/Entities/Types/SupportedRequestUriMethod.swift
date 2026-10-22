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

public struct PostOptions: Sendable {
  public let includeWalletMetadata: Bool
  public let useWalletNonce: NonceOption
  public let jarEncryption: EncryptionRequirement

  public init(
    includeWalletMetadata: Bool = false,
    useWalletNonce: NonceOption = .doNotUse,
    jarEncryption: EncryptionRequirement = .notRequired
  ) throws {
    self.includeWalletMetadata = includeWalletMetadata
    self.useWalletNonce = useWalletNonce
    self.jarEncryption = jarEncryption

    if jarEncryption != .notRequired && includeWalletMetadata == false {
      throw ValidationError.validationError(
        "Wallet Metadata must be included when JAR encryption is required"
      )
    }
  }
}

public enum SupportedRequestUriMethod: Sendable {
  case get
  case post(
    postOptions: PostOptions
  )
  case both(
    postOptions: PostOptions
  )

  public init?(
    method: String,
    includeWalletMetadata: Bool = true,
    useWalletNonce: NonceOption = .use(byteLength: 32)
  ) throws {
    switch method.uppercased() {
    case "GET":
      self = .get
    case "POST":
      guard let options: PostOptions = try? .init(
        includeWalletMetadata: includeWalletMetadata,
        useWalletNonce: useWalletNonce
      ) else {
        return nil
      }
      self = .post(
        postOptions: options
      )
    default:
      return nil
    }
  }

  /// Method to check if `get` is supported
  public func isGetSupported() -> Bool {
    switch self {
    case .get, .both:
      return true
    case .post:
      return false
    }
  }

  /// Method to check if `post` is supported
  public func isPostSupported() -> PostOptions? {
    switch self {
    case .both(let postOptions):
      return postOptions
    case .post(let postOptions):
      return postOptions
    case .get:
      return nil
    }
  }

  public static let encryptionOption: SupportedRequestUriMethod = .both(
    postOptions: try! PostOptions(
      includeWalletMetadata: true,
      useWalletNonce: NonceOption.use(byteLength: 32),
      jarEncryption: .required(
        encryptionRequirementSpecification: .init(
          supportedEncryptionAlgorithm: .ECDH_ES,
          supportedEncryptionMethod: .A128GCM,
          ephemeralEncryptionKeyCurve: .P256
        )
      )
    )
  )

  /// POST with wallet metadata and nonce; the Wallet offers Request Object encryption
  /// but also accepts a signed-only Request Object.
  public static let encryptionSupportedOption: SupportedRequestUriMethod = .both(
    postOptions: try! PostOptions(
      includeWalletMetadata: true,
      useWalletNonce: NonceOption.use(byteLength: 32),
      jarEncryption: .supported(
        encryptionRequirementSpecification: .init(
          supportedEncryptionAlgorithm: .ECDH_ES,
          supportedEncryptionMethod: .A128GCM,
          ephemeralEncryptionKeyCurve: .P256
        )
      )
    )
  )

  public static let noEncryptionOption: SupportedRequestUriMethod = .both(
    postOptions: try! PostOptions(
      includeWalletMetadata: true,
      useWalletNonce: NonceOption.use(byteLength: 32),
      jarEncryption: .notRequired
    )
  )
}
