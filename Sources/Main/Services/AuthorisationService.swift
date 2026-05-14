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

/// A protocol for an authorization service.
public protocol AuthorisationServiceType: Sendable {
  /// Posts a response and returns a generic result.
  func formPost<T: Codable & Sendable>(
    poster: Posting,
    response: AuthorizationResponse
  ) async throws -> T
  
  /// Posts a response and returns a success boolean.
  func formCheck(
    poster: Posting,
    response: AuthorizationResponse
  ) async throws -> (
    String,
    Bool
  )
}

/// An implementation of the `AuthorisationServiceType` protocol.
public actor AuthorisationService: AuthorisationServiceType {

  var joseResponse: String?

  public init() { }

  /// Posts a response and returns a generic result.
  public func formPost<T: Codable & Sendable>(
    poster: Posting,
    response: AuthorizationResponse
  ) async throws -> T {
    switch response {
    case .directPost(let url, let data):
      let post = VerifierFormPost(
        additionalHeaders: ["Content-Type": ContentType.form.rawValue],
        url: url,
        formData: try data.toDictionary()
      )

      let result: Result<T, PostError> = await poster.post(
        request: post.urlRequest
      )
      return try result.get()
    default: throw AuthorizationError.invalidResponseMode
    }
  }

  /// Posts a response and returns a success boolean.
  public func formCheck(
    poster: Posting,
    response: AuthorizationResponse
  ) async throws -> (String, Bool) {
    switch response {
    case .directPost(let url, let data):
      let payload = setupDirectPostPayload(
        payload: data,
        key: Constants.presentationSubmissionKey,
        dictionary: try? data.toDictionary()
      )

      let post = VerifierFormPost(
        additionalHeaders: ["Content-Type": ContentType.form.rawValue],
        url: url,
        formData: payload
      )

      let result: Result<(String, Bool), PostError> = await poster.check(
        key: "redirect_uri",
        request: post.urlRequest
      )
      return try result.get()

    case .directPostJwt(let url, let data, let responseEncryptionSpecification):
      // Handle invalid request case
      if case .invalidRequest(let error, _, let state, _) = data {
        let payload: [String: Any] = [
          "error": AuthorizationRequestErrorCode.fromError(error).rawValue,
          "error_description": error.localizedDescription,
          "state": state as Any
        ].compactMapValues { $0 }

        let post = VerifierFormPost(
          additionalHeaders: ["Content-Type": ContentType.form.rawValue],
          url: url,
          formData: payload
        )

        let result: Result<(String, Bool), PostError> = await poster.check(
          key: "redirect_uri",
          request: post.urlRequest
        )
        return try result.get()
      }

      let encryptor: ResponseEncryptor = .init()
      let joseResponse = try await encryptor.encryptResponse(
        responseEncryptionSpecification: responseEncryptionSpecification,
        data: data
      )

      let post = VerifierFormPost(
        additionalHeaders: [
          "Content-Type": ContentType.form.rawValue
        ],
        url: url,
        formData: [
          "response": joseResponse
        ]
      )

      self.joseResponse = joseResponse

      let result: Result<(String, Bool), PostError> = await poster.check(
        key: "redirect_uri",
        request: post.urlRequest
      )
      return try result.get()

    case .query, .queryJwt, .fragment, .fragmentJwt, .invalidRequest:
      throw AuthorizationError.invalidResponseMode
    }
  }
}

private extension AuthorisationService {
  func setupDirectPostPayload(
    payload: AuthorizationResponsePayload,
    key: String,
    dictionary: [String: Any]?
  ) -> [String: Any] {

    switch payload {
    case .invalidRequest(let error, _, let state, _):
      return [
        "error": AuthorizationRequestErrorCode.fromError(error).rawValue,
        "error_description": error.localizedDescription,
        "state": state as Any
      ].compactMapValues { $0 }

    default: break
    }

    guard let dictionary = dictionary else { return [:] }

    let value = dictionary[key] as? [String: Any]
    let presentationSubmission: String? = value?.toJSONString() ?? ""

    return dictionary
      .filter { $0.key != Constants.presentationSubmissionKey }
      .merging([Constants.presentationSubmissionKey: presentationSubmission as Any], uniquingKeysWith: { _, new in new })
      .compactMapValues { $0 }
      .filter { _, value in
        if let value = value as? String {
          return !value.isEmpty
        }
        return true
      }
  }
}
