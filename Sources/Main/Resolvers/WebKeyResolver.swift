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

public protocol WebKeyResolverType {

  /// The input type for resolving web keys.
  associatedtype InputType: Sendable

  /// The output type for resolved web keys. Must be Codable and Equatable.
  associatedtype OutputType: Codable, Equatable, Sendable

  /// The error type for resolving web keys. Must conform to the Error protocol.
  associatedtype ErrorType: Error

  /// Resolves web keys  asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching web keys.
  ///   - source: The input source for resolving web keys.
  /// - Returns: An asynchronous result containing the resolved web keys or an error.
  func resolve(
    fetcher: Fetcher<OutputType>,
    source: InputType?
  ) async -> Result<OutputType?, ErrorType>
}

public actor WebKeyResolver: WebKeyResolverType {
  /// Resolves web keys asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching web keys. Default value is Fetcher<WebKeySet>().
  ///   - source: The input source for resolving web keys.
  /// - Returns: An asynchronous result containing the resolved web keys or an error of type ResolvingError.
  public func resolve(
    fetcher: Fetcher<WebKeySet> = Fetcher(),
    source: WebKeySource?
  ) async -> Result<WebKeySet?, ResolvingError> {
    guard let source = source else { return .success(nil) }
    switch source {
    case .passByValue(let webKeys):
      return .success(webKeys)
    }
  }
}
