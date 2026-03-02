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

/// An error type representing possible failures when generating a nonce.
public enum NonceError: Error, Equatable {
  /// Indicates that the provided length for generating a nonce is invalid.
  ///
  /// This error occurs when the length specified is less than or equal to zero.
  /// The nonce generator requires a strictly positive integer value for its length.
  case invalidLength(minimum: Int)
  case invalidByteLength(minimum: Int)
  case randomGenerationFailed(OSStatus)
}
