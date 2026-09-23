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

public protocol DIDPublicKeyLookupAgentType: Sendable {
  /// Resolves the public key from the specified DID URL.
  /// The implementation should use the full DID URL (including fragment) to identify
  /// the specific verification method to use for key resolution.
  /// - Parameter didUrl: The full DID URL including the fragment identifying the verification method
  /// - Returns: The resolved public key, or nil if resolution fails
  func resolveKey(from didUrl: AbsoluteDIDUrl) async -> SecKey?
}
