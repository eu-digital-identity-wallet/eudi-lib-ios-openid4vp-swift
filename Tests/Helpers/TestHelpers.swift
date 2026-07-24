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

@testable import OpenID4VP

/// Test helper utilities for fetching test data from remote endpoints.
enum TestHelpers {

  /// Response structure for intended uses endpoint.
  struct IntendedUsesResponse: Decodable {
    let intendedUses: [IntendedUse]

    enum CodingKeys: String, CodingKey {
      case intendedUses = "intended_uses"
    }
  }

  /// An intended use entry from the verifier backend.
  struct IntendedUse: Decodable {
    let intendedUseId: String
    let description: String
    let registrationCertificate: String

    enum CodingKeys: String, CodingKey {
      case intendedUseId = "intended_use_id"
      case description
      case registrationCertificate = "registration_certificate"
    }
  }

  /// Fetches intended uses from the EUDI verifier backend.
  ///
  /// - Returns: A tuple containing the first `intended_use_id` and `registration_certificate` JWT.
  /// - Throws: An error if the fetch fails or the response is invalid.
  ///
  /// Example usage:
  /// ```swift
  /// let (intendedUseId, registrationCertJwt) = try await TestHelpers.fetchIntendedUse()
  /// print("Intended use: \(intendedUseId)")
  /// print("Registration certificate JWT: \(registrationCertJwt)")
  /// ```
  static func fetchIntendedUse() async throws -> (intendedUseId: String, registrationCertificate: String) {
    let url = URL(string: "https://dev.verifier-backend.eudiw.dev/ui/intended-uses")!

    let (data, response) = try await URLSession.shared.data(from: url)

    guard let httpResponse = response as? HTTPURLResponse,
          httpResponse.statusCode == 200 else {
      throw TestHelperError.invalidResponse
    }

    let decoder = JSONDecoder()
    let intendedUsesResponse = try decoder.decode(IntendedUsesResponse.self, from: data)

    guard let firstUse = intendedUsesResponse.intendedUses.first else {
      throw TestHelperError.noIntendedUsesFound
    }

    return (firstUse.intendedUseId, firstUse.registrationCertificate)
  }

  /// Errors that can occur when using test helpers.
  enum TestHelperError: Error, LocalizedError {
    case invalidResponse
    case noIntendedUsesFound

    var errorDescription: String? {
      switch self {
      case .invalidResponse:
        return "Invalid HTTP response from intended-uses endpoint"
      case .noIntendedUsesFound:
        return "No intended uses found in response"
      }
    }
  }
}
