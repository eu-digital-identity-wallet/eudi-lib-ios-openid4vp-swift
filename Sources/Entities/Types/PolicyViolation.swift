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

/// Represents violations of the WRP Registration Certificate policy.
/// Per ETSI TS 119 475, policy validation may produce errors that stop processing
/// or warnings that are returned to callers for handling.
public enum PolicyViolation: Sendable, Equatable {
  /// Denotes violations of the policy that should **stop the processing** of the authorization request.
  case error(PolicyViolationError)

  /// Denotes violations of the policy that **do not stop processing**.
  /// It is up to callers to handle them accordingly.
  case warning(PolicyViolationWarning)
}

/// Error-level policy violations that stop request processing.
public struct PolicyViolationError: Sendable, Equatable {
  /// A code identifying the type of error
  public let code: String

  /// A human-readable description of the error
  public let message: String

  public init(code: String, message: String) {
    self.code = code
    self.message = message
  }
}

/// Warning-level policy violations that do not stop processing.
public struct PolicyViolationWarning: Sendable, Equatable {
  /// A code identifying the type of warning
  public let code: String

  /// A human-readable description of the warning
  public let message: String

  public init(code: String, message: String) {
    self.code = code
    self.message = message
  }
}

// MARK: - Convenience Extensions

public extension PolicyViolation {
  /// Returns true if this is an error-level violation
  var isError: Bool {
    if case .error = self { return true }
    return false
  }

  /// Returns true if this is a warning-level violation
  var isWarning: Bool {
    if case .warning = self { return true }
    return false
  }
}

public extension Array where Element == PolicyViolation {
  /// Returns all error-level violations
  var errors: [PolicyViolationError] {
    compactMap { violation in
      if case .error(let error) = violation { return error }
      return nil
    }
  }

  /// Returns all warning-level violations
  var warnings: [PolicyViolationWarning] {
    compactMap { violation in
      if case .warning(let warning) = violation { return warning }
      return nil
    }
  }

  /// Returns true if any error-level violations exist
  var hasErrors: Bool {
    contains { $0.isError }
  }
}
