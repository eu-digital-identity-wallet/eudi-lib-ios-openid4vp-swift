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

/// An enumeration representing different types of authorization requests.
public enum AuthorizationRequest: Sendable {
  /// A not secured authorization request.
  case notSecured(
    data: ResolvedRequestData,
    policyViolations: [String: [PolicyViolation]] = [:]
  )

  /// A JWT authorization request.
  case jwt(
    request: ResolvedRequestData,
    policyViolations: [String: [PolicyViolation]] = [:]
  )

  /// The resolution was not succesful
  case invalidResolution(
    error: AuthorizationRequestError,
    dispatchDetails: ErrorDispatchDetails?
  )

  public var resolved: ResolvedRequestData? {
    return switch self {
    case .notSecured(let request, _):
      request
    case .jwt(let request, _):
      request
    case .invalidResolution:
      nil
    }
  }

  /// Policy warnings from WRPRC validation, if any.
  public var policyViolations: [String: [PolicyViolation]] {
    return switch self {
    case .notSecured(_, let violations):
      violations
    case .jwt(_, let warnings):
      warnings
    case .invalidResolution:
      [:]
    }
  }
}

internal extension UnvalidatedRequestObject {
  var validResponseMode: ResponseMode {
    return (try? ResponseMode(authorizationRequestData: self)) ?? .none
  }
}
