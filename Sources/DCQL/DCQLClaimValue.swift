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

/// A scalar expected claim value. Equality compares both the JSON type and value.
public enum DCQLClaimValue: Codable, Equatable, Sendable {
  case string(String)
  case integer(Int64)
  case boolean(Bool)

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if let value = try? container.decode(Bool.self) {
      self = .boolean(value)
    } else if let value = try? container.decode(String.self) {
      self = .string(value)
    } else if let value = try? container.decode(Int64.self) {
      self = .integer(value)
    } else {
      throw DecodingError.typeMismatch(
        DCQLClaimValue.self,
        .init(codingPath: decoder.codingPath,
              debugDescription: "Expected a string, integer or boolean claim value")
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .string(let value): try container.encode(value)
    case .integer(let value): try container.encode(value)
    case .boolean(let value): try container.encode(value)
    }
  }
}

extension DCQLClaimValue: ExpressibleByStringLiteral {
  public init(stringLiteral value: String) { self = .string(value) }
}

extension DCQLClaimValue: ExpressibleByIntegerLiteral {
  public init(integerLiteral value: Int64) { self = .integer(value) }
}

extension DCQLClaimValue: ExpressibleByBooleanLiteral {
  public init(booleanLiteral value: Bool) { self = .boolean(value) }
}
