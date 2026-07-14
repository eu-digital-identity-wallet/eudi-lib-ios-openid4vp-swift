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

/// Represents the type of a trusted authority.
///
public struct TrustedAuthorityType: Codable, Hashable, CustomStringConvertible, Sendable {
  
  /// The raw string value of the trusted authority type.
  public let value: String
  
  /// Creates a new `TrustedAuthorityType` with the given string.
  ///
  /// - Parameter value: The raw string value for the trusted authority type.
  /// - Throws: ``ValidationError.blankTrustedAuthorityType`` if the value is blank or whitespace.
  public init(_ value: String) throws {
    guard value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false else {
      throw ValidationError.blankTrustedAuthorityType
    }
    self.value = value
  }
  
  /// A `TrustedAuthorityType` representing an Authority Key Identifier (AKI).
  public static var AuthorityKeyIdentifier: TrustedAuthorityType {
    try! TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_AKI)
  }
  
  /// A `TrustedAuthorityType` representing a Trusted List (ETSI TL).
  public static var TrustedList: TrustedAuthorityType {
    try! TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_ETSI_TL)
  }
  
  /// A `TrustedAuthorityType` representing an OpenID Federation.
  public static var OpenIdFederation: TrustedAuthorityType {
    try! TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_OPENID_FEDERATION)
  }
  
  /// Returns the raw string value.
  public var description: String { value }
  
  /// Decodes a `TrustedAuthorityType` from a single string value.
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let decoded = try container.decode(String.self)
    try self.init(decoded)
  }
  
  /// Encodes the `TrustedAuthorityType` as a single string value.
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(value)
  }
  
  /// Validation errors that can occur when creating a `TrustedAuthorityType`.
  public enum ValidationError: LocalizedError {
    /// The value was blank or contained only whitespace.
    case blankTrustedAuthorityType
    
    public var errorDescription: String? {
      "TrustedAuthorityType cannot be blank"
    }
  }
}

/// Represents a trusted authority, including its type and associated values.
///
/// This is equivalent to the Kotlin `data class TrustedAuthority`.
/// It enforces that `values` is non-empty and contains no blank strings.
public struct TrustedAuthority: Codable, Equatable, Sendable {
  
  /// The type of the trusted authority.
  public let type: TrustedAuthorityType
  
  /// The associated values for this trusted authority.
  ///
  /// For example, these could be identifiers, URLs, or other strings depending on the `type`.
  public let values: [String]
  
  /// Creates a new `TrustedAuthority` with the given type and values.
  ///
  /// - Parameters:
  ///   - type: The type of the trusted authority.
  ///   - values: The associated values (must be non-empty and contain no blanks).
  /// - Throws:
  ///   - ``ValidationError.emptyValues`` if `values` is empty.
  ///   - ``ValidationError.containsBlankValues`` if any value is blank or whitespace.
  public init(type: TrustedAuthorityType, values: [String]) throws {
    guard values.isEmpty == false else {
      throw ValidationError.emptyValues
    }
    guard values.allSatisfy({ $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false }) else {
      throw ValidationError.containsBlankValues
    }
    self.type = type
    self.values = values
  }
  
  /// Creates a `TrustedAuthority` of type `.AuthorityKeyIdentifier`.
  ///
  /// - Parameter values: The associated string values.
  /// - Throws: Validation errors if the values list is invalid.
  public static func authorityKeyIdentifiers(_ values: [String]) throws -> TrustedAuthority {
    try TrustedAuthority(type: .AuthorityKeyIdentifier, values: values)
  }
  
  /// Creates a `TrustedAuthority` of type `.TrustedList` from a list of URLs.
  ///
  /// - Parameter values: The associated URL values.
  /// - Throws: Validation errors if the values list is invalid.
  public static func trustedLists(_ values: [URL]) throws -> TrustedAuthority {
    try TrustedAuthority(type: .TrustedList, values: values.map { $0.absoluteString })
  }
  
  /// Creates a `TrustedAuthority` of type `.OpenIdFederation` from a list of URLs.
  ///
  /// - Parameter values: The associated URL values.
  /// - Throws: Validation errors if the values list is invalid.
  public static func federatedEntities(_ values: [URL]) throws -> TrustedAuthority {
    try TrustedAuthority(type: .OpenIdFederation, values: values.map { $0.absoluteString })
  }
  
  private enum CodingKeys: String, CodingKey {
    case type
    case values
  }
  
  /// Decodes a `TrustedAuthority` from its JSON representation, validating its contents.
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let decodedType = try container.decode(TrustedAuthorityType.self, forKey: .type)
    let decodedValues = try container.decode([String].self, forKey: .values)
    try self.init(type: decodedType, values: decodedValues)
  }
  
  /// Validation errors that can occur when creating a `TrustedAuthority`.
  public enum ValidationError: LocalizedError {
    /// The values array was empty.
    case emptyValues
    /// The values array contained one or more blank strings.
    case containsBlankValues
    
    public var errorDescription: String? {
      switch self {
      case .emptyValues:
        return "\(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_VALUES) cannot be empty"
      case .containsBlankValues:
        return "\(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_VALUES) cannot contain blank values"
      }
    }
  }
}

