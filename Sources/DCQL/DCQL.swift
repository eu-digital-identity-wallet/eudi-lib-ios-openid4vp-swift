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
@preconcurrency import SwiftyJSON

public typealias Credentials = [CredentialQuery]
public typealias CredentialSets = [CredentialSetQuery]
public typealias CredentialSet = Set<QueryId>
public typealias ClaimSet = Set<ClaimId>

public enum DCQLError: Error {
  case emptyCredentials
  case duplicateQueryId
  case unknownQueryId
  case emptyCredentialSet
  case emptyNamespace
  case emptyClaimName
  case emptyDocType
  case error(String)
}

public struct CredentialQuery: Codable, Equatable, Sendable {
  enum CodingKeys: String, CodingKey {
    case id
    case format
    case meta
    case claims
    case claimSets = "claim_sets"
    case multiple
    case trustedAuthorities = "trusted_authorities"
    case requireCryptographicHolderBinding = "require_cryptographic_holder_binding"
  }
  
  public let id: QueryId
  public let format: Format
  public let meta: JSON
  public let claims: [ClaimsQuery]?
  public let claimSets: [ClaimSet]?
  public let multiple: Bool?
  public let trustedAuthorities: [TrustedAuthority]?
  public let requireCryptographicHolderBinding: Bool?
  
  public init(
    id: QueryId,
    format: Format,
    meta: JSON,
    claims: [ClaimsQuery]? = nil,
    claimSets: [ClaimSet]? = nil,
    multiple: Bool? = nil,
    trustedAuthorities: [TrustedAuthority]? = nil,
    requireCryptographicHolderBinding: Bool? = nil
  ) throws {
    
    if let trustedAuthorities = trustedAuthorities {
      guard trustedAuthorities.isEmpty == false else {
        throw ValidationError.validationError("Empty TrustedAuthorities")
      }
    }
    
    self.id = id
    self.format = format
    self.meta = meta
    self.claims = claims
    self.claimSets = claimSets
    self.multiple = multiple
    self.trustedAuthorities = trustedAuthorities
    self.requireCryptographicHolderBinding = requireCryptographicHolderBinding
  }
  
  public static func sdJwtVc(
    id: QueryId,
    sdJwtVcMeta: DCQLMetaSdJwtVcExtensions? = nil,
    claims: [ClaimsQuery]? = nil,
    claimSets: [ClaimSet]? = nil,
    multiple: Bool? = nil,
    trustedAuthorities: [TrustedAuthority]? = nil,
    requireCryptographicHolderBinding: Bool? = nil
  ) throws -> CredentialQuery {
    
    let jsonData = try JSONEncoder().encode(sdJwtVcMeta)
    let json = JSON(jsonData)
    
    return try CredentialQuery(
      id: id,
      format: try Format.SdJwtVc(),
      meta: json,
      claims: claims,
      claimSets: claimSets,
      multiple: multiple,
      trustedAuthorities: trustedAuthorities,
      requireCryptographicHolderBinding: requireCryptographicHolderBinding
    )
  }
  
  public static func mdoc(
    id: QueryId,
    msoMdocMeta: DCQLMetaMsoMdocExtensions? = nil,
    claims: [ClaimsQuery]? = nil,
    claimSets: [ClaimSet]? = nil,
    multiple: Bool? = nil,
    trustedAuthorities: [TrustedAuthority]? = nil,
    requireCryptographicHolderBinding: Bool? = nil
  ) throws -> CredentialQuery {
    
    let jsonData = try JSONEncoder().encode(msoMdocMeta)
    let json = JSON(jsonData)
    
    return try CredentialQuery(
      id: id,
      format: try Format.MsoMdoc(),
      meta: json,
      claims: claims,
      claimSets: claimSets,
      multiple: multiple,
      trustedAuthorities: trustedAuthorities,
      requireCryptographicHolderBinding: requireCryptographicHolderBinding
    )
  }
}

public struct CredentialSetQuery: Codable, Equatable, Sendable {
  
  public static let defaultRequiredValue: Bool = true
  
  public let options: [CredentialSet]
  public let required: Bool?
  
  enum CodingKeys: String, CodingKey {
    case options, required
  }
  
  public init(
    options: [CredentialSet],
    required: Bool = CredentialSetQuery.defaultRequiredValue
  ) throws {
    for credentialSet in options {
      guard !credentialSet.isEmpty else { throw DCQLError.emptyCredentialSet }
    }
    self.options = options
    self.required = required
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.options = try container.decode([CredentialSet].self, forKey: .options)
    self.required = try? container.decode(Bool.self, forKey: .required)
  }
}

public struct ClaimId: Codable, Hashable, Sendable {
  public let id: String
  
  enum CodingKeys: String, CodingKey {
    case id
  }
  
  public init(_ id: String) throws {
    try ClaimId.ensureValid(id)
    self.id = id
  }
  
  public static func ensureValid(_ value: String) throws {
    try DCQLId.ensureValid(value)
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let id = try container.decode(String.self)
    try ClaimId.ensureValid(id)
    try self.init(id)
  }
}

internal struct DCQLId {
  
  @discardableResult
  static func ensureValid(_ value: String) throws -> String {
    guard !value.isEmpty else {
      throw ValidationError.emptyValue
    }
    
    let regex = "^[a-zA-Z0-9_-]+$"
    let predicate: NSPredicate = .init(format: "SELF MATCHES %@", regex)
    
    guard predicate.evaluate(with: value) else {
      throw ValidationError.invalidFormat
    }
    
    return value
  }
}

public struct DCQL: Codable, Equatable, Sendable {
  
  public let credentials: Credentials
  public let credentialSets: CredentialSets?
  
  enum CodingKeys: String, CodingKey {
    case credentials
    case credentialSets = "credential_sets"
  }
  
  public init(
    credentials: Credentials,
    credentialSets: CredentialSets? = nil
  ) throws {
    let uniqueIds = try credentials.ensureValid()
    if let credentialSets = credentialSets {
      try credentialSets.ensureValid(knownIds: uniqueIds)
      try credentialSets.ensureKnownIds(credentials)
    }
    
    try credentials.ensureFormatsValid()
    try credentials.ensureValid()
    
    self.credentials = credentials
    self.credentialSets = credentialSets
  }
  
  init(from json: JSON) throws {
    
    let credentialsData = try json[OpenId4VPSpec.DCQL_CREDENTIALS].rawData()
    let credentials = try JSONDecoder().decode(Credentials.self, from: credentialsData)
    
    var credentialSets: CredentialSets?
    if json[OpenId4VPSpec.DCQL_CREDENTIAL_SETS].exists() {
      let credentialSetsData = try json[OpenId4VPSpec.DCQL_CREDENTIAL_SETS].rawData()
      credentialSets = try JSONDecoder().decode(CredentialSets.self, from: credentialSetsData)
    }
    
    try self.init(credentials: credentials, credentialSets: credentialSets)
  }
}

public extension Credentials {
  
  @discardableResult
  func ensureValid() throws -> CredentialSet {
    guard !isEmpty else { throw DCQLError.emptyCredentials }
    return try ensureUniqueIds()
  }
  
  func ensureUniqueIds() throws -> CredentialSet {
    let uniqueIds = Set(map { $0.id })
    guard uniqueIds.count == count else { throw DCQLError.duplicateQueryId }
    return uniqueIds
  }
  
  func ensureFormatsValid() throws {
    try self.forEach { credentialQuery in
      let credentialQueryFormat = credentialQuery.format
      switch credentialQueryFormat.format {
      case OpenId4VPSpec.FORMAT_MSO_MDOC, OpenId4VPSpec.FORMAT_MSO_MDOC_ZK: try credentialQuery.claims?.forEach { try _ = $0.ensureMsoMdoc() }
      default: try credentialQuery.claims?.forEach { try _ = $0.ensureNotMsoMdoc() }
      }
    }
  }
}

public extension CredentialSets {
  func ensureValid(knownIds: CredentialSet) throws {
    guard !isEmpty else { throw DCQLError.emptyCredentials }
    for credentialSet in self {
      try credentialSet.ensureOptionsWithKnownIds(knownIds: knownIds)
    }
  }
}

public extension CredentialSetQuery {
  func ensureOptionsWithKnownIds(knownIds: CredentialSet) throws {
    for credentialSet in options {
      guard credentialSet.allSatisfy({ knownIds.contains($0) }) else {
        throw DCQLError.unknownQueryId
      }
    }
  }
}

public struct ClaimsQuery: Codable, Equatable, Sendable {
  public let id: ClaimId?
  public let path: ClaimPath
  public let values: [String]?
  public let intentToRetain: Bool?
  
  enum CodingKeys: String, CodingKey {
    case id
    case path
    case values
    case intentToRetain = "intent_to_retain"
  }
  
  public init(
    id: ClaimId?,
    path: ClaimPath,
    values: [String]?,
    intentToRetain: Bool? = nil
  ) {
    self.id = id
    self.path = path
    self.values = values
    self.intentToRetain = intentToRetain
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    
    self.id = try container.decodeIfPresent(ClaimId.self, forKey: .id)
    self.path = try container.decode(ClaimPath.self, forKey: .path)
    self.values = try container.decodeIfPresent([String].self, forKey: .values)
    self.intentToRetain = try container.decodeIfPresent(Bool.self, forKey: .intentToRetain)
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    
    try container.encodeIfPresent(id, forKey: .id)
    try container.encodeIfPresent(values, forKey: .values)
    try container.encodeIfPresent(path, forKey: .path)
    try container.encodeIfPresent(intentToRetain, forKey: .intentToRetain)
  }
  
  public static func sdJwtVc(
    id: ClaimId? = nil,
    path: ClaimPath,
    values: [String]? = nil
  ) throws -> ClaimsQuery {
    try ClaimsQuery(
      id: id,
      path: path,
      values: values
    ).ensureNotMsoMdoc()
  }
  
  public static func mdoc(
    id: ClaimId? = nil,
    values: [String]? = nil,
    namespace: String,
    claimName: String,
    intentToRetain: Bool? = nil
  ) throws -> ClaimsQuery {
    try ClaimsQuery(
      id: id,
      path: .claim(namespace).claim(claimName),
      values: values,
      intentToRetain: intentToRetain
    ).ensureMsoMdoc()
  }
  
  public static func mdoc(
    id: ClaimId? = nil,
    values: [String]? = nil,
    path: ClaimPath,
    intentToRetain: Bool? = nil
  ) throws -> ClaimsQuery {
    try ClaimsQuery(
      id: id,
      path: path,
      values: values,
      intentToRetain: intentToRetain
    ).ensureMsoMdoc()
  }
}

extension ClaimsQuery {
  
  func ensureMsoMdoc() throws -> ClaimsQuery {
    if path.value.count < 2 {
      throw DCQLError.error(
        "Claim paths for mso mdoc based must have at least two elements (namespace and element identifier)"
      )
    }

    let firstTwoAreClaims = path.value.prefix(2).allSatisfy { element in
      switch element {
      case .claim:
        return true
      default:
        return false
      }
    }
    if !firstTwoAreClaims {
      throw DCQLError.error(
        "The first two elements of an MSO MDoc ClaimPath (namespace and element identifier) must be Claim elements"
      )
    }
    return self
  }
  
  func ensureNotMsoMdoc() throws -> ClaimsQuery {
    if intentToRetain != nil {
      throw DCQLError.error(
        "\(OpenId4VPSpec.DCQL_MSO_MDOC_INTENT_TO_RETAIN) can be used only with msp mdoc based formats"
      )
    }
    return self
  }
}

// MARK: - Extensions

public struct DCQLMetaSdJwtVcExtensions: Codable {
  
  public let vctValues: [String]
  
  enum CodingKeys: String, CodingKey {
    case vctValues = "vct_values"
  }
  
  public init(vctValues: [String]) throws {
    guard vctValues.isEmpty == false else {
      throw ValidationError.validationError("Empty VctValues")
    }
    self.vctValues = vctValues
  }
}

public struct DCQLMetaMsoMdocExtensions: Encodable {
  
  public let doctypeValue: MsoMdocDocType
  
  enum CodingKeys: String, CodingKey {
    case doctypeValue = "doctype_value"
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(doctypeValue.value, forKey: .doctypeValue)
  }
}

public struct MsoMdocDocType: CustomStringConvertible {
  public let value: String
  
  public init(value: String) throws {
    guard !value.isEmpty else {
      throw DCQLError.emptyDocType
    }
    self.value = value
  }
  
  public var description: String {
    return value
  }
}

public extension Array where Element == CredentialQuery {
  /// Collects all known query IDs from the credential list.
  /// Assumes `CredentialQuery` exposes an `id: QueryId`.
  var ids: Set<QueryId> {
    Set(self.map { $0.id })
  }
}

public extension Set where Element == QueryId {
  /// Returns the IDs in this credential set that are not known by `credentials`.
  func unknownIds(in credentials: Credentials) -> [QueryId] {
    Array(self.subtracting(credentials.ids))
  }
}

public extension Array where Element == CredentialSetQuery {
  /**
   Ensures that all the credential set queries (`self`) have options that reference IDs
   known by the given `credentials`.
   
   - Parameter credentials: The credentials against which the credential set queries will be checked.
   - Returns: `self` (to allow fluent chaining, mirroring Kotlin's `apply`).
   - Throws: ``CredentialSetsValidationError/invalidOptions(message:)`` if any option references unknown IDs.
   */
  @discardableResult
  func ensureKnownIds(_ credentials: Credentials) throws -> Self {
    
    var violations: [Int: [(optionIndex: Int, unknownIds: [QueryId])]] = [:]
    
    for (setIndex, query) in self.enumerated() {
      var invalids: [(optionIndex: Int, unknownIds: [QueryId])] = []
      
      for (optionIndex, optionSet) in query.options.enumerated() {
        let unknown = optionSet.unknownIds(in: credentials)
        if !unknown.isEmpty {
          invalids.append((optionIndex: optionIndex, unknownIds: unknown))
        }
      }
      
      if !invalids.isEmpty {
        violations[setIndex] = invalids
      }
    }
    
    guard violations.isEmpty else {
      var message = "The following credential set queries have invalid options:\n"
      for (setIndex, invalids) in violations.sorted(by: { $0.key < $1.key }) {
        message += "[\(setIndex)]:\n"
        for entry in invalids {
          message += "[\(entry.optionIndex)]:\n"
          message += "  Unknown credential query ids: \(entry.unknownIds)\n"
        }
      }
      throw ValidationError.validationError("invalidOptions \(message)")
    }
    
    return self
  }
}
