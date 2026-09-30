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

public struct VpFormatsSupportedTO: Codable, Equatable, Sendable {
  public let vcSdJwt: VcSdJwtTO?
  public let jwtVp: JwtVpTO?
  public let ldpVp: LdpVpTO?
  public let msoMdoc: MsoMdocTO?

  public init(
    vcSdJwt: VcSdJwtTO? = nil,
    jwtVp: JwtVpTO? = nil,
    ldpVp: LdpVpTO? = nil,
    msoMdoc: MsoMdocTO? = nil
  ) {
    self.vcSdJwt = vcSdJwt
    self.jwtVp = jwtVp
    self.ldpVp = ldpVp
    self.msoMdoc = msoMdoc
  }

  enum CodingKeys: String, CodingKey {
    case vcSdJwt = "dc+sd-jwt"
    case jwtVp = "jwt_vp"
    case ldpVp = "ldp_vp"
    case msoMdoc = "mso_mdoc"
  }
}

public struct VcSdJwtTO: Codable, Equatable, Sendable {
  public let sdJwtAlgorithms: [String]?
  public let kdJwtAlgorithms: [String]?

  enum CodingKeys: String, CodingKey {
    case sdJwtAlgorithms = "sd-jwt_alg_values"
    case kdJwtAlgorithms = "kb-jwt_alg_values"
  }

  public init(
    sdJwtAlgorithms: [String]?,
    kdJwtAlgorithms: [String]?
  ) {
    self.sdJwtAlgorithms = sdJwtAlgorithms
    self.kdJwtAlgorithms = kdJwtAlgorithms
  }
}

public struct MsoMdocTO: Codable, Equatable, Sendable {
  public let issuerAuthAlgorithms: [CoseAlgorithm]?
  public let deviceAuthAlgorithms: [CoseAlgorithm]?
  
  enum CodingKeys: String, CodingKey {
    case issuerAuthAlgorithms = "issuerauth_alg_values"
    case deviceAuthAlgorithms = "deviceauth_alg_values"
  }

  public init(
    issuerAuthAlgorithms: [CoseAlgorithm]?,
    deviceAuthAlgorithms: [CoseAlgorithm]?
  ) {
    self.issuerAuthAlgorithms = issuerAuthAlgorithms
    self.deviceAuthAlgorithms = deviceAuthAlgorithms
  }
}

public struct JwtVpTO: Codable, Equatable, Sendable {
  public let alg: [String]

  public init(alg: [String]) {
    self.alg = alg
  }
}

public struct LdpVpTO: Codable, Equatable, Sendable {
  public let proofType: [String]

  enum CodingKeys: String, CodingKey {
    case proofType = "proof_type"
  }

  public init(proofType: [String]) {
    self.proofType = proofType
  }
}

public enum VpFormatSupported: Equatable, Sendable {

  case sdJwtVc(
    sdJwtAlgorithms: [JWSAlgorithm],
    kbJwtAlgorithms: [JWSAlgorithm]
  )
  case msoMdoc(
    issuerAuthAlgorithms: [CoseAlgorithm]?,
    deviceAuthAlgorithms: [CoseAlgorithm]?
  )
  case jwtVp(algorithms: [String])
  case ldpVp(proofTypes: [String])

  public static func createSdJwtVc(
    sdJwtAlgorithms: [JWSAlgorithm],
    kbJwtAlgorithms: [JWSAlgorithm]
  ) throws -> VpFormatSupported {

    guard !sdJwtAlgorithms.isEmpty else {
      throw ValidationError.validationError("SD-JWT algorithms cannot be empty")
    }

    return .sdJwtVc(
      sdJwtAlgorithms: sdJwtAlgorithms,
      kbJwtAlgorithms: kbJwtAlgorithms
    )
  }

  public static func createMsoMdoc(
    issuerAuthAlgorithms: [CoseAlgorithm]?,
    deviceAuthAlgorithms: [CoseAlgorithm]?
  ) throws -> VpFormatSupported {
    .msoMdoc(
      issuerAuthAlgorithms: issuerAuthAlgorithms,
      deviceAuthAlgorithms: deviceAuthAlgorithms
    )
  }
}

public extension VpFormatSupported {
  func formatName() -> FormatName {
    switch self {
    case .msoMdoc:
      return .MSO_MDOC
    case .sdJwtVc:
      return .SD_JWT_VC
    case .jwtVp:
      return .JWT_VP
    case .ldpVp:
      return .LDP_VP
    }
  }

  /// Returns the format string used in DCQL queries (e.g., "mso_mdoc", "dc+sd-jwt").
  func formatString() -> String {
    switch self {
    case .msoMdoc:
      return OpenId4VPSpec.FORMAT_MSO_MDOC
    case .sdJwtVc:
      return OpenId4VPSpec.FORMAT_SD_JWT_VC
    case .jwtVp:
      return OpenId4VPSpec.FORMAT_W3C_SIGNED_JWT
    case .ldpVp:
      return "ldp_vp"
    }
  }

  enum FormatName: String {
    case MSO_MDOC
    case SD_JWT_VC
    case JWT_VP
    case LDP_VP
  }
}

public struct VpFormatsSupported: Equatable, Sendable {

  public static let vpFormatsSupported = "vp_formats_supported"
  public let values: [VpFormatSupported]

  public static func `default`() throws -> VpFormatsSupported {
    try VpFormatsSupported(values: [
      .sdJwtVc(
        sdJwtAlgorithms: [JWSAlgorithm(.ES256)],
        kbJwtAlgorithms: [JWSAlgorithm(.ES256)]
      ),
      .msoMdoc(
        issuerAuthAlgorithms: [-7],
        deviceAuthAlgorithms: [-7]
      )
    ])
  }

  public static func empty() throws -> VpFormatsSupported {
    try VpFormatsSupported(values: [])
  }

  public init?(jsonString: String?) throws {
    guard let jsonString = jsonString else {
      return nil
    }
    let json = JSON(parseJSON: jsonString)
    try? self.init(json: json)
  }

  public init?(json: JSON) throws {
    guard let dictionaryObject = json.dictionaryObject else {
      return nil
    }

    let vpFormatsDictionary: JSON = JSON(dictionaryObject)[Self.vpFormatsSupported]
    if let formats = try? vpFormatsDictionary.decoded(as: VpFormatsSupportedTO.self) {
      try? self.init(from: formats)
    } else {
      return nil
    }
  }

  public init(formats: VpFormatSupported...) throws {
    self.values = formats
    try VpFormatsSupported.ensureUniquePerFormat(formats: formats)
  }

  public init(values: [VpFormatSupported]) throws {
    self.values = values
    try VpFormatsSupported.ensureUniquePerFormat(formats: values)
  }

  func contains(_ format: VpFormatSupported) -> Bool {
    return values.contains(where: { $0 == format })
  }

  /// Returns the set of format strings supported (e.g., "mso_mdoc", "dc+sd-jwt").
  public func supportedFormatStrings() -> Set<String> {
    Set(values.map { $0.formatString() })
  }

  /// Checks if a given format string is supported.
  public func supportsFormat(_ formatString: String) -> Bool {
    supportedFormatStrings().contains(formatString)
  }

  public static func common(_ this: VpFormatsSupported, _ that: VpFormatsSupported) -> VpFormatsSupported? {
    var commonFormats: [VpFormatSupported] = []

    for format in this.values {
      if that.contains(format) {
        commonFormats.append(format)
      }
    }

    return commonFormats.isEmpty ?
    nil :
    try? VpFormatsSupported(values: commonFormats)
  }

  private static func ensureUniquePerFormat(formats: [VpFormatSupported]) throws {
    let groupedFormats = Dictionary(grouping: formats) { $0.formatName() }

    for (formatName, instances) in groupedFormats {
      guard instances.count == 1 else {
        throw ValidationError.validationError(
          "Multiple instances \(instances.count) found for \(formatName)."
        )
      }
    }
  }
}

public extension VpFormatsSupported {

  // New initializer that accepts a VpFormatsSupportedTO object
  init?(from to: VpFormatsSupportedTO?) throws {

    guard let to = to else {
      return nil
    }

    var formats: [VpFormatSupported] = []

    if let vcSdJwt = to.vcSdJwt {
      let sdJwtAlgorithms = vcSdJwt.sdJwtAlgorithms?.compactMap { JWSAlgorithm(name: $0) } ?? []
      let kbJwtAlgorithms = vcSdJwt.kdJwtAlgorithms?.compactMap { JWSAlgorithm(name: $0) } ?? []

      let sdJwtVcFormat = VpFormatSupported.sdJwtVc(
        sdJwtAlgorithms: sdJwtAlgorithms,
        kbJwtAlgorithms: kbJwtAlgorithms
      )
      formats.append(sdJwtVcFormat)
    }

    if let msoMdoc = to.msoMdoc {
      let msoMdocFormat = VpFormatSupported.msoMdoc(
        issuerAuthAlgorithms: msoMdoc.issuerAuthAlgorithms,
        deviceAuthAlgorithms: msoMdoc.deviceAuthAlgorithms
      )
      formats.append(msoMdocFormat)
    }

    if let jwtVp = to.jwtVp {
      let jwtVpFormat = VpFormatSupported.jwtVp(algorithms: jwtVp.alg)
      formats.append(jwtVpFormat)
    }

    if let ldpVp = to.ldpVp {
      let ldpVpFormat = VpFormatSupported.ldpVp(proofTypes: ldpVp.proofType)
      formats.append(ldpVpFormat)
    }

    try self.init(values: formats)
  }

  // New initializer that accepts an array of VpFormatsSupportedTO objects
  init?(from tos: [VpFormatsSupportedTO]?) throws {

    guard let tos = tos else {
      return nil
    }

    var formats: [VpFormatSupported] = []

    for to in tos {
      // Convert VcSdJwtTO if it exists
      if let vcSdJwt = to.vcSdJwt {
        let sdJwtAlgorithms = vcSdJwt.sdJwtAlgorithms?.compactMap { JWSAlgorithm(name: $0) } ?? []
        let kbJwtAlgorithms = vcSdJwt.kdJwtAlgorithms?.compactMap { JWSAlgorithm(name: $0) } ?? []

        let sdJwtVcFormat = VpFormatSupported.sdJwtVc(
          sdJwtAlgorithms: sdJwtAlgorithms,
          kbJwtAlgorithms: kbJwtAlgorithms
        )
        formats.append(sdJwtVcFormat)
      }

      // Add msoMdoc if it exists
      if let msoMdoc = to.msoMdoc {
        let msoMdocFormat = VpFormatSupported.msoMdoc(
          issuerAuthAlgorithms: msoMdoc.issuerAuthAlgorithms,
          deviceAuthAlgorithms: msoMdoc.deviceAuthAlgorithms
        )
        formats.append(msoMdocFormat)
      }

      // Convert JwtVpTO if it exists
      if let jwtVp = to.jwtVp {
        let jwtVpFormat = VpFormatSupported.jwtVp(algorithms: jwtVp.alg)
        formats.append(jwtVpFormat)
      }

      // Convert LdpVpTO if it exists
      if let ldpVp = to.ldpVp {
        let ldpVpFormat = VpFormatSupported.ldpVp(proofTypes: ldpVp.proofType)
        formats.append(ldpVpFormat)
      }
    }

    try self.init(values: formats)
  }

  // Convert VpFormats to JSON
  func toJSON() -> JSON {
    var mergedFormats: [String: JSON] = [:]

    for format in values {
      let jsonFormat = format.toJSON()

      // Assuming jsonFormat is [String: JSON] — merge it in
      for (key, value) in jsonFormat {
        mergedFormats[key] = value
      }
    }

    return JSON([Self.vpFormatsSupported: mergedFormats])
  }
}

// Extend VpFormatSupported to convert to JSON
extension VpFormatSupported {
  func toJSON() -> JSON {
    switch self {
    case .sdJwtVc(let sdJwtAlgorithms, let kbJwtAlgorithms):
      return JSON(["dc+sd-jwt": [
        "sd-jwt_alg_values": sdJwtAlgorithms.map { $0.name },
        "kb-jwt_alg_values": kbJwtAlgorithms.map { $0.name }
      ]]
      )
    case .msoMdoc(
      let issuerAuthAlgorithms,
      let deviceAuthAlgorithms
    ):
      return JSON(["mso_mdoc": [
        "issuerauth_alg_values": issuerAuthAlgorithms,
        "deviceauth_alg_values": deviceAuthAlgorithms
      ]
                  ])

    case .jwtVp(let algorithms):
      return JSON([
        "jwtVp": ["algorithms": algorithms]
      ])
    case .ldpVp(let proofTypes):
      return JSON([
        "ldpVp": ["proofTypes": proofTypes]
      ])
    }
  }
}
