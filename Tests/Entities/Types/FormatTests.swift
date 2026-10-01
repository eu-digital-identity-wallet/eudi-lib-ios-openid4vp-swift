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
import XCTest
@testable import OpenID4VP

final class FormatTests: XCTestCase {
  func testInitWithValidFormat() throws {
    let format = try Format(format: "validFormat")
    XCTAssertEqual(format.format, "validFormat")
  }

  func testInitWithBlankFormat() {
    XCTAssertThrowsError(try Format(format: "")) { error in
      XCTAssertEqual(error as? FormatError, FormatError.blankValue)
    }

    XCTAssertThrowsError(try Format(format: "    ")) { error in
      XCTAssertEqual(error as? FormatError, FormatError.blankValue)
    }
  }

  func testEncodingAndDecoding() throws {
    let original = try Format(format: "jsonFormat")
    let encoder = JSONEncoder()
    let data = try encoder.encode(original)

    let decoder = JSONDecoder()
    let decoded = try decoder.decode(Format.self, from: data)

    XCTAssertEqual(decoded, original)
  }

  func testDecodingInvalidFormat() {
    let json = "\"   \"".data(using: .utf8)!
    let decoder = JSONDecoder()

    XCTAssertThrowsError(try decoder.decode(Format.self, from: json)) { error in
      XCTAssertEqual(error as? FormatError, FormatError.blankValue)
    }
  }

  func testDescription() throws {
    let format = try Format(format: "descFormat")
    XCTAssertEqual(format.description, "descFormat")
  }

  func testStaticMsoMdoc() throws {
    let format = try Format.MsoMdoc()
    XCTAssertEqual(format.format, OpenId4VPSpec.FORMAT_MSO_MDOC)
  }

  func testStaticSdJwtVc() throws {
    let format = try Format.SdJwtVc()
    XCTAssertEqual(format.format, OpenId4VPSpec.FORMAT_SD_JWT_VC)
  }

  func testStaticW3CJwtVcJSON() throws {
    let format = try Format.W3CJwtVcJson()
    XCTAssertEqual(format.format, OpenId4VPSpec.FORMAT_W3C_SIGNED_JWT)
  }

  // MARK: - VpFormatSupported format string tests

  func testVpFormatSupportedFormatStringMsoMdoc() {
    let format = VpFormatSupported.msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil)
    XCTAssertEqual(format.formatString(), "mso_mdoc")
  }

  func testVpFormatSupportedFormatStringSdJwtVc() {
    let format = VpFormatSupported.sdJwtVc(sdJwtAlgorithms: [], kbJwtAlgorithms: [])
    XCTAssertEqual(format.formatString(), "dc+sd-jwt")
  }

  func testVpFormatSupportedFormatStringJwtVp() {
    let format = VpFormatSupported.jwtVp(algorithms: [])
    XCTAssertEqual(format.formatString(), "jwt_vc_json")
  }

  func testVpFormatSupportedFormatStringLdpVp() {
    let format = VpFormatSupported.ldpVp(proofTypes: [])
    XCTAssertEqual(format.formatString(), "ldp_vp")
  }

  // MARK: - VpFormatsSupported tests

  func testVpFormatsSupportedFormatStrings() throws {
    let formats = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil),
      .sdJwtVc(sdJwtAlgorithms: [], kbJwtAlgorithms: [])
    ])

    let formatStrings = formats.supportedFormatStrings()
    XCTAssertEqual(formatStrings, Set(["mso_mdoc", "dc+sd-jwt"]))
  }

  func testVpFormatsSupportedEmptyFormatStrings() throws {
    let formats = try VpFormatsSupported.empty()
    let formatStrings = formats.supportedFormatStrings()
    XCTAssertTrue(formatStrings.isEmpty)
  }

  func testVpFormatsSupportedCommonReturnsNilWhenNoIntersection() throws {
    let walletFormats = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil)
    ])
    let clientFormats = try VpFormatsSupported(values: [
      .jwtVp(algorithms: ["ES256"])
    ])

    let common = VpFormatsSupported.common(clientFormats, walletFormats)
    XCTAssertNil(common)
  }

  func testVpFormatsSupportedCommonReturnsIntersection() throws {
    let walletFormats = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: [-7], deviceAuthAlgorithms: [-7]),
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [])
    ])
    let clientFormats = try VpFormatsSupported(values: [
      .msoMdoc(issuerAuthAlgorithms: [-7], deviceAuthAlgorithms: [-7]),
      .jwtVp(algorithms: ["ES256"])
    ])

    let common = VpFormatsSupported.common(clientFormats, walletFormats)
    XCTAssertNotNil(common)
    XCTAssertEqual(common?.supportedFormatStrings(), Set(["mso_mdoc"]))
  }

  func testVpFormatsSupportedCommonKeepsSharedAlgorithmsWhenClientSupportsMore() throws {
    let walletFormats = try VpFormatsSupported.default()
    let clientFormats = try VpFormatsSupported(values: [
      .sdJwtVc(
        sdJwtAlgorithms: [JWSAlgorithm(.ES256), JWSAlgorithm(.ES384), JWSAlgorithm(.ES512)],
        kbJwtAlgorithms: [JWSAlgorithm(.ES256), JWSAlgorithm(.ES384), JWSAlgorithm(.ES512)]
      ),
      .msoMdoc(issuerAuthAlgorithms: [-7, -35, -36], deviceAuthAlgorithms: [-7, -35, -36])
    ])

    let common = VpFormatsSupported.common(clientFormats, walletFormats)
    XCTAssertEqual(common, walletFormats)
  }

  func testVpFormatsSupportedCommonDropsFormatWithoutSharedAlgorithms() throws {
    let walletFormats = try VpFormatsSupported.default()
    let clientFormats = try VpFormatsSupported(values: [
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES384)], kbJwtAlgorithms: [JWSAlgorithm(.ES384)]),
      .msoMdoc(issuerAuthAlgorithms: [-7, -35], deviceAuthAlgorithms: [-7])
    ])

    let common = VpFormatsSupported.common(clientFormats, walletFormats)
    XCTAssertEqual(common?.values, [.msoMdoc(issuerAuthAlgorithms: [-7], deviceAuthAlgorithms: [-7])])
  }

  func testVpFormatsSupportedCommonReturnsNilWhenNoAlgorithmIsShared() throws {
    let walletFormats = try VpFormatsSupported.default()
    let clientFormats = try VpFormatsSupported(values: [
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES384)], kbJwtAlgorithms: [JWSAlgorithm(.ES384)]),
      .msoMdoc(issuerAuthAlgorithms: [-35], deviceAuthAlgorithms: [-35])
    ])

    XCTAssertNil(VpFormatsSupported.common(clientFormats, walletFormats))
  }

  func testVpFormatsSupportedCommonTreatsMissingAlgorithmsAsUnconstrained() throws {
    let walletFormats = try VpFormatsSupported.default()
    let clientFormats = try VpFormatsSupported(values: [
      .sdJwtVc(sdJwtAlgorithms: [], kbJwtAlgorithms: []),
      .msoMdoc(issuerAuthAlgorithms: nil, deviceAuthAlgorithms: nil)
    ])

    let common = VpFormatsSupported.common(clientFormats, walletFormats)
    XCTAssertEqual(common, walletFormats)
  }
}
