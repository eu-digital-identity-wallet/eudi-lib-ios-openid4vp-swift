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
import Foundation
import SwiftyJSON

@testable import OpenID4VP

class ResolvedOpenId4VPRequestDataTests: DiXCTest {

  func testWalletOpenId4VPConfigurationInitialization() throws {
    let signingKey = try KeyController.generateRSAPrivateKey()
    let signingKeySet = WebKeySet(keys: [])
    let supportedClientIdSchemes: [SupportedClientIdPrefix] = []
    let vpFormatsSupported: [ClaimFormat] = [.jwtType(.jwt)]

    let walletOpenId4VPConfiguration = OpenId4VPConfiguration(
      privateKey: signingKey,
      publicWebKeySet: signingKeySet,
      supportedClientIdSchemes: supportedClientIdSchemes,
      vpFormatsSupported: vpFormatsSupported,
      jarConfiguration: .noEncryptionOption,
      vpConfiguration: .default(),
      session: OpenId4VPConfiguration.walletSession,
      responseEncryptionConfiguration: .unsupported
    )

    XCTAssertEqual(walletOpenId4VPConfiguration.vpFormatsSupported, vpFormatsSupported)
  }
}

class VerifierFormPostTests: XCTestCase {

  func testUrlRequest() {
    let url = URL(string: "https://www.example.com")!
    let formData: [String: Any] = [
      "param1": "value1",
      "param2": 123,
      "param3": true
    ]
    let formPost = VerifierFormPost(url: url, formData: formData)

    var expectedRequest = URLRequest(url: url)
    expectedRequest.httpMethod = "POST"
    expectedRequest.httpBody = "param1=value1&param2=123&param3=true".data(using: .utf8)
    expectedRequest.httpShouldHandleCookies = false
    
    XCTAssertEqual(formPost.urlRequest, expectedRequest)
  }

  func testMethod() {
    let formPost = VerifierFormPost(url: URL(string: "https://www.example.com")!, formData: [:])
    XCTAssertEqual(formPost.method, HTTPMethod.POST)
  }

  func testAdditionalHeaders() {
    var formPost = VerifierFormPost(url: URL(string: "https://www.example.com")!, formData: [:])
    XCTAssertTrue(formPost.additionalHeaders.isEmpty)

    // Add test cases to cover other scenarios for additionalHeaders
    formPost.additionalHeaders = ["Authorization": "Bearer token"]
    XCTAssertEqual(formPost.additionalHeaders["Authorization"], "Bearer token")
  }

  func testBody() {
    let formData: [String: Any] = ["param": "value"]
    let formPost = VerifierFormPost(url: URL(string: "https://www.example.com")!, formData: formData)

    let expectedBody = "param=value".data(using: .utf8)
    XCTAssertEqual(formPost.body, expectedBody)

    // Add test cases to cover other scenarios for body
    let emptyFormData = [String: Any]()
    let emptyFormPost = VerifierFormPost(
      url: URL(string: "https://www.example.com")!,
      formData: emptyFormData
    )
    XCTAssertNotNil(emptyFormPost.body)
  }

  func testURLRequest() {
    let url = URL(string: "https://www.example.com")!
    let formData: [String: Any] = ["param": "value"]
    let formPost = VerifierFormPost(url: url, formData: formData)

    var expectedRequest = URLRequest(url: url)
    expectedRequest.httpMethod = "POST"
    expectedRequest.httpBody = "param=value".data(using: .utf8)
    expectedRequest.httpShouldHandleCookies = false
    
    XCTAssertEqual(formPost.urlRequest, expectedRequest)

    // Add test cases to cover other scenarios for urlRequest
    let request = formPost.urlRequest
    XCTAssertEqual(request.allHTTPHeaderFields, formPost.additionalHeaders)
  }
}

final class VpFormatsSupportedTests: XCTestCase {

  func testInitWithValidValues() throws {
    let sdJwtFormat = VpFormatSupported.sdJwtVc(
      sdJwtAlgorithms: [JWSAlgorithm(.ES256)],
      kbJwtAlgorithms: [JWSAlgorithm(.ES256)]
    )
    let jwtVpFormat = VpFormatSupported.jwtVp(algorithms: ["RS256"])
    let ldpVpFormat = VpFormatSupported.ldpVp(proofTypes: ["ProofType1"])
    let msoMdocFormat = VpFormatSupported.msoMdoc(
      issuerAuthAlgorithms: [],
      deviceAuthAlgorithms: []
    )

    let vpFormatsSupported = try VpFormatsSupported(values: [sdJwtFormat, jwtVpFormat, ldpVpFormat, msoMdocFormat])

    XCTAssertEqual(vpFormatsSupported.values.count, 4)
    XCTAssertTrue(vpFormatsSupported.contains(sdJwtFormat))
    XCTAssertTrue(vpFormatsSupported.contains(jwtVpFormat))
    XCTAssertTrue(vpFormatsSupported.contains(ldpVpFormat))
    XCTAssertTrue(vpFormatsSupported.contains(msoMdocFormat))
  }

  func testInitWithDuplicateFormatsThrowsError() {
    let format = VpFormatSupported.jwtVp(algorithms: ["RS256"])

    XCTAssertThrowsError(try VpFormatsSupported(values: [format, format])) { error in
      guard let validationError = error as? ValidationError else {
        return XCTFail("Unexpected error type")
      }
      XCTAssertEqual(validationError, .validationError("Multiple instances 2 found for JWT_VP."))
    }
  }

  func testFormatNames() {
    XCTAssertEqual(VpFormatSupported.msoMdoc(issuerAuthAlgorithms: [], deviceAuthAlgorithms: []).formatName(), .MSO_MDOC)
    XCTAssertEqual(VpFormatSupported.sdJwtVc(sdJwtAlgorithms: [], kbJwtAlgorithms: []).formatName(), .SD_JWT_VC)
    XCTAssertEqual(VpFormatSupported.jwtVp(algorithms: []).formatName(), .JWT_VP)
    XCTAssertEqual(VpFormatSupported.ldpVp(proofTypes: []).formatName(), .LDP_VP)
  }

  func testVpFormatToJSON() {
    let format = VpFormatSupported.sdJwtVc(
      sdJwtAlgorithms: [JWSAlgorithm(.ES256)],
      kbJwtAlgorithms: [JWSAlgorithm(.ES256)]
    )
    let json = format.toJSON()

    XCTAssertEqual(json["dc+sd-jwt"]["sd-jwt_alg_values"].arrayValue.map { $0.stringValue }, ["ES256"])
    XCTAssertEqual(json["dc+sd-jwt"]["kb-jwt_alg_values"].arrayValue.map { $0.stringValue }, ["ES256"])
  }

  func testVpFormatsToJSON() throws {
    let sdJwtFormat = VpFormatSupported.sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    let jwtVpFormat = VpFormatSupported.jwtVp(algorithms: ["RS256"])
    let vpFormatsSupported = try VpFormatsSupported(values: [sdJwtFormat, jwtVpFormat])

    let json = vpFormatsSupported.toJSON()

    XCTAssertEqual(json["vp_formats_supported"].dictionaryValue.count, 2)
  }

  func testVpFormatsFromJson() throws {
    let jsonString = """
    {
       "vp_formats_supported": {
              "dc+sd-jwt": {
                  "sd-jwt_alg_values": [
                      "ES256"
                  ],
                  "kb-jwt_alg_values": [
                      "ES256"
                  ]
              },
              "mso_mdoc": {
                  "alg": [
                      "ES256"
                  ]
              }
          }
    }
    """

    let vpFormatsSupported = try VpFormatsSupported(jsonString: jsonString)

    XCTAssertEqual(vpFormatsSupported?.values.count, 2)
  }

  func testVpFormatSupportedEquatable() {
    let format1 = VpFormatSupported.jwtVp(algorithms: ["RS256"])
    let format2 = VpFormatSupported.jwtVp(algorithms: ["RS256"])

    XCTAssertEqual(format1, format2)
  }

  func testVpFormatSupportedInequality() {
    let format1 = VpFormatSupported.jwtVp(algorithms: ["RS256"])
    let format2 = VpFormatSupported.jwtVp(algorithms: ["ES256"])

    XCTAssertNotEqual(format1, format2)
  }

  // MARK: - Test Empty VpFormatsSupported Creation

  func testVpFormatsSupportedEmptyCreation() throws {
    let emptyFormats = try VpFormatsSupported.empty()

    XCTAssertEqual(emptyFormats.values.count, 0)
  }

  func testVpFormatsSupportedDefaultCreation() throws {
    let defaultFormats = try VpFormatsSupported.default()

    XCTAssertEqual(defaultFormats.values.count, 2)
    XCTAssertEqual(defaultFormats.values.first?.formatName(), .SD_JWT_VC)
  }

  func testVpFormatsSupportedInitFromTO() throws {
    let to = VpFormatsSupportedTO(
      vcSdJwt: VcSdJwtTO(sdJwtAlgorithms: ["ES256"], kdJwtAlgorithms: ["ES256"]),
      jwtVp: JwtVpTO(alg: ["RS256"]),
      ldpVp: LdpVpTO(proofType: ["ProofType"]),
      msoMdoc: MsoMdocTO(issuerAuthAlgorithms: [], deviceAuthAlgorithms: [])
    )

    let vpFormatsSupported = try VpFormatsSupported(from: to)

    XCTAssertEqual(vpFormatsSupported?.values.count, 4)
    XCTAssertTrue(vpFormatsSupported?.contains(.jwtVp(algorithms: ["RS256"])) ?? false)
    XCTAssertTrue(vpFormatsSupported?.contains(.msoMdoc(issuerAuthAlgorithms: [], deviceAuthAlgorithms: [])) ?? false)
  }

  func testVpFormatsSupportedIntersectWithCommonElements() throws {
    let format1 = VpFormatSupported.sdJwtVc(
      sdJwtAlgorithms: [JWSAlgorithm(.ES256)],
      kbJwtAlgorithms: [JWSAlgorithm(.ES256)]
    )

    let format2 = VpFormatSupported.jwtVp(algorithms: ["RS256"])

    let vpFormatsSupported1 = try VpFormatsSupported(values: [format1, format2])
    let vpFormatsSupported2 = try VpFormatsSupported(values: [format1])

    let intersection = VpFormatsSupported.common(vpFormatsSupported1, vpFormatsSupported2)

    XCTAssertNotNil(intersection)
    XCTAssertEqual(intersection?.values.count, 1)
    XCTAssertTrue(intersection?.contains(format1) ?? false)
  }

  func testVpFormatsSupportedIntersectWithNoCommonElements() throws {
    let vpFormatsSupported1 = try VpFormatsSupported(values: [
      .sdJwtVc(sdJwtAlgorithms: [JWSAlgorithm(.ES256)], kbJwtAlgorithms: [JWSAlgorithm(.ES256)])
    ])

    let vpFormatsSupported2 = try VpFormatsSupported(values: [
      .jwtVp(algorithms: ["RS256"])
    ])

    let intersection = VpFormatsSupported.common(vpFormatsSupported1, vpFormatsSupported2)

    XCTAssertNil(intersection)
  }

  func testVpFormatsSupportedIntersectWithIdenticalFormats() throws {
    let format = VpFormatSupported.ldpVp(proofTypes: ["ProofType1"])

    let vpFormatsSupported1 = try VpFormatsSupported(values: [format])
    let vpFormatsSupported2 = try VpFormatsSupported(values: [format])

    let intersection = VpFormatsSupported.common(vpFormatsSupported1, vpFormatsSupported2)

    XCTAssertNotNil(intersection)
    XCTAssertEqual(intersection?.values.count, 1)
    XCTAssertTrue(intersection?.contains(format) ?? false)
  }

  func testVpFormatsSupportedIntersectWithEmptySet() throws {
    let vpFormatsSupported1 = try VpFormatsSupported(values: [])
    let vpFormatsSupported2 = try VpFormatsSupported(values: [
      .jwtVp(algorithms: ["RS256"])
    ])

    let intersection = VpFormatsSupported.common(vpFormatsSupported1, vpFormatsSupported2)

    XCTAssertNil(intersection)
  }

  func testVpFormatsSupportedIntersectWithBothEmpty() throws {
    let vpFormatsSupported1 = try VpFormatsSupported(values: [])
    let vpFormatsSupported2 = try VpFormatsSupported(values: [])

    let intersection = VpFormatsSupported.common(vpFormatsSupported1, vpFormatsSupported2)

    XCTAssertNil(intersection)
  }
}

class WalletMetaDataTests: XCTestCase {

  func testWalletMetaData() throws {

    let walletConfiguration = try OpenID4VPTests.preRegisteredWalletConfigurationWithKnownClientID()

    let json = walletMetaData(
      config: walletConfiguration
    )

    XCTAssertEqual(json["request_object_signing_alg_values_supported"].arrayValue.map { $0.stringValue }, ["ES256"])
    XCTAssertEqual(json["vp_formats_supported"].dictionaryValue.count, 2)
    XCTAssertEqual(json["client_id_prefixes_supported"].arrayValue.map { $0.stringValue }, ["pre-registered"])
    XCTAssertEqual(json["response_types_supported"].arrayValue.map { $0.stringValue }, ["vp_token"])
    XCTAssertEqual(json["response_modes_supported"].arrayValue.map { $0.stringValue }, ["direct_post", "direct_post.jwt"])
  }

  func testWebKeySetInitializationFromJSONString() throws {
    let jsonString = """
      {
        "keys": [
          {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF4iF42R-9DKM4TZpx4xq7se5OUzJ57Jv1g",
            "y": "x_FEzRu9iwjJHnA8sfxfCVXovE3KcdK1WlWpeRcd3WA",
            "alg": "ES256"
          }
       ]
    }
    """
    let webKeySet = try WebKeySet(jsonString)
    XCTAssertEqual(webKeySet.keys.count, 1)

    let key = webKeySet.keys[0]
    XCTAssertEqual(key.kty, "EC")
    XCTAssertEqual(key.crv, "P-256")
    XCTAssertEqual(key.x, "f83OJ3D2xF4iF42R-9DKM4TZpx4xq7se5OUzJ57Jv1g")
    XCTAssertEqual(key.y, "x_FEzRu9iwjJHnA8sfxfCVXovE3KcdK1WlWpeRcd3WA")
    XCTAssertEqual(key.alg, "ES256")
  }  
}

final class AuthorizationRequestUnprocessedDataTests: XCTestCase {

  func testInit() {
    let data = UnvalidatedRequestObject(
        responseType: "code",
        responseUri: "https://example.com/response",
        redirectUri: "https://example.com/redirect",
        request: "request",
        requestUri: "https://example.com/request",
        clientMetaData: "clientMetaData",
        clientId: "clientId",
        clientMetadataUri: "https://example.com/metadata",
        clientIdScheme: "clientScheme",
        nonce: "nonce",
        scope: "scope",
        responseMode: "responseMode",
        state: "state"
    )

    XCTAssertEqual(data.responseType, "code")
    XCTAssertEqual(data.responseUri, "https://example.com/response")
    XCTAssertEqual(data.redirectUri, "https://example.com/redirect")
    XCTAssertEqual(data.request, "request")
    XCTAssertEqual(data.requestUri, "https://example.com/request")
    XCTAssertEqual(data.clientMetaData, "clientMetaData")
    XCTAssertEqual(data.clientId, "clientId")
    XCTAssertEqual(data.clientMetadataUri, "https://example.com/metadata")
    XCTAssertEqual(data.clientIdScheme, "clientScheme")
    XCTAssertEqual(data.nonce, "nonce")
    XCTAssertEqual(data.scope, "scope")
    XCTAssertEqual(data.responseMode, "responseMode")
    XCTAssertEqual(data.state, "state")
  }

  func testInitFromDecoder() throws {
    let json = """
    {
        "response_type": "code",
        "response_uri": "https://example.com/response",
        "redirect_uri": "https://example.com/redirect",
        "request": "request",
        "request_uri": "https://example.com/request",
        "client_metadata": "clientMetaData",
        "client_id": "clientId",
        "client_metadata_uri": "https://example.com/metadata",
        "client_id_scheme": "clientScheme",
        "nonce": "nonce",
        "scope": "scope",
        "response_mode": "responseMode",
        "state": "state"
    }
    """

    let jsonData = json.data(using: .utf8)!
    let decoder = JSONDecoder()

    let data = try decoder.decode(UnvalidatedRequestObject.self, from: jsonData)

    XCTAssertEqual(data.responseType, "code")
    XCTAssertEqual(data.responseUri, "https://example.com/response")
    XCTAssertEqual(data.redirectUri, "https://example.com/redirect")
    XCTAssertEqual(data.request, "request")
    XCTAssertEqual(data.requestUri, "https://example.com/request")
    XCTAssertEqual(data.clientMetaData, "clientMetaData")
    XCTAssertEqual(data.clientId, "clientId")
    XCTAssertEqual(data.clientMetadataUri, "https://example.com/metadata")
    XCTAssertEqual(data.clientIdScheme, "clientScheme")
    XCTAssertEqual(data.nonce, "nonce")
    XCTAssertEqual(data.scope, "scope")
    XCTAssertEqual(data.responseMode, "responseMode")
    XCTAssertEqual(data.state, "state")
  }

  func testInitFromURL() {
    let url = URL(string: "https://example.com?response_type=code&response_uri=https%3A%2F%2Fexample.com%2Fresponse&redirect_uri=https%3A%2F%2Fexample.com%2Fredirect&request=request&request_uri=https%3A%2F%2Fexample.com%2Frequest&client_metadata=clientMetaData&client_id=clientId&client_metadata_uri=https%3A%2F%2Fexample.com%2Fmetadata&client_id_scheme=clientScheme&nonce=nonce&scope=scope&response_mode=responseMode&state=state")!

    let data = UnvalidatedRequestObject(from: url)

    XCTAssertEqual(data?.responseType, "code")
    XCTAssertEqual(data?.responseUri, "https://example.com/response")
    XCTAssertEqual(data?.redirectUri, "https://example.com/redirect")
    XCTAssertEqual(data?.request, "request")
    XCTAssertEqual(data?.requestUri, "https://example.com/request")
    XCTAssertEqual(data?.clientMetaData, "clientMetaData")
    XCTAssertEqual(data?.clientId, "clientId")
    XCTAssertEqual(data?.clientMetadataUri, "https://example.com/metadata")
    XCTAssertEqual(data?.clientIdScheme, "clientScheme")
    XCTAssertEqual(data?.nonce, "nonce")
    XCTAssertEqual(data?.scope, "scope")
    XCTAssertEqual(data?.responseMode, "responseMode")
    XCTAssertEqual(data?.state, "state")
  }
}
