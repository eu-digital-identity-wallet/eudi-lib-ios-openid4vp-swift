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
import XCTest
import JOSESwift

@testable import OpenID4VP

final class OpenID4VPTests: DiXCTest {

  func preRegisteredWalletConfiguration() throws -> OpenId4VPConfiguration {

    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)

    let alg = JWSAlgorithm(.RS256)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])

    let keySet = try WebKeySet([
      "keys": [publicKeyJWK.jsonString()?.convertToDictionary()]
    ])

    return OpenId4VPConfiguration(
      privateKey: privateKey,
      publicWebKeySet: keySet,
      supportedClientIdSchemes: [
        .preregistered(clients: [
          "verifier-backend.eudiw.dev": .init(
            clientId: "verifier-backend.eudiw.dev",
            legalName: "verifier-backend.eudiw.dev",
            jarSigningAlg: JWSAlgorithm(.RS256),
            jwkSetSource: .passByValue(webKeys: .init(keys: [
              .init(
                kty: "RSA",
                use: "sig",
                kid: "6b011ae0-86cb-4732-9039-fb918875898c",
                iat: 1691502634,
                crv: "",
                x: "",
                y: "",
                exponent: "AQAB",
                modulus: "qT-f2yAL1pA-AFNYusDrkfJPZ9AGJT8-xfqszP90-i6wOd7vTf-OPtMjElZ6i2XpBJcbAX8ICjFn7Q2TeAyGeBieKRgXYd1ry18ae7bOu6lE_s7yg-O5PE4s1ZpTRl1W1RRcOo8ZICA0lGaucgn5eDMZqwBYyepIcndUlIWggeUJvekaZBsvBLe6RTEC_6OLiP-VZOu6F-jor69_J9Y5QzDGu3p27-LwcSpjy1i_cwDb9QzYqyPT3k72wmHIoHEgzVR32Y6E-LUSmJX7GZJ9MQNraf6ch-_Mg1pDZqlnSdK6XNLodU8YxelUIc9aAWKLxUFnSlUWjyqN-dDHBLgY9Q",
                alg: "RS256"
              )
            ]))
          ),
          "Verifier": .init(
            clientId: "Verifier",
            legalName: "Verifier",
            jarSigningAlg: JWSAlgorithm(.RS256),
            jwkSetSource: .passByValue(webKeys: .init(keys: [
              .init(
                kty: "RSA",
                use: "sig",
                kid: "6b011ae0-86cb-4732-9039-fb918875898c",
                iat: 1691502634,
                crv: "",
                x: "",
                y: "",
                exponent: "AQAB",
                modulus: "qT-f2yAL1pA-AFNYusDrkfJPZ9AGJT8-xfqszP90-i6wOd7vTf-OPtMjElZ6i2XpBJcbAX8ICjFn7Q2TeAyGeBieKRgXYd1ry18ae7bOu6lE_s7yg-O5PE4s1ZpTRl1W1RRcOo8ZICA0lGaucgn5eDMZqwBYyepIcndUlIWggeUJvekaZBsvBLe6RTEC_6OLiP-VZOu6F-jor69_J9Y5QzDGu3p27-LwcSpjy1i_cwDb9QzYqyPT3k72wmHIoHEgzVR32Y6E-LUSmJX7GZJ9MQNraf6ch-_Mg1pDZqlnSdK6XNLodU8YxelUIc9aAWKLxUFnSlUWjyqN-dDHBLgY9Q",
                alg: "RS256"
              )
            ]))
          )
        ])
      ],
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: .noEncryptionOption,
      vpConfiguration: VPConfiguration.default(),
      responseEncryptionConfiguration: .unsupported
    )
  }

  static func preRegisteredWalletConfigurationWithKnownClientID(
    _ clientId: String = "verifier-backend.eudiw.dev"
  ) throws -> OpenId4VPConfiguration {

    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)

    let alg = JWSAlgorithm(.RS256)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "alg": alg.name,
        "use": "sig",
        "kid": UUID().uuidString
      ])

    let keySet = try WebKeySet([
      "keys": [publicKeyJWK.jsonString()?.convertToDictionary()]
    ])

    return OpenId4VPConfiguration(
      privateKey: privateKey,
      publicWebKeySet: keySet,
      supportedClientIdSchemes: [
        .preregistered(clients: [
          clientId: .init(
            clientId: clientId,
            legalName: "Verifier",
            jarSigningAlg: JWSAlgorithm(.RS256),
            jwkSetSource: .passByValue(webKeys: .init(keys: [
              .init(
                kty: "RSA",
                use: "sig",
                kid: "6b011ae0-86cb-4732-9039-fb918875898c",
                iat: 1691502634,
                crv: "",
                x: "",
                y: "",
                exponent: "AQAB",
                modulus: "qT-f2yAL1pA-AFNYusDrkfJPZ9AGJT8-xfqszP90-i6wOd7vTf-OPtMjElZ6i2XpBJcbAX8ICjFn7Q2TeAyGeBieKRgXYd1ry18ae7bOu6lE_s7yg-O5PE4s1ZpTRl1W1RRcOo8ZICA0lGaucgn5eDMZqwBYyepIcndUlIWggeUJvekaZBsvBLe6RTEC_6OLiP-VZOu6F-jor69_J9Y5QzDGu3p27-LwcSpjy1i_cwDb9QzYqyPT3k72wmHIoHEgzVR32Y6E-LUSmJX7GZJ9MQNraf6ch-_Mg1pDZqlnSdK6XNLodU8YxelUIc9aAWKLxUFnSlUWjyqN-dDHBLgY9Q",
                alg: "RS256"
              )
            ]))
          )
        ])],
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: .noEncryptionOption,
      vpConfiguration: VPConfiguration.default(),
      responseEncryptionConfiguration: .unsupported
    )
  }

  // MARK: - Authorisation Request Testing

  func testAuthorize_WhenWalletConfigurationIsNil_ReturnsInvalidResolutionWithMissingConfig() async {
    let vp = OpenID4VP(walletConfiguration: nil)
    let url = URL(string: "https://example.com/valid-request")!
    let result = await vp.authorize(
      fetcher: Fetcher<String>(),
      poster: Poster(),
      url: url
    )

    switch result {
    case .invalidResolution(let error, let dispatchDetails):

      if case ValidationError.nonDispatchable(let innerError) = error {
        if case ValidationError.missingConfiguration = innerError {
          XCTAssertTrue(true)
        } else {
          XCTFail("Expected inner error to be missingConfiguration")
        }
      } else {
        XCTFail("Expected error to be nonDispatchable")
      }

      XCTAssertNil(dispatchDetails, "dispatchDetails should be nil")

    default:
      XCTFail("Expected invalidResolution but got \(result)")
    }
  }

  // MARK: - Invalid data Testing

  func testAuthorisationValidationGivenDataIsInvalid() async throws {

    let walletConfiguration = try Self.preRegisteredWalletConfigurationWithKnownClientID()

    let unvalidatedRequest = UnvalidatedRequest.make(
      from: TestsConstants.invalidUrl.absoluteString
    )

    let resolver = AuthorizationRequestResolver()
    let request = try await resolver.resolve(
      walletConfiguration: walletConfiguration,
      unvalidatedRequest: unvalidatedRequest.get(),
      fetcher: Fetcher<String>(),
      poster: Poster()
    )

    switch request {
    case .notSecured:
      XCTAssert(false)
    case .jwt:
      XCTAssert(false)
    case .invalidResolution:
      XCTAssert(true)
    }
  }

  func testSDKValidationResolutionGivenDataRequestObjectByReferenceIsNotFoundURL() async throws {

    let walletConfiguration = try preRegisteredWalletConfiguration()
    let unvalidatedRequest = UnvalidatedRequest.make(
      from: TestsConstants.requestExpiredUrl.absoluteString
    )

    let resolver = AuthorizationRequestResolver()

    do {
      _ = try await resolver.resolve(
        walletConfiguration: walletConfiguration,
        unvalidatedRequest: unvalidatedRequest.get(),
        fetcher: Fetcher<String>(),
        poster: Poster()
      )
    } catch _ as FetchError {
      XCTAssert(true)
    }
  }
}
