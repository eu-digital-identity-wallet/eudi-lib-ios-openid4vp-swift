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
import JOSESwift

@testable import OpenID4VP

/// Request Object encryption on `request_uri_method=post`: what the Wallet advertises,
/// and what it accepts back, per `EncryptionRequirement`.
final class RequestObjectEncryptionTests: DiXCTest {

  private let signedOnly = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ2ZXJpZmllciJ9.c2lnbmF0dXJl"
  private let undecryptableJwe = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSJ9..aXY.Y2lwaGVydGV4dA.dGFn"

  func testRequirementFlags() throws {
    let spec = try EncryptionRequirementSpecification(supportedEncryptionAlgorithm: .ECDH_ES, supportedEncryptionMethod: .A128GCM, ephemeralEncryptionKeyCurve: .P256)
    XCTAssertTrue(EncryptionRequirement.notRequired.isNotRequired)
    XCTAssertFalse(EncryptionRequirement.notRequired.isRequired)
    XCTAssertNil(EncryptionRequirement.notRequired.specification)

    let required = EncryptionRequirement.required(encryptionRequirementSpecification: spec)
    XCTAssertFalse(required.isNotRequired)
    XCTAssertTrue(required.isRequired)
    XCTAssertEqual(required.specification, spec)

    let supported = EncryptionRequirement.supported(encryptionRequirementSpecification: spec)
    XCTAssertFalse(supported.isNotRequired)
    XCTAssertFalse(supported.isRequired)
    XCTAssertEqual(supported.specification, spec)
  }

  func testSupportedOptionAdvertisesEncryptionLikeRequired() throws {
    XCTAssertNotNil(JARConfiguration.encryptionSupportedOption.supportedEncryption)
    XCTAssertEqual(
      JARConfiguration.encryptionSupportedOption.supportedEncryption,
      JARConfiguration.encryptionOption.supportedEncryption
    )
    XCTAssertNil(JARConfiguration.noEncryptionOption.supportedEncryption)

    let key = try KeyController.generateECDHPrivateKey()
    let metadata = walletMetaData(config: try makeConfig(jar: .encryptionSupportedOption), key: key)
    XCTAssertNotNil(metadata["jwks"]["keys"].array?.first)
    XCTAssertEqual(metadata["request_object_encryption_alg_values_supported"].arrayValue.map(\.stringValue), ["ECDH-ES"])

    let none = walletMetaData(config: try makeConfig(jar: .noEncryptionOption), key: key)
    XCTAssertNil(none["jwks"].dictionary)
  }

  func testSignedOnlyRequestObjectIsAcceptedUnlessEncryptionIsRequired() async throws {
    let spec = try EncryptionRequirementSpecification(supportedEncryptionAlgorithm: .ECDH_ES, supportedEncryptionMethod: .A128GCM, ephemeralEncryptionKeyCurve: .P256)
    let fetcher = try makeFetcher(jar: .encryptionSupportedOption)

    let supported = try await fetcher.decryptIfNeeded(
      config: fetcher.config, jwt: signedOnly, keys: nil,
      encryption: .supported(encryptionRequirementSpecification: spec)
    )
    XCTAssertEqual(supported, signedOnly)

    let notRequired = try await fetcher.decryptIfNeeded(
      config: fetcher.config, jwt: signedOnly, keys: nil, encryption: .notRequired
    )
    XCTAssertEqual(notRequired, signedOnly)

    do {
      _ = try await fetcher.decryptIfNeeded(
        config: fetcher.config, jwt: signedOnly, keys: nil,
        encryption: .required(encryptionRequirementSpecification: spec)
      )
      XCTFail("A signed-only Request Object must be rejected when encryption is required")
    } catch AuthorizationError.jwtDecryptionFailed {
    }
  }

  func testEncryptedRequestObjectNeverFallsThroughToTheSigningParser() async throws {
    let spec = try EncryptionRequirementSpecification(supportedEncryptionAlgorithm: .ECDH_ES, supportedEncryptionMethod: .A128GCM, ephemeralEncryptionKeyCurve: .P256)
    let fetcher = try makeFetcher(jar: .encryptionSupportedOption)

    // The Verifier encrypted but the Wallet offered no key: an error, not the raw JWE.
    do {
      _ = try await fetcher.decryptIfNeeded(
        config: fetcher.config, jwt: undecryptableJwe, keys: nil,
        encryption: .supported(encryptionRequirementSpecification: spec)
      )
      XCTFail("An encrypted Request Object without a wallet key must fail")
    } catch AuthorizationError.jwtDecryptionFailed {
    }

    // A JWE the key cannot open is an error too, even though encryption is optional.
    let key = try KeyController.generateECDHPrivateKey()
    let jwk = try ECPrivateKey(privateKey: key)
    do {
      _ = try await fetcher.decryptIfNeeded(
        config: fetcher.config, jwt: undecryptableJwe, keys: (key, jwk),
        encryption: .supported(encryptionRequirementSpecification: spec)
      )
      XCTFail("A JWE that cannot be decrypted must not be returned as if it were a JWS")
    } catch {
    }
  }

  // MARK: - Helpers

  private func makeConfig(jar: JARConfiguration) throws -> OpenId4VPConfiguration {
    let privateKey = try KeyController.generateRSAPrivateKey()
    let publicKey = try KeyController.generateRSAPublicKey(from: privateKey)
    let publicKeyJWK = try RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: ["alg": "RS256", "use": "sig", "kid": UUID().uuidString]
    )
    let keySet = try WebKeySet(["keys": [publicKeyJWK.jsonString()?.convertToDictionary()]])
    return OpenId4VPConfiguration(
      privateKey: privateKey,
      publicWebKeySet: keySet,
      supportedClientIdSchemes: [.redirectUri],
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: jar,
      vpConfiguration: .default(),
      responseEncryptionConfiguration: .default()
    )
  }

  private func makeFetcher(jar: JARConfiguration) throws -> RequestFetcher {
    RequestFetcher(
      config: try makeConfig(jar: jar),
      fetcher: Fetcher<String>(),
      poster: Poster()
    )
  }
}
