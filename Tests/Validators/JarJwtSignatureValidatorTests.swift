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

final class JarJwtSignatureValidatorTests: XCTestCase {

  var validator: AccessValidator!

  override func tearDown() {
    DependencyContainer.shared.removeAll()
    self.validator = nil
    super.tearDown()
  }

  override func setUp() {
    overrideDependencies()
  }

  func testJarJwtSignature_WhenInputsAreValid_ThenAssertSuccess() async throws {

    self.validator = try? XCTUnwrap(AccessValidator(
      walletOpenId4VPConfig: preRegisteredWalletConfiguration()
    ))

    let walletConfig = await validator.walletOpenId4VPConfig!
    let algorithm = SignatureAlgorithm(rawValue: walletConfig.publicWebKeySet.keys.first!.alg!)!

    let clientId = "Verifier"
    let scheme = "pre-registered"
    let type = "oauth-authz-req+jwt"

    let jws = try JWS(
      header: .init(
        parameters: [
          "alg": algorithm.rawValue,
          "typ": type
        ]
      ),
      payload: try Payload([
        "client_id": clientId,
        "client_id_scheme": scheme
      ].toThrowingJSONData()),
      signer: Signer(
        signatureAlgorithm: algorithm,
        key: walletConfig.privateKey
      )!
    )

    try await validator.validate(
      clientId: clientId,
      jwt: jws.compactSerializedString
    )

    XCTAssert(true)
  }

  func testJarJwtSignature_WhenInputsAreValidExceptClientId_ThenReturnFailure() async throws {

    self.validator = try? XCTUnwrap(AccessValidator(
      walletOpenId4VPConfig: preRegisteredWalletConfiguration()
    ))

    let walletConfig = await validator.walletOpenId4VPConfig!
    let algorithm = SignatureAlgorithm(rawValue: walletConfig.publicWebKeySet.keys.first!.alg!)!

    let clientId = "Verifier"
    let scheme = "pre-registered"
    
    let jws = try JWS(
      header: .init(parameters: [
        "alg": algorithm.rawValue,
        "typ": "oauth-authz-req+jwt"
      ]),
      payload: try Payload([
        "client_id": "\(scheme):\(clientId)"
      ].toThrowingJSONData()),
      signer: Signer(
        signatureAlgorithm: algorithm,
        key: walletConfig.privateKey
      )!
    )

    do {
      try await validator.validate(
        clientId: "\(scheme):\(clientId)",
        jwt: jws.compactSerializedString
      )
    } catch {
      XCTAssert(false)
      return
    }

    XCTAssert(true)
  }

  func testJarJwtSignature_WhenInputsAreValidWithoutPregistered_ThenAssertSuccess() async throws {

    self.validator = try? XCTUnwrap(AccessValidator(
      walletOpenId4VPConfig: iso509WalletConfiguration()
    ))

    let walletConfig = await validator.walletOpenId4VPConfig!
    let algorithm = SignatureAlgorithm(rawValue: walletConfig.publicWebKeySet.keys.first!.alg!)!

    let clientId = "Verifier"
    let scheme = "pre-registered"
    
    let jws = try JWS(
      header: .init(parameters: [
        "alg": algorithm.rawValue,
        "typ": "oauth-authz-req+jwt"
      ]),
      payload: try Payload([
        "client_id": "\(scheme):\(clientId)"
      ].toThrowingJSONData()),
      signer: Signer(
        signatureAlgorithm: algorithm,
        key: walletConfig.privateKey
      )!
    )

    try await validator.validate(
      clientId: "\(scheme):\(clientId)",
      jwt: jws.compactSerializedString
    )

    XCTAssert(true)
  }
}

private extension JarJwtSignatureValidatorTests {

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
          "Verifier": .init(
            clientId: "Verifier",
            legalName: "Verifier",
            jarSigningAlg: JWSAlgorithm(.RS256),
            jwkSetSource: .passByValue(webKeys: .init(keys: keySet.keys))
          )
        ])],
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: .noEncryptionOption,
      vpConfiguration: VPConfiguration.default(),
      responseEncryptionConfiguration: .unsupported
    )
  }

  func iso509WalletConfiguration() throws -> OpenId4VPConfiguration {

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
          "Verifier": .init(
            clientId: "Verifier",
            legalName: "Verifier",
            jarSigningAlg: JWSAlgorithm(.RS256),
            jwkSetSource: .passByValue(webKeys: .init(keys: keySet.keys))
          )
        ])],
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: .noEncryptionOption,
      vpConfiguration: VPConfiguration.default(),
      responseEncryptionConfiguration: .unsupported
    )
  }

  func overrideDependencies() {
    DependencyContainer.shared.register(type: Reporting.self, dependency: {
      Reporter()
    })
  }
}
