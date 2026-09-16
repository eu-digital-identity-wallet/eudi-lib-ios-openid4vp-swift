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

@preconcurrency import XCTest
import JOSESwift

@testable import OpenID4VP

private let topPrivateKey = try! KeyController.generateRSAPrivateKey()
private let config: OpenId4VPConfiguration = .init(
  privateKey: topPrivateKey,
  publicWebKeySet: .init(keys: []),
  supportedClientIdSchemes: [
    .x509SanDns(trust: { _ in true })
  ],
  vpFormatsSupported: ClaimFormat.default(),
  jarConfiguration: .noEncryptionOption,
  vpConfiguration: VPConfiguration.default(),
  responseEncryptionConfiguration: .unsupported
)

final class VerifierAttestationIssuerTests: XCTestCase {

  override func setUpWithError() throws {
  }

  override func tearDownWithError() throws {
  }

  func testVerifierAttestationHappyPath() async throws {

    let clientId = "verifier_attestation:client-id"
    let issuer = VerifierAttestationIssuer()
    let verifier = await issuer.verifier!
    let jwt = try await issuer.attestation(
      clock: 10.0,
      clientId: clientId,
      redirectUris: [URL(string: "https://www.example.com")!],
      responseUris: [URL(string: "https://www.example.com")!]
    )

    let config = try await verifierAttestationWalletConfiguration(
      privateKey: issuer.algAndKey.key,
      verifier: verifier
    )

    let authenticator = RequestAuthenticator(
      config: config,
      clientAuthenticator: .init(config: config)
    )

    let client = try await authenticator.clientAuthenticator.getClient(
      clientId: clientId,
      jwt: jwt.compactSerializedString,
      responseUri: URL(string: "https://www.example.com")!,
      redirectUri: nil,
      config: config
    )

    switch client {
    case .attested(let client):
      XCTAssertEqual(client, "client-id")
    default:
      XCTAssert(false)
    }
  }

  func testVerifierAttestationInvalidIssuer() async throws {

    let clientId = "verifier_attestation:client-id"
    var issuer: VerifierAttestationIssuer

    issuer = VerifierAttestationIssuer()
    let verifier = await issuer.verifier!

    issuer = VerifierAttestationIssuer()
    let jwt = try await issuer.attestation(
      clock: 10.0,
      clientId: clientId,
      redirectUris: [URL(string: "https://www.example.com")!],
      responseUris: [URL(string: "https://www.example.com")!]
    )

    let config = try await verifierAttestationWalletConfiguration(
      privateKey: issuer.algAndKey.key,
      verifier: verifier
    )

    do {
      let authenticator = RequestAuthenticator(
        config: config,
        clientAuthenticator: .init(config: config)
      )

      // Attempt to call the async function
      _ = try await authenticator.clientAuthenticator.getClient(
        clientId: clientId,
        jwt: jwt.compactSerializedString,
        responseUri: URL(string: "https://www.example.com")!,
        redirectUri: nil,
        config: config
      )

      // If no error is thrown, this assertion will fail the test
      XCTFail("Expected error to be thrown, but no error was thrown.")
    } catch {
      guard let joseError = error as? JOSESwiftError else {
        XCTAssert(false)
        return
      }

      switch joseError {
      case .verifyingFailed:
        XCTAssert(true)
      default:
        XCTAssert(false)
      }
    }
  }
}

private extension VerifierAttestationIssuerTests {

  func verifierAttestationWalletConfiguration(
    privateKey: SecKey,
    verifier: Verifier
  ) throws -> OpenId4VPConfiguration {

    let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)

    let alg = JWSAlgorithm(.ES256)
    let publicKeyJWK = try ECPublicKey(
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
        .verifierAttestation(
          trust: verifier,
          clockSkew: 15.0
        )
      ],
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
