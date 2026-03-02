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
import CryptoKit

import XCTest
import JOSESwift

@testable import OpenID4VP

final class DirectPostTests: DiXCTest {
  
  func testValidDirectPostAuthorisationResponseGivenValidResolutionAndConsent() async throws {
    
    let validator = ClientMetaDataValidator()
    let metaData = try await validator.validate(
      clientMetaData: TestsConstants.testClientMetaData(),
      responseMode: nil,
      responseEncryptionConfiguration: .unsupported
    )
    
    // Obtain an id token resolution
    let resolved: ResolvedRequestData = .init(
      request: .init(
        presentationQuery:  .byDigitalCredentialsQuery(
          try! .init(credentials: [
            .init(
              id: .init(value: "query_0"),
              format: .init(format: "sd-jwt"),
              meta: [:]
            )
          ])
        ),
        clientMetaData: metaData,
        client: TestsConstants.testClient,
        nonce: TestsConstants.testNonce,
        responseMode: TestsConstants.testResponseMode,
        state: TestsConstants.generateRandomBase64String(),
        vpFormatsSupported: try .default(),
        responseEncryptionSpecification: nil
      )
    )
    
    // Obtain consent
    let consent: ClientConsent = .vpToken(vpContent: .dcql(verifiablePresentations: [try .init(value: "query_0") : [.generic(TestsConstants.cbor)]]))
    
    // Generate a direct post authorisation response
    let response = try? AuthorizationResponse(
      resolvedRequest: resolved,
      consent: consent,
      walletOpenId4VPConfig: nil
    )
    
    XCTAssertNotNil(response)
  }
  
  func testExpectedErrorGivenValidResolutionAndNegaticeConsent() async throws {
    
    let validator = ClientMetaDataValidator()
    let metaData = try await validator.validate(
      clientMetaData: TestsConstants.testClientMetaData(),
      responseMode: nil,
      responseEncryptionConfiguration: .unsupported
    )
    
    // Obtain an id token resolution
    let resolved: ResolvedRequestData = .init(
      request: .init(
        presentationQuery:  .byDigitalCredentialsQuery(
          try! .init(credentials: [
            .init(
              id: .init(value: "query_0"),
              format: .init(format: "sd-jwt"),
              meta: [:]
            )
          ])
        ),
        clientMetaData: metaData,
        client: TestsConstants.testClient,
        nonce: TestsConstants.testNonce,
        responseMode: TestsConstants.testResponseMode,
        state: TestsConstants.generateRandomBase64String(),
        vpFormatsSupported: try .default(),
        responseEncryptionSpecification: nil
      )
    )
    
    // Do not obtain consent
    let consent: ClientConsent = .negative(message: "user_cancelled")
    
    do {
      // Generate an error since consent was not given
      let response = try AuthorizationResponse(
        resolvedRequest: resolved,
        consent: consent,
        walletOpenId4VPConfig: nil
      )
      
      switch response {
      case .directPost(_, data: let data):
        switch data {
        case .noConsensusResponseData(state: let state, error: _):
          XCTAssert(true, state)
          return
        default: XCTAssert(false, "Incorrect response type")
        }
      default: XCTAssert(false, "Incorrect response type")
      }
    } catch ValidationError.negativeConsent {
      XCTAssert(true)
      return
    } catch {
      print(error.localizedDescription)
      XCTAssert(false)
    }
    
    XCTAssert(false)
  }
  
  func testSDKEndtoEndDirectPostVpTokenWithEncryption() async throws {
    
    let publicKeysURL = URL(string: "\(TestsConstants.host)/wallet/public-keys.json")!
    
    let rsaPrivateKey = try KeyController.generateRSAPrivateKey()
    let rsaPublicKey = try KeyController.generateRSAPublicKey(from: rsaPrivateKey)
    let privateKey = try KeyController.generateECDHPrivateKey()
    
    let rsaJWK = try RSAPublicKey(
      publicKey: rsaPublicKey,
      additionalParameters: [
        "use": "sig",
        "kid": UUID().uuidString,
        "alg": "RS256"
      ])
    
    let keySet = try WebKeySet(jwk: rsaJWK)
    
    let wallet: OpenId4VPConfiguration = .init(
      privateKey: privateKey,
      publicWebKeySet: keySet,
      supportedClientIdSchemes: [
        .preregistered(clients: [
          TestsConstants.testClientId: .init(
            clientId: TestsConstants.testClientId,
            legalName: "Verifier",
            jarSigningAlg: .init(.RS256),
            jwkSetSource: .fetchByReference(url: publicKeysURL)
          )
        ]),
        .x509SanDns(trust: { _ in
          return true
        }),
        .x509Hash(trust: { _ in
          return true
        })
      ],
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: .encryptionOption,
      vpConfiguration: .default(),
      responseEncryptionConfiguration: .default()
    )
    
    let sdk = OpenID4VP(walletConfiguration: wallet)
    /// To get this URL, visit https://dev.verifier.eudiw.dev/
    /// and  "Request for the entire PID"
    /// Copy the "Authenticate with wallet link", choose the value for "request_uri"
    /// Decode the URL online and paste it below in the url variable
    /// Note:  The url is only valid for one use
    let url = "#12"
    
    overrideDependencies()
    let result = await sdk.authorize(
      url: URL(
        string: url
      )!
    )
    
    switch result {
    case .jwt(request: let request):
      // Obtain consent
      let consent: ClientConsent = .vpToken(
        vpContent: .dcql(verifiablePresentations: [
          try QueryId(value: "query_0"): [.generic(TestsConstants.cbor)]
        ])
      )
      
      // Generate a direct post authorisation response
      let response = try? XCTUnwrap(AuthorizationResponse(
        resolvedRequest: request,
        consent: consent,
        walletOpenId4VPConfig: wallet
      ), "Expected item to be non-nil")
      
      // Dispatch
      XCTAssertNotNil(response)
      
      let result: DispatchOutcome = try await sdk.dispatch(
        session: NetworkingMock(json: .init([:]), statusCode: 200),
        response: response!
      )
      switch result {
      case .accepted:
        XCTAssert(true)
      default:
        XCTAssert(false)
      }
    default:
      XCTExpectFailure()
      XCTAssert(false)
    }
  }
  
  func testSDKEndtoEndDirectPostSdJwtVpTokenWithEncryption() async throws {
    
    let rsaPrivateKey = try KeyController.generateRSAPrivateKey()
    let rsaPublicKey = try KeyController.generateRSAPublicKey(from: rsaPrivateKey)
    let privateKey = try KeyController.generateECDHPrivateKey()
    
    let rsaJWK = try RSAPublicKey(
      publicKey: rsaPublicKey,
      additionalParameters: [
        "use": "sig",
        "kid": UUID().uuidString,
        "alg": "RS256"
      ])
    
    let keySet = try WebKeySet(jwk: rsaJWK)
    
    let wallet: OpenId4VPConfiguration = .init(
      privateKey: privateKey,
      publicWebKeySet: keySet,
      supportedClientIdSchemes: [
        .x509SanDns(trust: { _ in
          return true
        }),
        .x509Hash(trust: { _ in
          return true
        })
      ],
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: .encryptionOption,
      vpConfiguration: .default(),
      responseEncryptionConfiguration: .default()
    )
    
    let sdk = OpenID4VP(walletConfiguration: wallet)
    /// To get this URL, visit https://dev.verifier.eudiw.dev/
    /// and  "Request for the entire PID"
    /// Copy the "Authenticate with wallet link", choose the value for "request_uri"
    /// Decode the URL online and paste it below in the url variable
    /// Note:  The url is only valid for one use
    let url = "#13"
    
    overrideDependencies()
    let result = await sdk.authorize(
      url: URL(
        string: url
      )!
    )
    
    switch result {
    case .jwt(let resolved):
      let request = resolved.request
      let presentation: String? = TestsConstants.sdJwtPresentations(
        transactiondata: request.transactionData,
        clientID: request.client.id.originalClientId,
        nonce: request.nonce,
        useSha3: false
      )
      
      // Obtain consent
      let consent: ClientConsent = .vpToken(
        vpContent: .dcql(verifiablePresentations: [
          try QueryId(value: "query_0"): [.generic(presentation!)]
        ])
      )
      
      // Generate a direct post authorisation response
      let response = try? XCTUnwrap(AuthorizationResponse(
        resolvedRequest: resolved,
        consent: consent,
        walletOpenId4VPConfig: wallet
      ), "Expected item to be non-nil")
      
      // Dispatch
      XCTAssertNotNil(response)
      
      let result: DispatchOutcome = try await sdk.dispatch(response: response!)
      switch result {
      case .accepted:
        XCTAssert(true)
      default:
        XCTAssert(false)
      }
    default:
      XCTExpectFailure()
      XCTAssert(false)
    }
  }
}
