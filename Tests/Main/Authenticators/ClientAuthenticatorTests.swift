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
import CryptoKit
import JOSESwift
import SwiftASN1
import X509

@testable import OpenID4VP

/// Regression coverage for the "doubled Client Identifier Prefix" bug.
///
/// For a verifier that identifies with a prefixed client_id (e.g. `x509_san_dns:host`),
/// `ClientAuthenticator` used to store the raw, still-prefixed client_id on the resolved
/// `Client`. `VerifierId.clientId` then re-prepended the scheme, yielding a doubled prefix
/// such as `x509_san_dns:x509_san_dns:host`. The fix passes `verifierId.originalClientId`
/// (the bare host) at the construction sites, so the composed id is single-prefixed.
final class ClientAuthenticatorTests: XCTestCase {

  // MARK: - Unsigned Request Validation Tests

  /// Verifies that unsigned (plain) requests are rejected for preregistered scheme.
  /// Per OpenID4VP spec, only redirect_uri scheme allows unsigned requests.
  func testUnsignedRequestRejectedForPreregisteredScheme() async throws {
    let clientId = "preregistered:trusted-bank"

    let config = Self.makeConfiguration(
      supportedClientIdSchemes: [
        .preregistered(clients: [
          clientId: .init(
            clientId: clientId,
            legalName: "Trusted Bank",
            jarSigningAlg: .init(.RS256),
            jwkSetSource: .passByValue(webKeys: .init(keys: []))
          )
        ])
      ]
    )

    let authenticator = ClientAuthenticator(config: config)

    // Create a plain (unsigned) request
    let plainRequest = UnvalidatedRequestObject(
      responseType: "vp_token",
      responseUri: "https://attacker.com/steal",
      redirectUri: nil,
      dcqlQuery: nil,
      request: nil,
      requestUri: nil,
      requestUriMethod: nil,
      clientMetaData: nil,
      clientId: clientId,
      clientMetadataUri: nil,
      clientIdScheme: nil,
      nonce: "test-nonce",
      scope: nil,
      responseMode: "direct_post",
      state: "test-state",
      supportedAlgorithm: nil,
      transactionData: nil,
      verifierInfo: nil
    )

    do {
      _ = try await authenticator.authenticate(
        fetchRequest: .plain(requestObject: plainRequest),
        responseUri: URL(string: "https://attacker.com/steal"),
        redirectUri: nil
      )
      XCTFail("Expected unsigned preregistered request to be rejected")
    } catch {
      // Expected: unsigned requests must be rejected for preregistered scheme
      XCTAssertTrue(
        error.localizedDescription.contains("Unsigned requests are only permitted for redirect_uri scheme"),
        "Error should indicate unsigned requests are not allowed: \(error)"
      )
    }
  }

  /// Verifies that unsigned requests ARE allowed for redirect_uri scheme when properly bound.
  func testUnsignedRequestAllowedForRedirectUriScheme() async throws {
    let responseUri = "https://verifier.example.com/callback"
    let clientId = "redirect_uri:\(responseUri)"

    let config = Self.makeConfiguration(
      supportedClientIdSchemes: [
        .redirectUri
      ]
    )

    let authenticator = ClientAuthenticator(config: config)

    // Create a plain (unsigned) request with matching client_id and response_uri
    let plainRequest = UnvalidatedRequestObject(
      responseType: "vp_token",
      responseUri: responseUri,
      redirectUri: nil,
      dcqlQuery: nil,
      request: nil,
      requestUri: nil,
      requestUriMethod: nil,
      clientMetaData: nil,
      clientId: clientId,
      clientMetadataUri: nil,
      clientIdScheme: nil,
      nonce: "test-nonce",
      scope: nil,
      responseMode: "direct_post",
      state: "test-state",
      supportedAlgorithm: nil,
      transactionData: nil,
      verifierInfo: nil
    )

    let client = try await authenticator.authenticate(
      fetchRequest: .plain(requestObject: plainRequest),
      responseUri: URL(string: responseUri),
      redirectUri: nil
    )

    // redirect_uri scheme should succeed for unsigned requests
    XCTAssertEqual(client.id.originalClientId, responseUri)
  }

  // MARK: - Doubled Prefix Regression Test

  /// Headline regression: a `x509_san_dns:<host>` request resolves to a `Client` whose
  /// composed id carries a single `x509_san_dns:` prefix (not a doubled one), and whose
  /// `originalClientId` is the bare host.
  func testResolvedX509SanDnsClientIdIsSinglePrefixed() async throws {

    let host = "verifier.example.com"
    let clientId = "\(OpenId4VPSpec.clientIdSchemeX509SanDns):\(host)"

    // Build a self-signed leaf certificate whose SAN dNSNames include the host,
    // then a compact JWS that carries that certificate in its `x5c` header and is
    // signed by the certificate's own key.
    let signingKey = P256.Signing.PrivateKey()
    let certificateBase64DER = try Self.makeSelfSignedCertificateBase64DER(
      dnsName: host,
      key: signingKey
    )
    let jwt = try Self.makeSignedJWT(
      x5c: [certificateBase64DER],
      signingKey: signingKey
    )

    let config = Self.makeConfiguration(
      supportedClientIdSchemes: [
        .x509SanDns(trust: { _ in true })
      ]
    )

    let authenticator = ClientAuthenticator(config: config)
    let client = try await authenticator.authenticate(
      fetchRequest: .jwtSecured(clientId: clientId, jwt: jwt),
      responseUri: URL(string: "https://\(host)/callback")!,
      redirectUri: nil
    )

    // The resolved client must expose the bare host as its original id ...
    XCTAssertEqual(client.id.originalClientId, host)
    // ... and a SINGLE-prefixed composed client id (the bug produced a doubled prefix).
    XCTAssertEqual(client.id.clientId, clientId)
    XCTAssertEqual(client.id.clientId, "x509_san_dns:\(host)")
    XCTAssertFalse(
      client.id.clientId.hasPrefix("x509_san_dns:x509_san_dns:"),
      "Resolved client id must not carry a doubled Client Identifier Prefix"
    )
  }
}

// MARK: - Helpers

private extension ClientAuthenticatorTests {

  /// Minimal `OpenId4VPConfiguration` sufficient to drive `ClientAuthenticator`.
  static func makeConfiguration(
    supportedClientIdSchemes: [SupportedClientIdPrefix]
  ) -> OpenId4VPConfiguration {
    let privateKey = try! KeyController.generateRSAPrivateKey()
    let publicKey = try! KeyController.generateRSAPublicKey(from: privateKey)
    let rsaJWK = try! RSAPublicKey(
      publicKey: publicKey,
      additionalParameters: [
        "use": "sig",
        "kid": UUID().uuidString,
        "alg": "RS256"
      ]
    )
    return OpenId4VPConfiguration(
      privateKey: try! KeyController.generateECDHPrivateKey(),
      publicWebKeySet: try! WebKeySet(jwk: rsaJWK),
      supportedClientIdSchemes: supportedClientIdSchemes,
      vpFormatsSupported: ClaimFormat.default(),
      jarConfiguration: .noEncryptionOption,
      vpConfiguration: .default(),
      responseEncryptionConfiguration: .unsupported
    )
  }

  /// Builds a self-signed P-256 leaf certificate with the supplied dNSName SAN and
  /// returns its standard-base64 DER encoding (the form `parseCertificates` consumes).
  static func makeSelfSignedCertificateBase64DER(
    dnsName: String,
    key: P256.Signing.PrivateKey
  ) throws -> String {
    let certificateKey = Certificate.PrivateKey(key)
    let name = try DistinguishedName {
      CommonName(dnsName)
    }
    let now = Date()
    let extensions = try Certificate.Extensions {
      Critical(
        BasicConstraints.isCertificateAuthority(maxPathLength: nil)
      )
      Critical(
        KeyUsage(digitalSignature: true, keyCertSign: true)
      )
      SubjectAlternativeNames([.dnsName(dnsName)])
    }
    let certificate = try Certificate(
      version: .v3,
      serialNumber: Certificate.SerialNumber(),
      publicKey: certificateKey.publicKey,
      notValidBefore: now.addingTimeInterval(-60 * 60),
      notValidAfter: now.addingTimeInterval(60 * 60 * 24 * 365),
      issuer: name,
      subject: name,
      signatureAlgorithm: .ecdsaWithSHA256,
      extensions: extensions,
      issuerPrivateKey: certificateKey
    )
    var serializer = DER.Serializer()
    try serializer.serialize(certificate)
    return Data(serializer.serializedBytes).base64EncodedString()
  }

  /// Produces a compact ES256 JWS carrying the supplied `x5c` chain in its header,
  /// signed by `signingKey`.
  static func makeSignedJWT(
    x5c: [String],
    signingKey: P256.Signing.PrivateKey
  ) throws -> String {
    let header = try JWSHeader(parameters: [
      "alg": "ES256",
      "typ": "JWT",
      "x5c": x5c
    ])
    let payload = Payload(try JSONSerialization.data(withJSONObject: [
      "iss": "issuer",
      "nonce": "nonce"
    ]))
    let secKey = try Self.makeSecKey(from: signingKey)
    guard let signer = Signer(signatureAlgorithm: .ES256, key: secKey) else {
      throw ValidationError.validationError("Unable to build signer")
    }
    let jws = try JWS(header: header, payload: payload, signer: signer)
    return jws.compactSerializedString
  }

  /// Bridges a CryptoKit P-256 private key into a `SecKey` (ANSI X9.63 layout
  /// `0x04 || x || y || d`) so it can be used with JOSESwift's `Signer`.
  static func makeSecKey(from key: P256.Signing.PrivateKey) throws -> SecKey {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits as String: 256
    ]
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(
      key.x963Representation as CFData,
      attributes as CFDictionary,
      &error
    ) else {
      throw ValidationError.validationError("Unable to build SecKey")
    }
    return secKey
  }
}
