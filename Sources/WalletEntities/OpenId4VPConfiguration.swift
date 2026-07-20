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
@preconcurrency import Foundation

public typealias Issuer = URL

public struct OpenId4VPConfiguration: Sendable {
  public let privateKey: SecKey
  public let issuer: Issuer?
  public let publicWebKeySet: WebKeySet
  public let supportedClientIdSchemes: [SupportedClientIdPrefix]
  public let vpFormatsSupported: [ClaimFormat]
  public let jarConfiguration: JARConfiguration
  public let vpConfiguration: VPConfiguration
  public let errorDispatchPolicy: ErrorDispatchPolicy
  public let session: Networking
  public let responseEncryptionConfiguration: ResponseEncryptionConfiguration
  /// Optional policy for WRP Registration Certificate (WRPRC) validation.
  /// If provided, WRPRC validation is performed during request authorization.
  /// If nil, WRPRC validation is skipped.
  public let registrationCertificatePolicy: RegistrationCertificatePolicy?
  
  public static let SelfIssued = Issuer(string: "https://self-issued.me/v2")
  
  public init(
    privateKey: SecKey,
    issuer: Issuer? = Self.SelfIssued,
    publicWebKeySet: WebKeySet,
    supportedClientIdSchemes: [SupportedClientIdPrefix],
    vpFormatsSupported: [ClaimFormat] = ClaimFormat.default(),
    jarConfiguration: JARConfiguration = .noEncryptionOption,
    vpConfiguration: VPConfiguration = .default(),
    errorDispatchPolicy: ErrorDispatchPolicy = .onlyAuthenticatedClients,
    session: Networking = Self.walletSession,
    responseEncryptionConfiguration: ResponseEncryptionConfiguration,
    registrationCertificatePolicy: RegistrationCertificatePolicy? = nil
  ) {
    self.privateKey = privateKey
    self.issuer = issuer
    self.publicWebKeySet = publicWebKeySet
    self.supportedClientIdSchemes = supportedClientIdSchemes
    self.vpFormatsSupported = vpFormatsSupported
    self.jarConfiguration = jarConfiguration
    self.vpConfiguration = vpConfiguration
    self.errorDispatchPolicy = errorDispatchPolicy
    self.session = session
    self.responseEncryptionConfiguration = responseEncryptionConfiguration
    self.registrationCertificatePolicy = registrationCertificatePolicy
  }

  internal init() throws {
    privateKey = try KeyController.generateRSAPrivateKey()
    issuer = OpenId4VPConfiguration.SelfIssued
    publicWebKeySet = WebKeySet(keys: [])
    supportedClientIdSchemes = []
    vpFormatsSupported = []
    jarConfiguration = .noEncryptionOption
    vpConfiguration = .default()
    errorDispatchPolicy = .onlyAuthenticatedClients
    session = URLSession.shared
    responseEncryptionConfiguration = .unsupported
    registrationCertificatePolicy = nil
  }

  public static let walletSession: Networking = {
    /*let delegate = SelfSignedSessionDelegate()
     let configuration = URLSessionConfiguration.default
     return URLSession(
     configuration: configuration,
     delegate: delegate,
     delegateQueue: nil
     )*/
    URLSession.shared
  }()
}
