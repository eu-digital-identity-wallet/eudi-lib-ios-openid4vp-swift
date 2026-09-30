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
import SwiftyJSON

public struct ResolvedRequestData: Sendable {
  public let request: VpTokenData

  public var dcql: DCQL? {
    switch request.presentationQuery {
    case .byDigitalCredentialsQuery(let dcql):
      return dcql
    }
  }

  public var client: Client {
    return request.client
  }

  /// WRP Registration Certificate (WRPRC) raw value extracted from `verifier_info`, if any.
  public var registrationCertificate: String? {
    return request.registrationCertificate
  }
}

public extension ResolvedRequestData {
  
  /// Initializes a `ResolvedRequestData` instance with the provided parameters.
  init(
    walletConfiguration: OpenId4VPConfiguration,
    vpConfiguration: VPConfiguration,
    validatedClientMetaData: ClientMetaData.Validated,
    validatedAuthorizationRequest: ValidatedRequestData
  ) async throws {

    let request = validatedAuthorizationRequest.request
    guard let commonFormats = VpFormatsSupported.common(request.vpFormatsSupported, vpConfiguration.vpFormatsSupported) else {
      throw ValidationError.invalidFormat
    }
    let presentationQuery = try await Self.resolvePresentationQuery(
      from: request.querySource
    )

    // Validate DCQL credential formats against wallet's supported formats
    if case .byDigitalCredentialsQuery(let dcql) = presentationQuery {
      try Self.validateDCQLFormats(dcql: dcql, walletFormats: vpConfiguration.vpFormatsSupported)
    }

    // Validate that DCQL query formats are supported by Verifier's vp_formats_supported
    try Self.validateDCQLFormatsAgainstVerifier(
      presentationQuery: presentationQuery,
      verifierFormatsSupported: validatedClientMetaData.vpFormatsSupported
    )

    self = .init(request: .init(
      presentationQuery: presentationQuery,
      clientMetaData: validatedClientMetaData,
      client: request.client,
      nonce: request.nonce,
      responseMode: request.responseMode,
      state: request.state,
      vpFormatsSupported: commonFormats,
      responseEncryptionSpecification: validatedClientMetaData.responseEncryptionSpecification,
      transactionData: try Self.parseTransactionData(
        transactionData: request.transactionData,
        vpConfiguration: vpConfiguration,
        presentationQuery: presentationQuery),
      verifierInfo: try VerifierInfo.validatedVerifierInfo(
        request.verifierInfo,
        presentationQuery: presentationQuery
      ),
      registrationCertificate: request.registrationCertificate
    ))
  }
  
  private static func lookupConfiguredQueries(
    scope: Scope,
    vpConfiguration: VPConfiguration
  ) throws -> PresentationQuery {
    let scopes = scopeItems(from: scope)
    if let dcql = scopes
      .compactMap({ vpConfiguration.knownDCQLQueriesPerScope[$0] })
      .first {
      return .byDigitalCredentialsQuery(dcql)
    } else {
      throw ResolvedAuthorisationError.invalidQueryDataForScope(scope)
    }
  }
  
  var legalName: String? {
    return request.client.legalName
  }
}

private extension ResolvedRequestData {

  /// Validates that all DCQL credential formats are supported by the wallet.
  /// Throws `ValidationError.invalidRequest` if any format is unsupported.
  static func validateDCQLFormats(dcql: DCQL, walletFormats: VpFormatsSupported) throws {
    let supportedFormatStrings = walletFormats.supportedFormatStrings()
    let queryFormats = Set(dcql.credentials.map { $0.format.format })
    let unsupportedFormats = queryFormats.subtracting(supportedFormatStrings)

    guard unsupportedFormats.isEmpty else {
      throw ValidationError.invalidRequest
    }
  }

  static func resolvePresentationQuery(
    from source: QuerySource
  ) async throws -> PresentationQuery {
    switch source {
    case .dcqlQuery(let dcql):
      return .byDigitalCredentialsQuery(dcql)

    default:
      throw ValidationError.validationError("Query source by scope is not supported for now")
    }
  }

  /// Validates that all formats used in a DCQL query are declared in the Verifier's vp_formats_supported.
  /// A Verifier that queries for mso_mdoc while advertising only dc+sd-jwt has sent an inconsistent request.
  static func validateDCQLFormatsAgainstVerifier(
    presentationQuery: PresentationQuery,
    verifierFormatsSupported: VpFormatsSupported
  ) throws {
    switch presentationQuery {
    case .byDigitalCredentialsQuery(let dcql):
      let verifierSupportedStrings = verifierFormatsSupported.supportedFormatStrings()
      for credential in dcql.credentials {
        let queryFormat = credential.format.format
        guard verifierSupportedStrings.contains(queryFormat) else {
          throw ValidationError.invalidRequest
        }
      }
    }
  }

  static func parseTransactionData(
    transactionData: [String]?,
    vpConfiguration: VPConfiguration,
    presentationQuery: PresentationQuery
  ) throws -> [TransactionData]? {
    /// If there is no transactionData in the request, return nil.
    guard let data = transactionData else { return nil }
    guard !data.isEmpty else {
      throw ValidationError.invalidTransactionData("transaction_data must not be empty")
    }
    
    /// For each item in data, attempt to parse and unwrap it.
    return try data.compactMap { item in
      try TransactionData.parse(
        item,
        supportedTypes: vpConfiguration.supportedTransactionDataTypes,
        presentationQuery: presentationQuery
      ).get()
    }
  }
}
