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

  /// Pre-validated WRP Registration Certificate (WRPRC) if available.
  public var registrationCertificate: WRPRegistrationCertificate? {
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
    let commonFormats = VpFormatsSupported.common(request.vpFormatsSupported, vpConfiguration.vpFormatsSupported) ?? request.vpFormatsSupported
    let presentationQuery = try await Self.resolvePresentationQuery(
      from: request.querySource
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
  
  static func parseTransactionData(
    transactionData: [String]?,
    vpConfiguration: VPConfiguration,
    presentationQuery: PresentationQuery
  ) throws -> [TransactionData]? {
    /// If there is no transactionData in the request, return nil.
    guard let data = transactionData else { return nil }
    
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
