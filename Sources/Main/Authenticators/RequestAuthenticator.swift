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
import X509

internal struct AuthenticatedRequest: Sendable {
  let client: Client
  let requestObject: UnvalidatedRequestObject
}

internal struct JWTDecoder {
  
  static func decodeJWT(_ jwt: String) -> UnvalidatedRequestObject? {
    // JWS compact: header.payload.signature (we only need payload)
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count >= 2 else { return nil }
    
    guard let payloadData = String(parts[1]).base64AnyDecodedData else { return nil }
    
    do {
      let json = try JSON(data: payloadData)
      return mapJSONToRequestObject(json)
    } catch {
      return nil
    }
  }
  
  private static func mapJSONToRequestObject(_ json: JSON) -> UnvalidatedRequestObject {
    var dcqlQuery: JSON?
    let raw = JSON(json["dcql_query"])
    if raw != .null {
      dcqlQuery = raw
    }
    
    let transactionData = json["transaction_data"].arrayObject as? [String]
    let verifierInfo = json["verifier_info"].arrayValue
    
    return UnvalidatedRequestObject(
      responseType: json["response_type"].string,
      responseUri: json["response_uri"].string,
      redirectUri: json["redirect_uri"].string,
      dcqlQuery: dcqlQuery,
      request: json["request"].string,
      requestUri: json["request_uri"].string,
      requestUriMethod: json["request_uri_method"].string,
      clientMetaData: json["client_metadata"].dictionaryObject?.toJSONString(),
      clientId: json["client_id"].string,
      clientMetadataUri: json["client_metadata_uri"].string,
      clientIdScheme: json["client_id_scheme"].string,
      nonce: json["nonce"].string,
      scope: json["scope"].string,
      responseMode: json["response_mode"].string,
      state: json["state"].string,
      supportedAlgorithm: json["supported_algorithm"].string,
      transactionData: transactionData,
      verifierInfo: verifierInfo
    )
  }
}

internal actor RequestAuthenticator {
  
  let config: OpenId4VPConfiguration
  let clientAuthenticator: ClientAuthenticator
  
  init(config: OpenId4VPConfiguration, clientAuthenticator: ClientAuthenticator) {
    self.config = config
    self.clientAuthenticator = clientAuthenticator
  }
  
  func authenticate(fetchRequest: FetchedRequest) async throws -> AuthenticatedRequest {
    switch fetchRequest {
    case .plain(let requestObject):
      // For plain requests, URIs come from the request object
      let client = try await clientAuthenticator.authenticate(
        fetchRequest: fetchRequest,
        responseUri: requestObject.responseUri.flatMap { URL(string: $0) },
        redirectUri: requestObject.redirectUri.flatMap { URL(string: $0) }
      )
      return .init(client: client, requestObject: requestObject)

    case .jwtSecured(let clientId, let jwt):
      // Decode JWT first to extract response_uri/redirect_uri for binding validation
      guard let requestObject = JWTDecoder.decodeJWT(jwt) else {
        throw ValidationError.invalidRequest
      }

      let responseUri = requestObject.responseUri.flatMap { URL(string: $0) }
      let redirectUri = requestObject.redirectUri.flatMap { URL(string: $0) }

      // Authenticate client with response URI binding validation
      let client = try await clientAuthenticator.authenticate(
        fetchRequest: fetchRequest,
        responseUri: responseUri,
        redirectUri: redirectUri
      )

      // Verify JWT signature
      try await verify(
        validator: AccessValidator(
          walletOpenId4VPConfig: config,
          fetcher: Fetcher<WebKeySet>(
            session: config.session
          )
        ),
        token: jwt,
        clientId: clientId
      )

      return .init(client: client, requestObject: requestObject)
    }
  }
  
  func verify(
    validator: AccessValidating,
    token: JWTString,
    clientId: String?
  ) async throws {
    try await validator.validate(clientId: clientId, jwt: token)
  }
  
  // Create a VP token request
  func createVpToken(
    clientId: String,
    client: Client,
    nonce: String,
    requestObject: UnvalidatedRequestObject,
    clientMetaData: ClientMetaData.Validated
  ) async throws -> ValidatedRequestData {
    let formats: VpFormatsSupported = clientMetaData.vpFormatsSupported
    let querySource = try parseQuerySource(
      requestObject: requestObject
    )

    let verifierInfo = try requestObject.verifierInfo?.map({ json in
      try VerifierInfo.from(json: json)
    })

    // Validate WRPRC early if policy is configured
    let registrationCertificate = try await validateRegistrationCertificateIfNeeded(
      client: client,
      verifierInfo: verifierInfo
    )

    return .init(request: .init(
      querySource: querySource,
      clientMetaDataSource: nil,
      clientId: clientId,
      client: client,
      nonce: nonce,
      responseMode: requestObject.validResponseMode,
      requestUriMethod: .init(method: requestObject.requestUriMethod),
      state: requestObject.state,
      vpFormatsSupported: formats.values.isEmpty ? try VpFormatsSupported.default() : formats,
      transactionData: requestObject.transactionData,
      verifierInfo: verifierInfo,
      registrationCertificate: registrationCertificate
    ))
  }

  /// Extracts WRPRC if a RegistrationCertificatePolicy is configured.
  private func validateRegistrationCertificateIfNeeded(
    client: Client,
    verifierInfo: [VerifierInfo]?
  ) async throws -> String? {
    guard config.registrationCertificatePolicy != nil else {
      // No policy configured, skip WRPRC extraction
      return nil
    }

    // Extract WRPAC (WRP Authentication Certificate) from client
    guard extractWRPAC(from: client) != nil else {
      throw ValidationError.validationError(
        "WRPRC policy is configured but client does not have an authentication certificate (WRPAC)"
      )
    }

    // Extract WRPRC from verifier_info
    guard let verifierInfo = verifierInfo, !verifierInfo.isEmpty else {
      throw ValidationError.validationError(
        "WRPRC policy is configured but verifier_info is missing"
      )
    }

    let wrprcEntries = verifierInfo.filter {
      $0.format == OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC
    }

    // Per CIR 2024/2082, only one WRPRC is allowed
    guard wrprcEntries.count <= 1 else {
      throw ValidationError.validationError(
        "Multiple WRPRCs found in verifier_info. Per CIR 2024/2082, only one WRPRC is allowed."
      )
    }

    guard let wrprcInfo = wrprcEntries.first else {
      throw ValidationError.validationError(
        "WRPRC policy is configured but no WRPRC found in verifier_info"
      )
    }

    guard let rawValue = wrprcInfo.data.string else {
      throw ValidationError.validationError("WRPRC verifier_info data must be a string value")
    }

    return rawValue
  }

  /// Extracts the WRPAC (authentication certificate) from the client.
  private func extractWRPAC(from client: Client) -> Certificate? {
    switch client {
    case .x509Hash(_, let authenticationCertificate):
      return authenticationCertificate
    case .x509SanDns(_, let certificate):
      return certificate
    default:
      return nil
    }
  }
  
  func parseQuerySource(requestObject: UnvalidatedRequestObject) throws -> QuerySource {
    
    let hasDcqlQuery = requestObject.dcqlQuery?.exists() ?? false
    let querySourceCount = [hasDcqlQuery].filter { $0 }.count
    
    if querySourceCount > 1 {
      throw ValidationError.multipleQuerySources
    }
    
    if hasDcqlQuery, let dcqlQuery = requestObject.dcqlQuery {
      return .dcqlQuery(
        try .init(
          from: dcqlQuery
        )
      )
      
    } else {
      throw ValidationError.invalidQuerySource
    }
  }
}

package extension String {
  
  /// Normalizes a Base64 or Base64URL string (adds padding, swaps URL-safe chars).
  var normalizedBase64: String {
    // Trim whitespace/newlines just in case
    var s = self.trimmingCharacters(in: .whitespacesAndNewlines)
    
    // Convert Base64URL alphabet to standard Base64 if present
    if s.contains("-") || s.contains("_") {
      s = s.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    }
    
    // Pad to multiple of 4 characters
    let remainder = s.count % 4
    if remainder != 0 {
      s.append(String(repeating: "=", count: 4 - remainder))
    }
    return s
  }
  
  /// Decodes either Base64 or Base64URL.
  var base64AnyDecodedData: Data? {
    Data(base64Encoded: self.normalizedBase64, options: .ignoreUnknownCharacters)
  }
}
