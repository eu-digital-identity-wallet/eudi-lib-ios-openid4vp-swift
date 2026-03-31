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
import JOSESwift

public protocol AuthorizationRequestResolving: Sendable {
  func resolve(
    walletConfiguration: OpenId4VPConfiguration,
    unvalidatedRequest: UnvalidatedRequest,
    fetcher: any Fetching
  ) async -> AuthorizationRequest
}

public actor AuthorizationRequestResolver: AuthorizationRequestResolving {

  public init() {}

  public func resolve(
    walletConfiguration: OpenId4VPConfiguration,
    unvalidatedRequest: UnvalidatedRequest,
    fetcher: any Fetching
  ) async -> AuthorizationRequest {

    let clientMetaDataValidator: ClientMetaDataValidator = .init()
    let clientAuthenticator: ClientAuthenticator = .init(
      config: walletConfiguration
    )
    let requestAuthenticator: RequestAuthenticator = .init(
      config: walletConfiguration,
      clientAuthenticator: clientAuthenticator
    )

    let fetchedRequest: FetchedRequest
    do {
      fetchedRequest = try await fetchRequest(
        config: walletConfiguration,
        unvalidatedRequest: unvalidatedRequest,
        fetcher: fetcher
      )
    } catch {
      return .invalidResolution(
        error: ValidationError.validationError(error.localizedDescription),
        dispatchDetails: nil
      )
    }

    let authorizedRequest: AuthenticatedRequest
    do {
      authorizedRequest = try await authenticateRequest(
        requestAuthenticator: requestAuthenticator,
        config: walletConfiguration,
        fetchedRequest: fetchedRequest
      )
    } catch {
      let dispatchDetails: ErrorDispatchDetails? = switch walletConfiguration.errorDispatchPolicy {
      case .allClients:
        optionalDispatchDetails(
          config: walletConfiguration,
          fetchedRequest: fetchedRequest
        )
      case .onlyAuthenticatedClients:
        nil
      }
      return .invalidResolution(
        error: ValidationError.validationError(error.localizedDescription),
        dispatchDetails: dispatchDetails
      )
    }

    let validatedClientMetaData: ClientMetaData.Validated?
    let clientMetaData = authorizedRequest.requestObject.clientMetaData
    let responseMode = try? ResponseMode(
      authorizationRequestData: authorizedRequest.requestObject
    )
    
    // If clientMetaData is nil, we assume the client does not provide any metadata.
    if let clientMetaData {
      do {
        validatedClientMetaData = try await validateClientMetaData(
          validator: clientMetaDataValidator,
          clientMetaData: clientMetaData,
          responseMode: responseMode,
          responseEncryptionConfiguration: walletConfiguration.responseEncryptionConfiguration
        )
      } catch {
        return .invalidResolution(
          error: ValidationError.invalidClientMetadata,
          dispatchDetails: optionalDispatchDetails(
            config: walletConfiguration,
            fetchedRequest: fetchedRequest
          )
        )
      }
    } else {
      validatedClientMetaData = ClientMetaData.Validated(
        vpFormatsSupported: try! .default()
      )
    }

    guard let validatedClientMetaData = validatedClientMetaData else {
      return .invalidResolution(
        error: ValidationError.invalidClientMetadata,
        dispatchDetails: optionalDispatchDetails(
          config: walletConfiguration,
          fetchedRequest: fetchedRequest
        )
      )
    }

    guard
      let unvalidatedResponseType = authorizedRequest.requestObject.responseType,
      let responseType = ResponseType(rawValue: unvalidatedResponseType)
    else {
      return .invalidResolution(
        error: ValidationError.missingResponseType,
        dispatchDetails: optionalDispatchDetails(
          config: walletConfiguration,
          fetchedRequest: fetchedRequest
        )
      )
    }

    guard let nonce = authorizedRequest.requestObject.nonce else {
      return .invalidResolution(
        error: ValidationError.missingNonce,
        dispatchDetails: optionalDispatchDetails(
          config: walletConfiguration,
          fetchedRequest: fetchedRequest
        )
      )
    }

    let validated: ValidatedRequestData
    do {
      validated = try await createValidatedAuthorizationRequest(
        responseType: responseType,
        config: walletConfiguration,
        requestAuthenticator: requestAuthenticator,
        authorizedRequest: authorizedRequest,
        nonce: nonce,
        clientMetaData: validatedClientMetaData
      )
    } catch {
      return .invalidResolution(
        error: ValidationError.validationError(error.localizedDescription),
        dispatchDetails: optionalDispatchDetails(
          config: walletConfiguration,
          requestObject: authorizedRequest.requestObject
        )
      )
    }

    let resolved: ResolvedRequestData
    do {
      resolved = try await resolveRequest(
        config: walletConfiguration,
        validatedClientMetaData: validatedClientMetaData,
        validatedAuthorizationRequest: validated
      )
    } catch {
      return .invalidResolution(
        error: ValidationError.validationError(error.localizedDescription),
        dispatchDetails: optionalDispatchDetails(
          validatedRequestObject: validated,
          clientMetaData: validatedClientMetaData,
          config: walletConfiguration
        )
      )
    }

    return buildFinalRequest(
      fetchedRequest: fetchedRequest,
      resolved: resolved
    )
  }

  private func fetchRequest(
    config: OpenId4VPConfiguration,
    unvalidatedRequest: UnvalidatedRequest,
    fetcher: any Fetching
  ) async throws -> FetchedRequest {
    try await RequestFetcher(
      config: config,
      fetcher: fetcher
    ).fetchRequest(request: unvalidatedRequest)
  }

  private func authenticateRequest(
    requestAuthenticator: RequestAuthenticator,
    config: OpenId4VPConfiguration,
    fetchedRequest: FetchedRequest
  ) async throws -> AuthenticatedRequest {
    return try await requestAuthenticator.authenticate(
      fetchRequest: fetchedRequest
    )
  }

  private func validateClientMetaData(
    validator: ClientMetaDataValidator,
    clientMetaData: String?,
    responseMode: ResponseMode?,
    responseEncryptionConfiguration: ResponseEncryptionConfiguration
  ) async throws -> ClientMetaData.Validated? {
    guard let clientMetaData else {
      throw ValidationError.invalidClientMetadata
    }
    let metaData: ClientMetaData = try .init(
      metaDataString: clientMetaData
    )
    return try await validator.validate(
      clientMetaData: metaData,
      responseMode: responseMode,
      responseEncryptionConfiguration: responseEncryptionConfiguration
    )
  }

  private func createValidatedAuthorizationRequest(
    responseType: ResponseType,
    config: OpenId4VPConfiguration,
    requestAuthenticator: RequestAuthenticator,
    authorizedRequest: AuthenticatedRequest,
    nonce: String,
    clientMetaData: ClientMetaData.Validated
  ) async throws -> ValidatedRequestData {
    let clientId = authorizedRequest.client.id.originalClientId

    switch responseType {
    case .vpToken:
      return try await requestAuthenticator.createVpToken(
        clientId: clientId,
        client: authorizedRequest.client,
        nonce: nonce,
        requestObject: authorizedRequest.requestObject,
        clientMetaData: clientMetaData
      )
    default:
      throw ValidationError.unsupportedResponseType(responseType.rawValue)
    }
  }

  private func resolveRequest(
    config: OpenId4VPConfiguration,
    validatedClientMetaData: ClientMetaData.Validated,
    validatedAuthorizationRequest: ValidatedRequestData
  ) async throws -> ResolvedRequestData {
    try await .init(
      walletConfiguration: config,
      vpConfiguration: config.vpConfiguration,
      validatedClientMetaData: validatedClientMetaData,
      validatedAuthorizationRequest: validatedAuthorizationRequest
    )
  }

  private func buildFinalRequest(
    fetchedRequest: FetchedRequest,
    resolved: ResolvedRequestData
  ) -> AuthorizationRequest {
    switch fetchedRequest {
    case .plain:
      return .notSecured(data: resolved)
    case .jwtSecured:
      return .jwt(request: resolved)
    }
  }
}

internal extension AuthorizationRequestResolver {

  /**
   * Creates an invalid resolution for errors that manifested while trying to authenticate a Client.
   */
  func optionalDispatchDetails(
    config: OpenId4VPConfiguration,
    fetchedRequest: FetchedRequest
  ) -> ErrorDispatchDetails? {
    switch fetchedRequest {
    case .plain(let requestObject):
      return optionalDispatchDetails(
        config: config,
        requestObject: requestObject
      )
    case .jwtSecured(let clientId, let jwt):
      guard
        let jws = try? JWS(compactSerialization: jwt),
        let mode = jws.claimValue(forKey: "response_mode") as? String,
        let responseUri = jws.claimValue(forKey: "response_uri") as? String,
        let url = URL(string: responseUri)
      else {
        return nil
      }

      guard let responseMode: ResponseMode = switch mode {
      case "direct_post":
        ResponseMode.directPost(responseURI: url)
      case "direct_post.jwt":
        ResponseMode.directPostJWT(responseURI: url)
      default:
        nil
      } else {
        return nil
      }

      return ErrorDispatchDetails(
        responseMode: responseMode,
        nonce: jws.claimValue(forKey: "nonce") as? String,
        state: jws.claimValue(forKey: "state") as? String,
        clientId: try? VerifierId.parse(clientId: clientId).get()
      )
    }
  }

  func optionalDispatchDetails(
    config: OpenId4VPConfiguration,
    requestObject: UnvalidatedRequestObject
  ) -> ErrorDispatchDetails? {
    guard let responseMode = requestObject.validatedResponseMode else {
      return nil
    }

    return if !responseMode.isJarm() {
      ErrorDispatchDetails(
        responseMode: responseMode,
        nonce: requestObject.nonce,
        state: requestObject.state,
        clientId: requestObject.clientId.flatMap { id in
          let verifierId = VerifierId.parse(clientId: id)
          switch verifierId {
          case .success(let verifierId):
            return verifierId
          case .failure:
            return nil
          }
        }
      )
    } else {
      nil
    }
  }

  func optionalDispatchDetails(
    validatedRequestObject: ValidatedRequestData,
    clientMetaData: ClientMetaData.Validated?,
    config: OpenId4VPConfiguration
  ) -> ErrorDispatchDetails? {
    .init(
      responseMode: validatedRequestObject.responseMode,
      nonce: validatedRequestObject.nonce,
      state: validatedRequestObject.state,
      clientId: validatedRequestObject.clientId,
      responseEncryptionSpecification: clientMetaData?.responseEncryptionSpecification
    )
  }
}
