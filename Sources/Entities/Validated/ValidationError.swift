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

indirect public enum ValidationError: AuthorizationRequestError, Equatable {
  case validationError(String)
  case unsupportedClientIdScheme(String?)
  case unsupportedResponseType(String?)
  case unsupportedResponseMode(String?)
  case invalidResponseType
  case noAuthorizationData
  case invalidAuthorizationData
  case invalidConfiguration
  case invalidClientMetadata
  case invalidJWTWebKeySet
  case missingRequiredField(String?)
  case invalidJwtPayload
  case invalidRequestUri(String?)
  case invalidRequest
  case invalidTransactionData(String)
  case invalidScope
  case walletUnavailable
  case conflictingData
  case notSupportedOperation
  case invalidFormat
  case unsupportedConsent
  case negativeConsent
  case clientIdMismatch(String?, String?)
  case invalidClientId
  case invalidJarmClientMetadata
  case invalidWalletConfiguration
  case unsupportedAlgorithm(String?)
  case unsupportedMethod(String?)
  case invalidKey
  case emptyValue
  case multipleQuerySources
  case invalidQuerySource
  case invalidUri
  case invalidRequestUriMethod
  case invalidUseOfBothRequestAndRequestUri
  case missingClientId
  case missingConfiguration
  case missingResponseType
  case missingNonce
  case nonDispatchable(ValidationError)
  case invalidJarmRequirement
  case invalidResponseEncryptionSpecification
  case invalidVerifierAttestationFormat
  case invalidVerifierAttestationCredentialIds
  case authorizationPolicyNotMet(PolicyViolation)

  // MARK: - RP Authentication Failures
  // These dedicated cases allow wallets to distinguish "RP cannot be trusted"
  // from "request is malformed" and display appropriate user-facing messages.

  /// The certificate chain could not be validated or trusted.
  case untrustedCertificateChain(String)
  /// The client_id was not found in the certificate's Subject Alternative Names.
  case clientIdNotInCertificateSAN(clientId: String, certificateSANs: [String])
  /// The client_id does not match the certificate's SHA-256 hash (x509_hash scheme).
  case clientIdCertificateHashMismatch(clientId: String, expectedHash: String)
  /// The request object (JAR) signature is invalid.
  case invalidRequestSignature(String)
  /// The pre-registered client was not found in wallet configuration.
  case preregisteredClientNotFound(clientId: String)
  /// Unsigned requests are only permitted for redirect_uri scheme.
  case unsignedRequestNotPermitted(scheme: String)
  /// No certificate was found in the JWT header (x5c).
  case missingCertificateInHeader
  /// The DID URL in the JWT kid header is invalid.
  case invalidDIDUrl(String)
  /// The DID in the JWT kid does not match the client_id.
  case didClientIdMismatch(kidDID: String, clientIdDID: String)
  /// Unable to resolve the public key from the DID URL.
  case publicKeyResolutionFailed(String)
  /// The response_uri/redirect_uri binding validation failed.
  case responseUriBindingFailed(String)
  /// The verifier attestation JWT is invalid or cannot be verified.
  case invalidVerifierAttestation(String)

  public var errorDescription: String? {
    switch self {
    case .validationError(let message):
      return "Validation Error \(message)"
    case .unsupportedClientIdScheme(let scheme):
      return ".unsupportedClientIdScheme \(scheme ?? "")"
    case .unsupportedResponseType(let type):
      return ".unsupportedResponseType \(String(describing: type))"
    case .unsupportedResponseMode(let mode):
      return ".unsupportedResponseMode \(mode ?? "")"
    case .invalidResponseType:
      return ""
    case .noAuthorizationData:
      return ".noAuthorizationData"
    case .invalidAuthorizationData:
      return "invalidAuthorizationData"
    case .invalidConfiguration:
      return "invalidConfiguration"
    case .invalidClientMetadata:
      return ".invalidClientMetadata"
    case .invalidJWTWebKeySet:
      return ".invalidJWTWebKeySet"
    case .missingRequiredField(let field):
      return ".missingRequiredField \(field ?? "")"
    case .invalidJwtPayload:
      return ".invalidJwtPayload"
    case .invalidRequestUri(let uri):
      return ".invalidRequestUri \(uri ?? "")"
    case .conflictingData:
      return ".conflictingData"
    case .invalidTransactionData(let message):
      return message
    case .invalidScope:
      return "Invalid scope"
    case .walletUnavailable:
      return "Wallet unavailable"
    case .invalidRequest:
      return ".invalidRequest"
    case .notSupportedOperation:
      return ".notSupportedOperation"
    case .invalidFormat:
      return ".invalidFormat"
    case .unsupportedConsent:
      return ".unsupportedConsent"
    case .negativeConsent:
      return ".negativeConsent"
    case .clientIdMismatch(let lhs, let rhs):
      return ".clientIdMismatch \(String(describing: lhs)) \(String(describing: rhs))"
    case .invalidClientId:
      return ".invalidClientId"
    case .invalidJarmClientMetadata:
      return ".invalidJarmClientMetadata"
    case .invalidWalletConfiguration:
      return ".invalidWalletConfiguration"
    case .unsupportedAlgorithm(let algorithm):
      return "unsupportedAlgorithm \(algorithm ?? "-")"
    case .unsupportedMethod(let method):
      return "unsupportedMethod \(method ?? "-")"
    case .invalidKey:
      return ".invalidKey"
    case .emptyValue:
      return ".emptyValue"
    case .multipleQuerySources:
      return ".multipleQuerySources"
    case .invalidQuerySource:
      return ".invalidQuerySource"
    case .invalidUri:
      return ".invalidUri"
    case .invalidRequestUriMethod:
      return ".invalidRequestUriMethod"
    case .invalidUseOfBothRequestAndRequestUri:
      return ".invalidUseOfBothRequestAndRequestUri"
    case .missingClientId:
      return ".missingClientId"
    case .missingConfiguration:
      return ".missingConfiguration"
    case .missingResponseType:
      return ".missingResponseType"
    case .missingNonce:
      return ".missingNonce"
    case .nonDispatchable(let error):
      return ".nonDispatchable \(error.localizedDescription)"
    case .invalidJarmRequirement:
      return ".invalidJarmRequirement"
    case .invalidVerifierAttestationFormat:
      return ".invalidVerifierAttestationFormat"
    case .invalidVerifierAttestationCredentialIds:
      return ".invalidVerifierAttestationCredentialIds"
    case .invalidResponseEncryptionSpecification:
      return ".invalidResponseEncryptionSpecification"
    case .authorizationPolicyNotMet(let violation):
      return ".authorizationPolicyNotMet \(violation.violation)"

    // RP Authentication Failures
    case .untrustedCertificateChain(let reason):
      return ".untrustedCertificateChain: \(reason)"
    case .clientIdNotInCertificateSAN(let clientId, let sans):
      return ".clientIdNotInCertificateSAN: '\(clientId)' not in \(sans)"
    case .clientIdCertificateHashMismatch(let clientId, let expectedHash):
      return ".clientIdCertificateHashMismatch: '\(clientId)' != '\(expectedHash)'"
    case .invalidRequestSignature(let reason):
      return ".invalidRequestSignature: \(reason)"
    case .preregisteredClientNotFound(let clientId):
      return ".preregisteredClientNotFound: '\(clientId)'"
    case .unsignedRequestNotPermitted(let scheme):
      return ".unsignedRequestNotPermitted: scheme '\(scheme)' requires signed JAR"
    case .missingCertificateInHeader:
      return ".missingCertificateInHeader"
    case .invalidDIDUrl(let url):
      return ".invalidDIDUrl: '\(url)'"
    case .didClientIdMismatch(let kidDID, let clientIdDID):
      return ".didClientIdMismatch: kid='\(kidDID)' != client_id='\(clientIdDID)'"
    case .publicKeyResolutionFailed(let reason):
      return ".publicKeyResolutionFailed: \(reason)"
    case .responseUriBindingFailed(let reason):
      return ".responseUriBindingFailed: \(reason)"
    case .invalidVerifierAttestation(let reason):
      return ".invalidVerifierAttestation: \(reason)"
    }
  }
}
