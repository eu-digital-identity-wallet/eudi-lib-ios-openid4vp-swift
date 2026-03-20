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
public struct OpenId4VPSpec {
  public static let clientIdSchemeSeparator: Character = ":"
  public static let clientIdSchemeDIDWithSeparator = "did:"
  public static let clientIdSchemePreRegistered = "pre-registered"
  public static let clientIdSchemeRedirectUri = "redirect_uri"
  public static let clientIdSchemeHttps = "https"
  public static let clientIdSchemeOpenidFederation = "openid_federation"
  public static let clientIdSchemeDid = "decentralized_identifier"
  public static let clientIdSchemeX509SanDns = "x509_san_dns"
  public static let clientIdSchemeX509Hash = "x509_hash"
  public static let clientIdSchemeVerifierAttestation = "verifier_attestation"

  public static let AUTHORIZATION_REQUEST_OBJECT_TYPE = "oauth-authz-req+jwt"

  public static let TRANSACTION_DATA_TYPE = "type"
  public static let TRANSACTION_DATA_CREDENTIAL_IDS = "credential_ids"
  public static let TRANSACTION_DATA_HASH_ALGORITHMS = "transaction_data_hashes_alg"

  public static let FORMAT_MSO_MDOC: String = "mso_mdoc"
  public static let FORMAT_MSO_MDOC_ZK: String = "mso_mdoc_zk"
  public static let FORMAT_SD_JWT_VC: String = "dc+sd-jwt"
  public static let FORMAT_W3C_SIGNED_JWT: String = "jwt_vc_json"

  public static let DCQL_CREDENTIALS: String = "credentials"
  public static let DCQL_CREDENTIAL_SETS: String = "credential_sets"

  public static let DCQL_ID: String = "id"
  public static let DCQL_FORMAT: String = "format"
  public static let DCQL_META: String = "meta"
  public static let DCQL_CLAIMS: String = "claims"
  public static let DCQL_CLAIM_SETS: String = "claim_sets"
  public static let DCQL_OPTIONS: String = "options"
  public static let DCQL_REQUIRED: String = "required"

  public static let DCQL_PATH: String = "path"
  public static let DCQL_VALUES: String = "values"
  public static let DCQL_SD_JWT_VC_VCT_VALUES: String = "vct_values"
  public static let DCQL_MSO_MDOC_DOCTYPE_VALUE: String = "doctype_value"
  public static let DCQL_MSO_MDOC_NAMESPACE: String = "namespace"
  public static let DCQL_MSO_MDOC_CLAIM_NAME: String = "claim_name"

  public static let DCQL_MULTIPLE: String = "multiple"
  public static let DCQL_TRUSTED_AUTHORITIES: String = "trusted_authorities"
  public static let DCQL_REQUIRE_CRYPTOGRAPHIC_HB: String = "require_cryptographic_holder_binding"
  
  public static let DCQL_MSO_MDOC_INTENT_TO_RETAIN: String = "intent_to_retain"
  public static let DCQL_TRUSTED_AUTHORITY_TYPE: String = "type"
  public static let DCQL_TRUSTED_AUTHORITY_VALUES: String = "values"
  public static let DCQL_TRUSTED_AUTHORITY_TYPE_AKI: String = "aki"
  public static let DCQL_TRUSTED_AUTHORITY_TYPE_ETSI_TL: String = "etsi_tl"
  public static let DCQL_TRUSTED_AUTHORITY_TYPE_OPENID_FEDERATION: String = "openid_federation"
}
