# OpenID4VP 

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

:heavy_exclamation_mark: **Repository Renamed**

This repository has been renamed to **eudi-lib-ios-openid4vp-swift**.
Please update your Git remotes:

```bash
git remote set-url origin https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vp-swift.git
```

All future development will take place in the renamed repository.


## Table of contents

* [Introduction](#introduction)
* [Disclaimer](#disclaimer)
* [Library implementation](#library-implementation)
* [Usage](#usage)
* [Dependencies](#dependencies)
* [License details](#license-details)

## Introduction

OpenID4VP is a Protocol that enables the presentation of Verifiable Credentials. It is built on top of OAuth 2.0 and supports multiple credential formats. This protocol allows for simple, secure, and developer-friendly credential presentation and can be used to support credential presentation and the issuance of access tokens for access to APIs based on Verifiable Credentials in the wallet

This is a swift library that supports 
[OpenId4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) protocols.
In particular, the library focus on the wallet's role using those two protocols with constraints
included in `ISO 23220-4` and `ISO-18013-7`.

OpenID Connect for Verifiable Presentations (OIDC4VP) enables the presentation of Verifiable Credentials using the OpenID Connect protocol.

## Features

| Feature                                                                                                                   | Coverage                                                                                                                               |
|---------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| Self-Issued OpenID Provider Authorization Requests                                                                        | ✅                                                                                                                                      |
| Client authentication prefixes                                                                                            | ✅ pre-registered, ✅ redirect_uri, ❌ openid_federation, ✅ decentralized_identifier, ✅ verifier_attestation, ✅ x509_san_dns, ✅ x509_hash |
| Attestation query dialect                                                                                                 | ✅ DCQL                                                                                                                                 |
| Signed/encrypted authorization requests (JAR)                                                                             | ✅                                                                                                                                      |
| Scoped authorization requests                                                                                             | ✅                                                                                                                                      |
| Request URI Methods                                                                                                       | ✅ GET, ✅ POST                                                                                                                          |
| Wallet metadata                                                                                                           | ✅                                                                                                                                      |
| [Dispatch positive and negative responses](#dispatch-authorization-response-to-verifier--rp)                              | ✅                                                                                                                                      |
| [Dispatch authorization error response to verifier when possible](#dispatch-authorization-error-response-to-verifier--rp) | ✅                                                                                                                                      |
| Encrypted authorization responses                                                                                         | ✅                                                                                                                                      |
| Response modes                                                                                                            | ✅ direct_post, ✅ direct_post.jwt, ✅ query, ✅ query.jwt, ✅ fragment, ✅ fragment.jwt                                                     |
| Transaction Data                                                                                                          | ✅                                                                                                                                      |
| Verifier Attestation JWT                                                                                                  | ✅                                                                                                                                      |
| Digital Credential API                                                                                                    | ❌                                                                                                                                      |


## Disclaimer

The released software is an initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short time-boxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend not putting this version of the software into production use.
-  Only the latest version of the software will be supported

## Library implementation

This is a Swift library, that conforms to OpenID for Verifiable Presentations (OpenID4VP) specification.
In particular, the library focuses on the wallet's role and in addition focuses on the 
usage of those two protocols as they are constrained by `ISO 23220-4` and `ISO-18013-7`

You can use this library to simplify the integration of OIDC4VP into your mobile applications.


## Usage

Entry point to the library is the class [OpenId4Vp](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vp-swift/blob/main/Sources/SiopOpenID4VP/OpenID4VP.swift).

You can add the library to your project using Swift Package Manager. [Releases](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vp-swift/releases)

```swift
import OpenID4VP

let walletConfig: OpenId4VPConfig = .init(...)

let openId4Vp = OpenID4V(walletConfiguration: walletConfig)
```


### Resolve an authorization request URI 

Wallet receives an OAUTH2 Authorization request, formed by the Verifier, that may represent either 

- an OpenID4VP authorization request

In the same device scenario the aforementioned authorization request reaches the wallet in terms of 
a deep link. Similarly, in the cross device scenario, the request would be obtained via scanning a QR Code.

Regardless of the scenario, a wallet must take the URI (of the deep link or the QR Code) that represents the 
authorization request and ask the SDK to validate the URI (that is to make sure that it represents one of the supported
requests mentioned aforementioned) and in addition gather from Verifier additional information that may be included by
reference.

The object that captures the aforementioned functionality is 
[ResolvedRequestData](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vp-swift/blob/main/Sources/Entities/Resolved/ResolvedRequestData.swift)


`async/await` version:

```swift
import OpenID4VP

let authorizationRequestUri : URL = ...

let sdk = OpenID4VP(walletConfiguration: ...)
let result = try await sdk.authorization(url: authorizationRequestUri)

switch result {
    ...
}
```

### Holder's consent, handling of a valid authorization request

After receiving a valid authorization wallet has to process it. Depending on the type of request this means

* For a OpenID4VP authorization request,
    * wallet should check whether holder has claims that can fulfill verifier's requirements
    * let the holder choose which claims will be presented to the verifier and form a `vp_token`

This functionality is a wallet concern and it is not supported directly by the library

### Build an authorization response

After collecting holder's consensus, wallet can use the library to form an appropriate response [AuthorizationResponse](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vp-swift/blob/main/Sources/Entities/AuthorisationRequest/AuthorizationResponse.swift).

```swift
import OpenID4VP

let resolved: ResolvedRequestData = ...
let jwt: JWTString = ... // provided by wallet
let consent: ClientConsent = .vpToken(...)
let response = try AuthorizationResponse(
      resolvedRequest: resolved,
      consent: consent
    )
```

### Dispatch authorization response to verifier / RP

The final step, of processing an authorization request, is to dispatch to the verifier the authorization response.
Depending on the `response_mode` that the verifier included in his authorization request, this is done either
* via a direct post (when `response_mode` is `direct_post` or `direct_post.jwt`), or
* by forming an appropriate `redirect_uri` (when response mode is `fragment` or `fragment.jwt`) _not supported yet_

Library tackles this dispatching via the Dispatcher class.

```swift
let authorizationResponse // from previous step
let dispatchResponse = dispatch.dispatch(response: authorizationResponse)
```
...or if something went wrong and you would like to dispatch an error and, the error is dispatchable:

```swift
switch result {
case .inValidResolution(let error, let details):
    let result: DispatchOutcome = try await sdk.dispatch(
        error: error,
        details: details
    )
    ...
```


## OpenId4VP features supported

## `response_mode`

A Wallet can take the form a web or mobile application.
OpenId4VP describes flows for both cases. Given that we are focusing on a mobile wallet we could
assume that `AuthorizationRequest` contains always a `response_mode`.

Library currently supports `response_mode`
* `direct_post`
* `direct_post.jwt`


## Supported Client ID Scheme

Library requires the presence of `client_id_scheme` with one of the following values:

- `pre-registered` assuming out of bound knowledge of verifier meta-data. A verifier may send an authorization request signed (JAR) or plain
- `x509-san-dns` where verifier must send the authorization request signed (JAR) using by a suitable X509 certificate
- `x509-hash` when the client Identifier prefix is x509_hash is a hash and matches the hash of the leaf certificate passed with the request.
- `decentralized_identifier` where verifier must send the authorization request signed (JAR) using a key resolvable via DID URL.
- `verifier_attestation` where verifier must send the authorization request signed (JAR), witch contains a verifier attestation JWT from a trusted issuer

### Retrieving Authorization Request 

According to OpenID4VP, when the `request_uri` parameter is included in the authorization request wallet must fetch the Authorization Request by following this URI.
In this case there are two methods to get the request, controlled by the `request_uri_method` comunicated by the verifier:
- Via an HTTP GET: In this case the Wallet MUST send the request to retrieve the Request Object using the HTTP GET method, as defined in [RFC9101](https://www.rfc-editor.org/rfc/rfc9101.html). 
- Via an HTTP POST: In this case a supporting Wallet MUST send the request using the HTTP POST method as detailed in [Section 5.8](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html#name-request-uri-method-post).
 
In the later case wallet can communicate its [metadata](Sources/WalletEntities/WalletMetaData.swift) to the verifier. Library supports both methods.

## Authorization Request encoding

OAUTH2 foresees that `AuthorizationRequest` is encoded as an HTTP GET
request which contains specific HTTP parameters.

OpenID4VP on the other hand foresees in addition, support to
[RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html#request_object) where
the aforementioned HTTP Get contains a JWT encoded `AuthorizationRequest`

Finally, `ISO-23220-4` requires the  usage of `RFC 9101`

Library supports obtaining the request object both by value (using `request` attribute) or
by reference (using `request_uri`)

## DCQL

The Verifier articulated requirements of the Verifiable Credential(s) that are requested, are provided using
the `dcql_query` parameter that contains a [DCQL Query](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6-2) JSON object.

According to OpenId4VP, verifier may pass the `dcql_query` either

* [by value](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1-2.6)
* [using scope](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.6)


## Client metadata in Authorization Request
According to [OpenId4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request) verifier may pass his metadata (client metadata) either
* by value

## Supported response types

Library currently supports `response_type` equal to `id_token` or `vp_token id_token`


## Dependencies

* Lint support: [SwiftLint](https://github.com/realm/SwiftLint.git)
* JWS, JWE, and JWK support: [JOSESwift](https://github.com/airsidemobile/JOSESwift.git)
* X.509 certificate support: [swift-certificates](https://github.com/apple/swift-certificates)
* JSON: [SwiftyJSON](https://github.com/SwiftyJSON/SwiftyJSON)
* ASN.1 types and DER serialization: [swift-asn1](https://github.com/apple/swift-asn1)

## License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
