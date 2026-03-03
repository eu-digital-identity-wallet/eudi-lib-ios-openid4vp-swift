# OpenID4VP Library Architecture

## High-Level Request/Response Flow

```mermaid
flowchart TD
    subgraph Input
        URL[URL / Deep Link / QR Code]
    end

    subgraph Resolution["Request Resolution"]
        UP[UnvalidatedRequest.make]
        ARR[AuthorizationRequestResolver]
        RF[RequestFetcher]
        RA[RequestAuthenticator]
        CA[ClientAuthenticator]
        CMR[ClientMetaDataResolver]
        CMV[ClientMetaDataValidator]
    end

    subgraph Output["Resolved Request"]
        AR{AuthorizationRequest}
        NS[notSecured]
        JWT[jwt]
        IR[invalidResolution]
    end

    URL --> UP
    UP --> ARR
    ARR --> RF
    RF --> RA
    RA --> CA
    CA --> CMR
    CMR --> CMV
    CMV --> AR
    AR --> NS
    AR --> JWT
    AR --> IR
```

## Response Dispatch Flow

```mermaid
flowchart TD
    subgraph Input["Response Building"]
        RRD[ResolvedRequestData]
        CC[ClientConsent]
        WC[OpenId4VPConfiguration]
    end

    subgraph Processing["Response Processing"]
        ARP[AuthorizationResponsePayload]
        RSE[ResponseSignerEncryptor]
        AR{AuthorizationResponse}
    end

    subgraph Modes["Response Modes"]
        DP[directPost]
        DPJ[directPostJwt]
        Q[query]
        QJ[queryJwt]
        F[fragment]
    end

    subgraph Dispatch["Dispatch"]
        D[Dispatcher]
        AS[AuthorisationService]
        HTTP[HTTP POST]
    end

    subgraph Result["Outcome"]
        DO{DispatchOutcome}
        ACC[accepted]
        REJ[rejected]
    end

    RRD --> ARP
    CC --> ARP
    WC --> ARP
    ARP --> RSE
    RSE --> AR
    AR --> DP
    AR --> DPJ
    AR --> Q
    AR --> QJ
    AR --> F
    DP --> D
    DPJ --> D
    Q --> D
    QJ --> D
    F --> D
    D --> AS
    AS --> HTTP
    HTTP --> DO
    DO --> ACC
    DO --> REJ
```

## Module Architecture

```mermaid
flowchart TD
    subgraph Public["Public API"]
        O4VP[OpenID4VP]
    end

    subgraph Core["Core Domain"]
        E[Entities]
        AR[AuthorizationRequest]
        ARESP[AuthorizationResponse]
        RRD[ResolvedRequestData]
        CM[ClientMetaData]
        VT[VpToken]
    end

    subgraph Main["Main Processing"]
        RES[Resolvers]
        AUTH[Authenticators]
        VAL[Validators]
        SVC[Services]
    end

    subgraph DCQL["DCQL Module"]
        DQ[DCQL Query]
        CQ[CredentialQuery]
        CLQ[ClaimsQuery]
    end

    subgraph Wallet["Wallet Config"]
        CFG[OpenId4VPConfiguration]
        WMD[WalletMetaData]
        JAR[JARConfiguration]
    end

    subgraph Utils["Utilities"]
        JWT[JWT / JOSE]
        NET[Networking]
        CRYPTO[Cryptography]
    end

    O4VP --> Core
    O4VP --> Main
    O4VP --> Wallet
    Core --> E
    E --> AR
    E --> ARESP
    E --> RRD
    E --> CM
    E --> VT
    Main --> RES
    Main --> AUTH
    Main --> VAL
    Main --> SVC
    RES --> Utils
    AUTH --> Utils
    SVC --> Utils
    DCQL --> DQ
    DQ --> CQ
    CQ --> CLQ
    Wallet --> CFG
    CFG --> WMD
    CFG --> JAR
```

## Client Authentication Schemes

```mermaid
flowchart LR
    subgraph Schemes["Client ID Schemes"]
        PR[pre-registered]
        X509D[x509_san_dns]
        X509H[x509_hash]
        DID[decentralized_identifier]
        VA[verifier_attestation]
        RU[redirect_uri]
    end

    subgraph Authenticators["Authentication"]
        CA[ClientAuthenticator]
        XCT[X509CertificateTrust]
        DIDL[DIDPublicKeyLookup]
        VAI[VerifierAttestationIssuer]
    end

    PR --> CA
    X509D --> XCT
    X509H --> XCT
    DID --> DIDL
    VA --> VAI
    RU --> CA
    XCT --> CA
    DIDL --> CA
    VAI --> CA
```

## JWT & Cryptography Flow

```mermaid
flowchart TD
    subgraph Input["Input"]
        REQ[JWT Request]
        RESP[Response Payload]
    end

    subgraph JOSE["JOSE Operations"]
        JC[JOSEController]
        JWS[JWS Signing]
        JWE[JWE Encryption]
        JWK[JWK Key Sets]
    end

    subgraph Keys["Key Management"]
        KC[KeyController]
        RSA[RSA Keys]
        EC[EC Keys]
        ECDH[ECDH Key Agreement]
    end

    subgraph Output["Output"]
        SJWT[Signed JWT]
        EJWT[Encrypted JWT]
    end

    REQ --> JC
    JC --> JWS
    JC --> JWE
    JC --> JWK
    KC --> RSA
    KC --> EC
    KC --> ECDH
    JWS --> KC
    JWE --> KC
    RESP --> JWS
    JWS --> SJWT
    SJWT --> JWE
    JWE --> EJWT
```

## Error Handling Flow

```mermaid
flowchart TD
    subgraph Errors["Error Types"]
        VE[ValidationError]
        AE[AuthorizationError]
        RAE[ResolvedAuthorisationError]
    end

    subgraph Policy["Dispatch Policy"]
        EDP[ErrorDispatchPolicy]
        DISP[dispatchIfPossible]
        NEVER[neverDispatch]
        ALWAYS[alwaysAttemptDispatch]
    end

    subgraph Dispatch["Error Dispatch"]
        ED[ErrorDispatcher]
        EDD[ErrorDispatchDetails]
    end

    subgraph Result["Outcome"]
        DO{DispatchOutcome}
        ACC[accepted]
        REJ[rejected]
    end

    VE --> EDP
    AE --> EDP
    RAE --> EDP
    EDP --> DISP
    EDP --> NEVER
    EDP --> ALWAYS
    DISP --> ED
    ALWAYS --> ED
    ED --> EDD
    EDD --> DO
    DO --> ACC
    DO --> REJ
```

## Dependency Graph

```mermaid
flowchart BT
    subgraph External["External Dependencies"]
        JOSE[JOSESwift]
        CERT[swift-certificates]
        ASN1[swift-asn1]
        ECC[BlueECC]
        CS[CryptoSwift]
        SJ[SwiftyJSON]
    end

    subgraph Internal["Internal Modules"]
        UTILS[Utilities]
        ENTITIES[Entities]
        MAIN[Main]
        WALLET[WalletEntities]
        DCQL[DCQL]
        API[OpenID4VP]
    end

    JOSE --> UTILS
    CERT --> UTILS
    ASN1 --> UTILS
    ECC --> UTILS
    CS --> UTILS
    SJ --> UTILS
    UTILS --> ENTITIES
    UTILS --> MAIN
    ENTITIES --> MAIN
    ENTITIES --> DCQL
    MAIN --> WALLET
    DCQL --> WALLET
    WALLET --> API
    MAIN --> API
```
