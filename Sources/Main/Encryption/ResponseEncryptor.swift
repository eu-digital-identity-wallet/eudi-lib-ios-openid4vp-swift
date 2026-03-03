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

internal actor ResponseEncryptor {

  func encryptResponse(
    responseEncryptionSpecification: ResponseEncryptionSpecification,
    data: AuthorizationResponsePayload
  ) throws -> String {
    return try encrypt(
      responseEncryptionAlg: responseEncryptionSpecification.responseEncryptionAlg,
      responseEncryptionEnc: responseEncryptionSpecification.responseEncryptionEnc,
      keySet: responseEncryptionSpecification.clientKey,
      data: data
    ).compactSerializedString
  }
}

private extension ResponseEncryptor {

  func encrypt(
    responseEncryptionAlg: JWEAlgorithm,
    responseEncryptionEnc: JOSEEncryptionMethod,
    keySet: WebKeySet,
    data: AuthorizationResponsePayload
  ) throws -> JWE {

    let keyAndEncryptor = try keyAndEncryptor(
      jweAlgorithm: responseEncryptionAlg,
      encryptionMethod: responseEncryptionEnc,
      keySet: keySet
    )

    let parameters: [String: Any?] = [
      "alg": responseEncryptionAlg.name,
      "enc": responseEncryptionEnc.name,
      "kid": keyAndEncryptor.key.kid,
      "apv": data.nonce.base64urlEncode,
      "apu": data.apu
    ].filter { $0.value != nil }

    let header = try JWEHeader(parameters: parameters as [String: Any])

    let jwe = try JWE(
      header: header,
      payload: Payload(
        data.toDictionary().toThrowingJSONData()
      ),
      encrypter: keyAndEncryptor.encrypter
    )
    return jwe
  }

  func keyAndEncryptor(
    jweAlgorithm: JWEAlgorithm,
    encryptionMethod: JOSEEncryptionMethod,
    keySet: WebKeySet
  ) throws -> (key: WebKeySet.Key, encrypter: Encrypter) {

    let encrypters = try findEncrypters(
      jweAlgorithm: jweAlgorithm,
      encryptionMethod: encryptionMethod,
      keySet: keySet
    )
    if let firstKey = encrypters.keys.first, let firstValue = encrypters[firstKey] {
      return (key: firstKey, encrypter: firstValue)
    }
    throw ValidationError.validationError("Unable to create key/encryptor pair")
  }

  // swiftlint:disable line_length
  func createEncrypter(
    jweAlgorithm: JWEAlgorithm,
    encryptionMethod: JOSEEncryptionMethod,
    key: WebKeySet.Key
  ) throws -> Encrypter? {

    let data = try key.toDictionary().toThrowingJSONData()

    guard let keyAlgorithm: KeyManagementAlgorithm = .init(rawValue: jweAlgorithm.name) else {
      throw ValidationError.validationError("Create encrypter - Unknown key management algorithm")
    }

    guard let contentEncryptionAlgorithm: ContentEncryptionAlgorithm = .init(rawValue: encryptionMethod.name) else {
      throw ValidationError.validationError("Create encrypter - Unknown content encryption algorithm")
    }

    if JWEAlgorithm.Family.parse(.RSA).contains(jweAlgorithm) {
      let publicKey = try RSAPublicKey(data: data)
      let secKey: SecKey = try publicKey.converted(to: SecKey.self)
      return Encrypter(
        keyManagementAlgorithm: keyAlgorithm,
        contentEncryptionAlgorithm: contentEncryptionAlgorithm,
        encryptionKey: secKey
      )
    } else if JWEAlgorithm.Family.parse(.ECDH_ES).contains(jweAlgorithm) {
      let publicKey = try ECPublicKey(data: data)
      return Encrypter(
        keyManagementAlgorithm: keyAlgorithm,
        contentEncryptionAlgorithm: contentEncryptionAlgorithm,
        encryptionKey: publicKey
      )
    } else {
      throw ValidationError.validationError("JWE Algorithm should be of the RSA or ECDH family")
    }
  }

  func findEncrypters(
    jweAlgorithm: JWEAlgorithm,
    encryptionMethod: JOSEEncryptionMethod,
    keySet: WebKeySet
  ) throws -> [WebKeySet.Key: Encrypter] {
    func encrypter(for key: WebKeySet.Key) throws -> Encrypter? {
      return try createEncrypter(
        jweAlgorithm: jweAlgorithm,
        encryptionMethod: encryptionMethod, key: key
      )
    }

    return Dictionary(uniqueKeysWithValues: keySet.keys.compactMap { key in
      try? encrypter(for: key).map { (key, $0) }
    })
  }
}
