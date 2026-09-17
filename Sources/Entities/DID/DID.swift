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

public let DID_URL_SYNTAX = try? NSRegularExpression(pattern: "^did:[a-z0-9]+:(([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])*:)*([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])+(/(([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)*)*(\\?(((([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?(#(((([-A-Z._a-z0-9]|~)|%[0-9A-Fa-f][0-9A-Fa-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?$", options: [])
public let DID_SYNTAX = try? NSRegularExpression(pattern: "^did:[a-z0-9]+:(([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])*:)*([A-Z.a-z0-9]|-|_|%[0-9A-Fa-f][0-9A-Fa-f])+$", options: [])

public struct AbsoluteDIDUrl: Sendable {
  private let uri: URL

  private init(uri: URL) {
    self.uri = uri
  }

  public var string: String {
    return uri.absoluteString
  }

  /// Extracts the base DID (without fragment, query, or path) from this DID URL.
  public var did: DID? {
    // Remove fragment, query, and path to get the base DID
    var components = URLComponents(url: uri, resolvingAgainstBaseURL: false)
    components?.fragment = nil
    components?.query = nil
    components?.path = ""
    guard let baseString = components?.string else { return nil }
    return DID.parse(baseString)
  }

  /// The fragment portion of the DID URL (e.g., "key-1" from "did:example:123#key-1")
  public var fragment: String? {
    return uri.fragment
  }

  public static func parse(_ string: String) -> AbsoluteDIDUrl? {
    guard let regex = DID_URL_SYNTAX else {
      return nil
    }

    let parsed = DID.parse(string, regex: regex)
    if regex.matches(
      in: string,
      options: [],
      range: NSRange(
        location: 0, length: string.utf16.count
      )
    ).isEmpty == false && parsed != nil {
      if let url = URL(string: string) {
        return AbsoluteDIDUrl(uri: url)
      } else {
        return nil
      }
    } else {
      return nil
    }
  }
}

public struct DID: Sendable {

  public let uri: URL

  public init(uri: URL) {
    self.uri = uri
  }

  public var string: String {
    return uri.absoluteString
  }

  public static func parse(_ string: String, regex: NSRegularExpression? = DID_SYNTAX) -> DID? {
    guard
      let regex = regex,
      regex.matches(
        in: string,
        options: [],
        range: NSRange(
          location: 0,
          length: string.utf16.count
        )
      ).isEmpty == false,
      let url = URL(string: string)
    else {
      return nil
    }

    return DID(uri: url)
  }
}
