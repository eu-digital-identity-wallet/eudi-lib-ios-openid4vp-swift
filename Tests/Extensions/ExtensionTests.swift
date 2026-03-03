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
import XCTest

class ExtensionTests: XCTestCase {

  func testToJSONDataSuccess() {
    let testDictionary: [String: Any] = ["key1": "value1", "key2": 42]

    let jsonData = testDictionary.toJSONData()

    XCTAssertNotNil(jsonData, "json data should not be nil")

    do {
      if let jsonData = jsonData {
        let decodedDictionary = try JSONSerialization.jsonObject(with: jsonData, options: []) as? [String: Any]

        XCTAssertEqual(decodedDictionary?["key1"] as? String, "value1", "Decoded dictionary should match original")
        XCTAssertEqual(decodedDictionary?["key2"] as? Int, 42, "Decoded dictionary should match original")
      }
    } catch {
      XCTFail("Failed to decode JSON data: \(error)")
    }
  }

  func testToQueryItems() {
    let dictionary: [String: Any] = [
        "key1": "value1",
        "key2": NSNumber(value: 123),
        "key3": ["value3a", "value3b"]
    ]

    let queryItems = dictionary.toQueryItems()

    XCTAssertEqual(queryItems.count, 4)
    XCTAssertTrue(queryItems.contains { $0.name == "key1" && $0.value == "value1" })
    XCTAssertTrue(queryItems.contains { $0.name == "key2" && $0.value == "123" })
    XCTAssertTrue(queryItems.contains { $0.name == "key3" && $0.value == "value3a" })
    XCTAssertTrue(queryItems.contains { $0.name == "key3" && $0.value == "value3b" })
  }

  func testToDictionarySuccess() {

    struct TestStruct: Encodable {
      let name: String
      let age: Int
    }

    let testObject = TestStruct(name: "John Doe", age: 30)

    do {
      let dictionary = try testObject.toDictionary()

      XCTAssertEqual(dictionary["name"] as? String, "John Doe")
      XCTAssertEqual(dictionary["age"] as? Int, 30)
    } catch {
      XCTFail("Failed to convert to dictionary: \(error)")
    }
  }

  func testToDictionaryFailure() {
    // `JSONEncoder().encode(_:)` may throw an error if this object
    // isn't encodable (i.e., if it contains non-encodable properties)
    let testObject = URL(string: "https://example.com")!

    XCTAssertThrowsError(try testObject.toDictionary(), "Should throw an error when trying to convert non-Encodable object to dictionary") { error in
      let nsError = error as NSError
      XCTAssertEqual(nsError.domain, "ConversionError")
      XCTAssertEqual(nsError.code, 0)
      XCTAssertEqual(nsError.userInfo[NSLocalizedDescriptionKey] as? String, "Failed to convert Codable object to dictionary.")
    }
  }

  func testBase64URLEncode() {
    let testString = "Hello, World!"
    let expectedBase64URLEncoded = "SGVsbG8sIFdvcmxkIQ"

    XCTAssertEqual(testString.base64urlEncode, expectedBase64URLEncoded)
  }

  func testBase64URLEncodeWithSpecialCharacters() {
    let testString = "Hello+World/="
    let expectedBase64URLEncoded = "SGVsbG8rV29ybGQvPQ"

    XCTAssertEqual(testString.base64urlEncode, expectedBase64URLEncoded)
  }
}

class URLHostTests: XCTestCase {
  
  func testBasicHost() {
    let url = URL(string: "https://example.com")!
     
    XCTAssertEqual(url.host(includePercentEncoding: true), "example.com")
    XCTAssertEqual(url.host(includePercentEncoding: false), "example.com")
  }
  
  func testPunyHost() {
    let url = URL(string: "https://exämple.com")!
    
    XCTAssertEqual(url.host(includePercentEncoding: true), "xn--exmple-cua.com")
    XCTAssertEqual(url.host(includePercentEncoding: false), "xn--exmple-cua.com")
  }
  
  func testPercentEncodedPathNotAffectingHost() {
    let url = URL(string: "http://example.com/cameralife/2025-06%20Hello%20world/")!
    XCTAssertEqual(url.host(includePercentEncoding: true), "example.com")
    XCTAssertEqual(url.host(includePercentEncoding: false), "example.com")
  }
  
  func testInvalidURL() {
    let url = URL(string: "not a valid url")
    XCTAssertNil(url?.host(includePercentEncoding: true))
    XCTAssertNil(url?.host(includePercentEncoding: false))
  }
  
  func testURLWithNoHost() {
    // Relative path only, no host
    let url = URL(string: "/local/path/file.html")!
    XCTAssertNil(url.host(includePercentEncoding: true))
    XCTAssertNil(url.host(includePercentEncoding: false))
  }
}
