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
@testable import OpenID4VP

final class DCQLClaimValueTests: XCTestCase {
  func testProofOfAgeQueryPreservesBooleanRestriction() throws {
    let data = Data(#"{"credentials":[{"id":"age-over-18-mdoc","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.av.1"},"claims":[{"path":["eu.europa.ec.av.1","age_over_18"],"values":[true],"intent_to_retain":false}]}]}"#.utf8)
    let query = try JSONDecoder().decode(DCQL.self, from: data)
    XCTAssertEqual(query.credentials.first?.claims?.first?.values, [.boolean(true)])
    let encoded = try JSONEncoder().encode(query)
    XCTAssertEqual(try JSONDecoder().decode(DCQL.self, from: encoded), query)
  }

  func testMixedValuesRoundTripWithoutCoercion() throws {
    let data = Data(#"[true,false,18,-18,0,"true","18",""]"#.utf8)
    let values = try JSONDecoder().decode([DCQLClaimValue].self, from: data)
    XCTAssertEqual(values, [.boolean(true), .boolean(false), .integer(18), .integer(-18), .integer(0), .string("true"), .string("18"), .string("")])
    XCTAssertNotEqual(values[0], values[5])
    XCTAssertNotEqual(values[2], values[6])
    XCTAssertNotEqual(DCQLClaimValue.boolean(true), .integer(1))
    XCTAssertEqual(try JSONDecoder().decode([DCQLClaimValue].self, from: JSONEncoder().encode(values)), values)
  }

  func testIntegerBoundaries() throws {
    for value in [Int64.min, Int64.max] {
      let encoded = try JSONEncoder().encode(DCQLClaimValue.integer(value))
      XCTAssertEqual(try JSONDecoder().decode(DCQLClaimValue.self, from: encoded), .integer(value))
    }
  }

  func testUnsupportedValuesAreRejected() {
    for value in ["null", "1.5", "[]", "{}", "9223372036854775808"] {
      XCTAssertThrowsError(try JSONDecoder().decode(DCQLClaimValue.self, from: Data(value.utf8)))
    }
  }

  func testBuildersAcceptTypedAndStringLiteralValues() throws {
    let mdoc = try ClaimsQuery.mdoc(values: [true, 18, "true"], namespace: "eu.europa.ec.av.1", claimName: "age_over_18")
    XCTAssertEqual(mdoc.values, [.boolean(true), .integer(18), .string("true")])
    let sdJwt = try ClaimsQuery.sdJwtVc(path: .claim("age_over_18"), values: [true])
    XCTAssertEqual(sdJwt.values, [.boolean(true)])
    XCTAssertNil(try ClaimsQuery.mdoc(namespace: "eu.europa.ec.av.1", claimName: "age_over_18").values)
  }
}
