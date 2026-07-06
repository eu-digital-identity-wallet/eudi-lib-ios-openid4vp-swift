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
import XCTest

@testable import OpenID4VP

final class WebKeyResolverTests: DiXCTest {

  var webKeyResolver: WebKeyResolver!

  override func tearDown() {
    self.webKeyResolver = nil
    super.tearDown()
  }

  override func setUp() {
    self.webKeyResolver = WebKeyResolver()
  }

  func testResolve_WhenSourceIsNil_ThenReturnSuccessWithNilValue() async throws {

    let response = await self.webKeyResolver.resolve(source: nil)

    switch response {
    case .success(let webKeys):
      XCTAssertNil(webKeys)
    case .failure(let error):
      XCTFail(error.localizedDescription)
    }
  }

  func testResolve_WhenPassByValue_ThenReturnSuccessWebKeySet() async throws {

    let response = await self.webKeyResolver.resolve(source: .passByValue(webKeys: TestsConstants.webKeySet))

    switch response {
    case .success(let webKeys):
      XCTAssertEqual(webKeys?.keys.first, TestsConstants.webKeySet.keys.first)
    case .failure(let error):
      XCTFail(error.localizedDescription)
    }
  }
}
