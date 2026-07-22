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
import JOSESwift
import X509
import SwiftyJSON

@testable import OpenID4VP

final class WRPRegistrationCertificateTests: XCTestCase {

  // MARK: - Test Constants

  /// A signed WRPRC JWT with valid signature
  static let signedWRPRCJwt = """
    eyJ4NWMiOlsiTUlJQlZUQ0IrNkFEQWdFQ0FnRUJNQW9HQ0NxR1NNNDlCQU1DTURReEZUQVRCZ05WQkFNTURGWmxjbWxtYVdWeUlFUmxkakVPTUF3R0ExVUVDZ3dGVG1selkza3hDekFKQmdOVkJBWVRBa1ZWTUI0WERUSTJNRGN5TVRFeE5UQTBNMW9YRFRJM01EY3lNVEV4TlRBME0xb3dOREVWTUJNR0ExVUVBd3dNVm1WeWFXWnBaWElnUkdWMk1RNHdEQVlEVlFRS0RBVk9hWE5qZVRFTE1Ba0dBMVVFQmhNQ1JWVXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUUt5L0hvMXpBSUYvREtmc3U2dkZ2MUh6OG5GcTVhSmVPd09JSGNoK3NRWHhlWDNuYk1DVnBRN1JyTGRIazlua3hSZkxMOVM0dVZzUTNUUHNrZlhuQzVNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNmUlkyajJoRUFMUENDM1Y2NUFDanZkS05hVFZaZHhQcGNvb1FTWEVFZFdRSWhBTXdCTG42NTh6cWZLV1YvSk1Ya2JCWDVMaVpjK1NRcHczdkxrMFNzMkFXbyJdLCJ0eXAiOiJyYy13cnArand0IiwiYWxnIjoiRVMyNTYifQ.eyJlbnRpdGxlbWVudHMiOlsiaHR0cHM6Ly91cmkuZXRzaS5vcmcvMTk0NzUvRW50aXRsZW1lbnQvU2VydmljZV9Qcm92aWRlciJdLCJzdWIiOiJMRUlFVS05ODc2NTQzMjEiLCJjb3VudHJ5IjoiRVUiLCJwb2xpY3lfaWQiOlsiMC40LjAuMTk0NzUuMy4xIl0sImNyZWRlbnRpYWxzIjpbeyJmb3JtYXQiOiJkYytzZC1qd3QiLCJtZXRhIjp7InZjdF92YWx1ZXMiOlsidXJuOmV1ZGk6cGlkOjEiXX0sImNsYWltIjpbeyJwYXRoIjpbImZhbWlseV9uYW1lIl19LHsicGF0aCI6WyJnaXZlbl9uYW1lIl19LHsicGF0aCI6WyJiaXJ0aGRhdGUiXX0seyJwYXRoIjpbImJpcnRoX2ZhbWlseV9uYW1lIl19LHsicGF0aCI6WyJiaXJ0aF9naXZlbl9uYW1lIl19LHsicGF0aCI6WyJwbGFjZV9vZl9iaXJ0aCIsImxvY2FsaXR5Il19LHsicGF0aCI6WyJhZGRyZXNzIiwiZm9ybWF0dGVkIl19LHsicGF0aCI6WyJhZGRyZXNzIiwiY291bnRyeSJdfSx7InBhdGgiOlsiYWRkcmVzcyIsInJlZ2lvbiJdfSx7InBhdGgiOlsiYWRkcmVzcyIsImxvY2FsaXR5Il19LHsicGF0aCI6WyJhZGRyZXNzIiwicG9zdGFsX2NvZGUiXX0seyJwYXRoIjpbImFkZHJlc3MiLCJzdHJlZXRfYWRkcmVzcyJdfSx7InBhdGgiOlsiYWRkcmVzcyIsImhvdXNlX251bWJlciJdfSx7InBhdGgiOlsic2V4Il19LHsicGF0aCI6WyJuYXRpb25hbGl0aWVzIixudWxsXX0seyJwYXRoIjpbImRhdGVfb2ZfaXNzdWFuY2UiXX0seyJwYXRoIjpbImRhdGVfb2ZfZXhwaXJ5Il19LHsicGF0aCI6WyJpc3N1aW5nX2F1dGhvcml0eSJdfSx7InBhdGgiOlsiZG9jdW1lbnRfbnVtYmVyIl19LHsicGF0aCI6WyJwZXJzb25hbF9hZG1pbmlzdHJhdGl2ZV9udW1iZXIiXX0seyJwYXRoIjpbImlzc3VpbmdfY291bnRyeSJdfSx7InBhdGgiOlsiaXNzdWluZ19qdXJpc2RpY3Rpb24iXX0seyJwYXRoIjpbInBpY3R1cmUiXX0seyJwYXRoIjpbImVtYWlsIl19LHsicGF0aCI6WyJwaG9uZV9udW1iZXIiXX1dfSx7ImZvcm1hdCI6Im1zb19tZG9jIiwibWV0YSI6eyJkb2N0eXBlX3ZhbHVlIjoiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEifSwiY2xhaW0iOlt7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJmYW1pbHlfbmFtZSJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJnaXZlbl9uYW1lIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImJpcnRoX2RhdGUiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwiZmFtaWx5X25hbWVfYmlydGgiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwiZ2l2ZW5fbmFtZV9iaXJ0aCJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJwbGFjZV9vZl9iaXJ0aCJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJyZXNpZGVudF9hZGRyZXNzIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsInJlc2lkZW50X2NvdW50cnkiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwicmVzaWRlbnRfc3RhdGUiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwicmVzaWRlbnRfY2l0eSJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJyZXNpZGVudF9wb3N0YWxfY29kZSJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJyZXNpZGVudF9zdHJlZXQiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwicmVzaWRlbnRfaG91c2VfbnVtYmVyIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsInNleCJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJuYXRpb25hbGl0eSJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJpc3N1YW5jZV9kYXRlIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImV4cGlyeV9kYXRlIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImlzc3VpbmdfYXV0aG9yaXR5Il19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImRvY3VtZW50X251bWJlciJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJwZXJzb25hbF9hZG1pbmlzdHJhdGl2ZV9udW1iZXIiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwiaXNzdWluZ19jb3VudHJ5Il19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImlzc3VpbmdfanVyaXNkaWN0aW9uIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsInBvcnRyYWl0Il19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImVtYWlsX2FkZHJlc3MiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwibW9iaWxlX3Bob25lX251bWJlciJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJ0cnVzdF9hbmNob3IiXX1dfV0sInB1cnBvc2UiOlt7ImxhbmciOiJlbiIsInZhbHVlIjoiUGVyc29uIGlkZW50aWZpY2F0aW9uIn1dLCJyZWdpc3RyeV91cmkiOiJodHRwczovL3JlZ2lzdHJ5LmV4YW1wbGUuZXUiLCJjZXJ0aWZpY2F0ZV9wb2xpY3kiOiJodHRwczovL2V4YW1wbGUuZXUvY2VydGlmaWNhdGUtcG9saWN5Iiwic3J2X2Rlc2NyaXB0aW9uIjpbeyJsYW5nIjoiZW4iLCJ2YWx1ZSI6IkFuIGltcGxlbWVudGF0aW9uIG9mIGEgY3JlZGVudGlhbCB2ZXJpZmllciBzZXJ2aWNlLCBhY2NvcmRpbmcgdG8gT3BlbklkNFZQIC0gdjEuMCJ9XSwic3VwcG9ydF91cmkiOiJodHRwczovL2Rldi52ZXJpZmllci1iYWNrZW5kLmV1ZGl3LmRldi9zdXBwb3J0Iiwic3VwZXJ2aXNvcnlfYXV0aG9yaXR5Ijp7ImVtYWlsIjoic3VwZXJ2aXNvcnlAYXV0aG9yaXR5LmV4YW1wbGUuZXUiLCJwaG9uZSI6Iis0OTMwMTIzNDU2NyIsInVyaSI6Imh0dHBzOi8vc3VwZXJ2aXNvcnkuYXV0aG9yaXR5LmV4YW1wbGUuZXUifSwicHJpdmFjeV9wb2xpY3kiOiJodHRwczovL2Rldi52ZXJpZmllci1iYWNrZW5kLmV1ZGl3LmRldi9wcml2YWN5IiwibmFtZSI6IlZlcmlmaWVyIERldiIsImluZm9fdXJpIjoiaHR0cHM6Ly9kZXYudmVyaWZpZXItYmFja2VuZC5ldWRpdy5kZXYiLCJzdWJfbG4iOiJOaXNjeSIsImlhdCI6MTc4NDYzNDY0Miwic3RhdHVzIjp7InN0YXR1c19saXN0Ijp7ImlkeCI6OTEwLCJ1cmkiOiJodHRwczovL2lzc3Vlci5ldWRpdy5kZXYvdG9rZW5fc3RhdHVzX2xpc3QvRVUvZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEvMjBlZjllOTgtODY3Ni00NWJjLTg5YmEtMTcwOGYwZjIxMjM5In19fQ.m9bmy_iWc4A2Ix7aDsfUEI4KFj88YtcwGoOH5q3NGGJ89Ipb88eq2muhnbqUxtoMeYOqJobWGQBqwtisb1T9dQ
    """

  /// An unsigned WRPRC JWT (no signature) - same header and payload
  static let unsignedWRPRCJwt = """
    eyJ4NWMiOlsiTUlJQlZUQ0IrNkFEQWdFQ0FnRUJNQW9HQ0NxR1NNNDlCQU1DTURReEZUQVRCZ05WQkFNTURGWmxjbWxtYVdWeUlFUmxkakVPTUF3R0ExVUVDZ3dGVG1selkza3hDekFKQmdOVkJBWVRBa1ZWTUI0WERUSTJNRGN5TVRFeE5UQTBNMW9YRFRJM01EY3lNVEV4TlRBME0xb3dOREVWTUJNR0ExVUVBd3dNVm1WeWFXWnBaWElnUkdWMk1RNHdEQVlEVlFRS0RBVk9hWE5qZVRFTE1Ba0dBMVVFQmhNQ1JWVXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUUt5L0hvMXpBSUYvREtmc3U2dkZ2MUh6OG5GcTVhSmVPd09JSGNoK3NRWHhlWDNuYk1DVnBRN1JyTGRIazlua3hSZkxMOVM0dVZzUTNUUHNrZlhuQzVNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNmUlkyajJoRUFMUENDM1Y2NUFDanZkS05hVFZaZHhQcGNvb1FTWEVFZFdRSWhBTXdCTG42NTh6cWZLV1YvSk1Ya2JCWDVMaVpjK1NRcHczdkxrMFNzMkFXbyJdLCJ0eXAiOiJyYy13cnArand0IiwiYWxnIjoiRVMyNTYifQ.eyJlbnRpdGxlbWVudHMiOlsiaHR0cHM6Ly91cmkuZXRzaS5vcmcvMTk0NzUvRW50aXRsZW1lbnQvU2VydmljZV9Qcm92aWRlciJdLCJzdWIiOiJMRUlFVS05ODc2NTQzMjEiLCJjb3VudHJ5IjoiRVUiLCJwb2xpY3lfaWQiOlsiMC40LjAuMTk0NzUuMy4xIl0sImNyZWRlbnRpYWxzIjpbeyJmb3JtYXQiOiJkYytzZC1qd3QiLCJtZXRhIjp7InZjdF92YWx1ZXMiOlsidXJuOmV1ZGk6cGlkOjEiXX0sImNsYWltIjpbeyJwYXRoIjpbImZhbWlseV9uYW1lIl19LHsicGF0aCI6WyJnaXZlbl9uYW1lIl19LHsicGF0aCI6WyJiaXJ0aGRhdGUiXX0seyJwYXRoIjpbImJpcnRoX2ZhbWlseV9uYW1lIl19LHsicGF0aCI6WyJiaXJ0aF9naXZlbl9uYW1lIl19LHsicGF0aCI6WyJwbGFjZV9vZl9iaXJ0aCIsImxvY2FsaXR5Il19LHsicGF0aCI6WyJhZGRyZXNzIiwiZm9ybWF0dGVkIl19LHsicGF0aCI6WyJhZGRyZXNzIiwiY291bnRyeSJdfSx7InBhdGgiOlsiYWRkcmVzcyIsInJlZ2lvbiJdfSx7InBhdGgiOlsiYWRkcmVzcyIsImxvY2FsaXR5Il19LHsicGF0aCI6WyJhZGRyZXNzIiwicG9zdGFsX2NvZGUiXX0seyJwYXRoIjpbImFkZHJlc3MiLCJzdHJlZXRfYWRkcmVzcyJdfSx7InBhdGgiOlsiYWRkcmVzcyIsImhvdXNlX251bWJlciJdfSx7InBhdGgiOlsic2V4Il19LHsicGF0aCI6WyJuYXRpb25hbGl0aWVzIixudWxsXX0seyJwYXRoIjpbImRhdGVfb2ZfaXNzdWFuY2UiXX0seyJwYXRoIjpbImRhdGVfb2ZfZXhwaXJ5Il19LHsicGF0aCI6WyJpc3N1aW5nX2F1dGhvcml0eSJdfSx7InBhdGgiOlsiZG9jdW1lbnRfbnVtYmVyIl19LHsicGF0aCI6WyJwZXJzb25hbF9hZG1pbmlzdHJhdGl2ZV9udW1iZXIiXX0seyJwYXRoIjpbImlzc3VpbmdfY291bnRyeSJdfSx7InBhdGgiOlsiaXNzdWluZ19qdXJpc2RpY3Rpb24iXX0seyJwYXRoIjpbInBpY3R1cmUiXX0seyJwYXRoIjpbImVtYWlsIl19LHsicGF0aCI6WyJwaG9uZV9udW1iZXIiXX1dfSx7ImZvcm1hdCI6Im1zb19tZG9jIiwibWV0YSI6eyJkb2N0eXBlX3ZhbHVlIjoiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEifSwiY2xhaW0iOlt7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJmYW1pbHlfbmFtZSJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJnaXZlbl9uYW1lIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImJpcnRoX2RhdGUiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwiZmFtaWx5X25hbWVfYmlydGgiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwiZ2l2ZW5fbmFtZV9iaXJ0aCJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJwbGFjZV9vZl9iaXJ0aCJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJyZXNpZGVudF9hZGRyZXNzIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsInJlc2lkZW50X2NvdW50cnkiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwicmVzaWRlbnRfc3RhdGUiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwicmVzaWRlbnRfY2l0eSJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJyZXNpZGVudF9wb3N0YWxfY29kZSJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJyZXNpZGVudF9zdHJlZXQiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwicmVzaWRlbnRfaG91c2VfbnVtYmVyIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsInNleCJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJuYXRpb25hbGl0eSJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJpc3N1YW5jZV9kYXRlIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImV4cGlyeV9kYXRlIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImlzc3VpbmdfYXV0aG9yaXR5Il19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImRvY3VtZW50X251bWJlciJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJwZXJzb25hbF9hZG1pbmlzdHJhdGl2ZV9udW1iZXIiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwiaXNzdWluZ19jb3VudHJ5Il19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImlzc3VpbmdfanVyaXNkaWN0aW9uIl19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsInBvcnRyYWl0Il19LHsicGF0aCI6WyJldS5ldXJvcGEuZWMuZXVkaS5waWQuMSIsImVtYWlsX2FkZHJlc3MiXX0seyJwYXRoIjpbImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwibW9iaWxlX3Bob25lX251bWJlciJdfSx7InBhdGgiOlsiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJ0cnVzdF9hbmNob3IiXX1dfV0sInB1cnBvc2UiOlt7ImxhbmciOiJlbiIsInZhbHVlIjoiUGVyc29uIGlkZW50aWZpY2F0aW9uIn1dLCJyZWdpc3RyeV91cmkiOiJodHRwczovL3JlZ2lzdHJ5LmV4YW1wbGUuZXUiLCJjZXJ0aWZpY2F0ZV9wb2xpY3kiOiJodHRwczovL2V4YW1wbGUuZXUvY2VydGlmaWNhdGUtcG9saWN5Iiwic3J2X2Rlc2NyaXB0aW9uIjpbeyJsYW5nIjoiZW4iLCJ2YWx1ZSI6IkFuIGltcGxlbWVudGF0aW9uIG9mIGEgY3JlZGVudGlhbCB2ZXJpZmllciBzZXJ2aWNlLCBhY2NvcmRpbmcgdG8gT3BlbklkNFZQIC0gdjEuMCJ9XSwic3VwcG9ydF91cmkiOiJodHRwczovL2Rldi52ZXJpZmllci1iYWNrZW5kLmV1ZGl3LmRldi9zdXBwb3J0Iiwic3VwZXJ2aXNvcnlfYXV0aG9yaXR5Ijp7ImVtYWlsIjoic3VwZXJ2aXNvcnlAYXV0aG9yaXR5LmV4YW1wbGUuZXUiLCJwaG9uZSI6Iis0OTMwMTIzNDU2NyIsInVyaSI6Imh0dHBzOi8vc3VwZXJ2aXNvcnkuYXV0aG9yaXR5LmV4YW1wbGUuZXUifSwicHJpdmFjeV9wb2xpY3kiOiJodHRwczovL2Rldi52ZXJpZmllci1iYWNrZW5kLmV1ZGl3LmRldi9wcml2YWN5IiwibmFtZSI6IlZlcmlmaWVyIERldiIsImluZm9fdXJpIjoiaHR0cHM6Ly9kZXYudmVyaWZpZXItYmFja2VuZC5ldWRpdy5kZXYiLCJzdWJfbG4iOiJOaXNjeSIsImlhdCI6MTc4NDYzNDY0Miwic3RhdHVzIjp7InN0YXR1c19saXN0Ijp7ImlkeCI6OTEwLCJ1cmkiOiJodHRwczovL2lzc3Vlci5ldWRpdy5kZXYvdG9rZW5fc3RhdHVzX2xpc3QvRVUvZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEvMjBlZjllOTgtODY3Ni00NWJjLTg5YmEtMTcwOGYwZjIxMjM5In19fQ.
    """

  // MARK: - Parsing Tests

  /// Tests that a valid signed WRPRC JWT can be parsed from verifier_info.
  func testParseSignedWRPRCFromVerifierInfo() throws {
    let jwt = Self.signedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let verifierInfo = VerifierInfo(
      format: OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC,
      data: JSON(stringLiteral: jwt),
      credentialIds: nil
    )

    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])

    XCTAssertNotNil(wrprc)
    XCTAssertEqual(wrprc?.jwt, jwt)
    XCTAssertNotNil(wrprc?.certificate)
    XCTAssertFalse(wrprc!.certificateChain.isEmpty)
  }

  /// Tests that an unsigned WRPRC JWT can be parsed (parsing doesn't verify signature).
  func testParseUnsignedWRPRCFromVerifierInfo() throws {
    let jwt = Self.unsignedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let verifierInfo = VerifierInfo(
      format: OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC,
      data: JSON(stringLiteral: jwt),
      credentialIds: nil
    )

    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])

    XCTAssertNotNil(wrprc)
    XCTAssertEqual(wrprc?.jwt, jwt)
    XCTAssertNotNil(wrprc?.certificate)
  }

  /// Tests that the JWT type header is correctly validated.
  func testWRPRCJwtTypeHeader() throws {
    let jwt = Self.signedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let jws = try JWS(compactSerialization: jwt)

    XCTAssertEqual(jws.header.typ, OpenId4VPSpec.WRPRC_JWT_TYPE)
    XCTAssertEqual(jws.header.typ, "rc-wrp+jwt")
  }

  /// Tests that an invalid JWT type header causes parsing to fail.
  func testInvalidJwtTypeHeaderFails() throws {
    // Take the valid signed JWT and modify the header to have wrong typ
    let originalJwt = Self.signedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let parts = originalJwt.split(separator: ".")
    guard parts.count == 3 else {
      XCTFail("Invalid JWT format")
      return
    }

    // Decode the original header
    guard let headerData = String(parts[0]).base64AnyDecodedData else {
      XCTFail("Failed to decode header")
      return
    }

    var headerJson = try JSONSerialization.jsonObject(with: headerData) as! [String: Any]
    headerJson["typ"] = "JWT"  // Change to invalid type

    // Re-encode header
    let newHeaderData = try JSONSerialization.data(withJSONObject: headerJson)
    let newHeaderBase64 = newHeaderData.base64URLEncodedString()

    // Create new JWT with modified header
    let invalidJwt = "\(newHeaderBase64).\(parts[1]).\(parts[2])"

    let verifierInfo = VerifierInfo(
      format: OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC,
      data: JSON(stringLiteral: invalidJwt),
      credentialIds: nil
    )

    XCTAssertThrowsError(try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])) { error in
      // The error should mention the invalid typ header
      let errorMessage = error.localizedDescription
      XCTAssertTrue(
        errorMessage.contains("typ") || errorMessage.contains("rc-wrp+jwt"),
        "Expected error about 'typ' header but got: \(errorMessage)"
      )
    }
  }

  // MARK: - Certificate Extraction Tests

  /// Tests that the certificate chain is correctly extracted from x5c header.
  func testCertificateChainExtraction() throws {
    let jwt = Self.signedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let verifierInfo = VerifierInfo(
      format: OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC,
      data: JSON(stringLiteral: jwt),
      credentialIds: nil
    )

    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])

    XCTAssertNotNil(wrprc)
    XCTAssertEqual(wrprc!.certificateChain.count, 1)  // Self-signed cert has 1 cert in chain
  }

  /// Tests that the leaf certificate properties can be accessed.
  func testLeafCertificateProperties() throws {
    let jwt = Self.signedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let verifierInfo = VerifierInfo(
      format: OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC,
      data: JSON(stringLiteral: jwt),
      credentialIds: nil
    )

    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])
    let cert = wrprc!.certificate

    // Check certificate subject contains expected values
    let subject = cert.subject.description
    XCTAssertTrue(subject.contains("Verifier Dev") || subject.contains("Niscy"))

    // Check certificate validity period
    XCTAssertNotNil(cert.notValidBefore)
    XCTAssertNotNil(cert.notValidAfter)
  }

  // MARK: - Signature Verification Tests

  /// Tests that signature verification succeeds for a validly signed WRPRC.
  func testSignatureVerificationSucceeds() throws {
    let jwt = Self.signedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let verifierInfo = VerifierInfo(
      format: OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC,
      data: JSON(stringLiteral: jwt),
      credentialIds: nil
    )

    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])!

    // Extract public key from certificate
    let publicKey = wrprc.certificate.publicKey
    let pem = try publicKey.serializeAsPEM().pemString

    // Get the JWS
    let jws = try JWS(compactSerialization: jwt)
    guard let algorithm = jws.header.algorithm else {
      XCTFail("No algorithm in JWT header")
      return
    }

    // Convert PEM to SecKey
    guard let secKey = KeyController.convertPEMToPublicKey(pem, algorithm: algorithm) else {
      XCTFail("Failed to convert PEM to SecKey")
      return
    }

    // Verify signature using JOSEController
    let joseController = JOSEController()
    let verified = try joseController.verify(jws: jws, publicKey: secKey, algorithm: algorithm)

    XCTAssertTrue(verified, "Signature verification should succeed for signed WRPRC")
  }

  /// Tests that signature verification fails for an unsigned/tampered WRPRC.
  func testSignatureVerificationFailsForUnsigned() throws {
    let jwt = Self.unsignedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let verifierInfo = VerifierInfo(
      format: OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC,
      data: JSON(stringLiteral: jwt),
      credentialIds: nil
    )

    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])!

    // Extract public key from certificate
    let publicKey = wrprc.certificate.publicKey
    let pem = try publicKey.serializeAsPEM().pemString

    // Get the JWS
    let jws = try JWS(compactSerialization: jwt)
    guard let algorithm = jws.header.algorithm else {
      XCTFail("No algorithm in JWT header")
      return
    }

    // Convert PEM to SecKey
    guard let secKey = KeyController.convertPEMToPublicKey(pem, algorithm: algorithm) else {
      XCTFail("Failed to convert PEM to SecKey")
      return
    }

    // Verify signature - should fail for unsigned JWT
    let joseController = JOSEController()
    let verified = (try? joseController.verify(jws: jws, publicKey: secKey, algorithm: algorithm)) ?? false

    XCTAssertFalse(verified, "Signature verification should fail for unsigned WRPRC")
  }

  // MARK: - Payload Content Tests

  /// Tests that the WRPRC payload contains expected claims.
  func testWRPRCPayloadContent() throws {
    let jwt = Self.signedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let parts = jwt.split(separator: ".")
    guard parts.count >= 2 else {
      XCTFail("Invalid JWT format")
      return
    }

    // Decode payload
    guard let payloadData = String(parts[1]).base64AnyDecodedData else {
      XCTFail("Failed to decode payload")
      return
    }

    let payload = try JSON(data: payloadData)

    // Verify expected claims
    XCTAssertEqual(payload["sub"].string, "LEIEU-987654321")
    XCTAssertEqual(payload["country"].string, "EU")
    XCTAssertEqual(payload["name"].string, "Verifier Dev")
    XCTAssertEqual(payload["sub_ln"].string, "Niscy")

    // Verify entitlements
    let entitlements = payload["entitlements"].arrayValue.compactMap { $0.string }
    XCTAssertTrue(entitlements.contains("https://uri.etsi.org/19475/Entitlement/Service_Provider"))

    // Verify policy_id
    let policyIds = payload["policy_id"].arrayValue.compactMap { $0.string }
    XCTAssertTrue(policyIds.contains("0.4.0.19475.3.1"))

    // Verify purpose
    let purposes = payload["purpose"].arrayValue
    XCTAssertFalse(purposes.isEmpty)
    XCTAssertEqual(purposes.first?["lang"].string, "en")
    XCTAssertEqual(purposes.first?["value"].string, "Person identification")

    // Verify credentials are defined (both sd-jwt and mso_mdoc)
    let credentials = payload["credentials"].arrayValue
    XCTAssertEqual(credentials.count, 2)

    let formats = credentials.compactMap { $0["format"].string }
    XCTAssertTrue(formats.contains("dc+sd-jwt"))
    XCTAssertTrue(formats.contains("mso_mdoc"))
  }

  /// Tests that WRPRC contains status information.
  func testWRPRCStatusInfo() throws {
    let jwt = Self.signedWRPRCJwt.trimmingCharacters(in: .whitespacesAndNewlines)
    let parts = jwt.split(separator: ".")
    guard parts.count >= 2,
          let payloadData = String(parts[1]).base64AnyDecodedData else {
      XCTFail("Failed to decode payload")
      return
    }

    let payload = try JSON(data: payloadData)

    // Verify status information
    let status = payload["status"]
    XCTAssertTrue(status.exists())

    let statusList = status["status_list"]
    XCTAssertTrue(statusList.exists())
    XCTAssertEqual(statusList["idx"].int, 910)
    XCTAssertTrue(statusList["uri"].string?.contains("token_status_list") ?? false)
  }

  // MARK: - Format Validation Tests

  /// Tests that verifier_info format must be "registration_cert".
  func testVerifierInfoFormatConstant() {
    XCTAssertEqual(OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC, "registration_cert")
  }

  /// Tests that JWT type constant is "rc-wrp+jwt".
  func testJwtTypeConstant() {
    XCTAssertEqual(OpenId4VPSpec.WRPRC_JWT_TYPE, "rc-wrp+jwt")
  }

  /// Tests that non-WRPRC format is ignored.
  func testNonWRPRCFormatReturnsNil() throws {
    let verifierInfo = VerifierInfo(
      format: "other_format",
      data: JSON(stringLiteral: Self.signedWRPRCJwt),
      credentialIds: nil
    )

    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])
    XCTAssertNil(wrprc)
  }

  /// Tests that nil verifier_info returns nil.
  func testNilVerifierInfoReturnsNil() throws {
    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: nil)
    XCTAssertNil(wrprc)
  }

  /// Tests that empty verifier_info returns nil.
  func testEmptyVerifierInfoReturnsNil() throws {
    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [])
    XCTAssertNil(wrprc)
  }

  // MARK: - Remote Fetch Tests

  /// Tests fetching and parsing a WRPRC from the EUDI verifier backend.
  func testFetchAndParseWRPRCFromRemote() async throws {
    // Fetch the registration certificate from the remote endpoint
    let (intendedUseId, registrationCertJwt) = try await TestHelpers.fetchIntendedUse()

    // Verify we got valid data
    XCTAssertFalse(intendedUseId.isEmpty, "Intended use ID should not be empty")
    XCTAssertFalse(registrationCertJwt.isEmpty, "Registration certificate JWT should not be empty")

    // Create verifier_info from the fetched JWT
    let verifierInfo = VerifierInfo(
      format: OpenId4VPSpec.VERIFIER_INFO_FORMAT_WRPRC,
      data: JSON(stringLiteral: registrationCertJwt),
      credentialIds: nil
    )

    // Parse the WRPRC
    let wrprc = try WRPRegistrationCertificate.from(verifierInfo: [verifierInfo])

    XCTAssertNotNil(wrprc, "WRPRC should be parsed successfully")
    XCTAssertNotNil(wrprc?.certificate, "Certificate should be extracted")
    XCTAssertFalse(wrprc!.certificateChain.isEmpty, "Certificate chain should not be empty")
    XCTAssertEqual(wrprc?.jwt, registrationCertJwt, "JWT should match")

    // Verify signature
    let publicKey = wrprc!.certificate.publicKey
    let pem = try publicKey.serializeAsPEM().pemString

    let jws = try JWS(compactSerialization: registrationCertJwt)
    guard let algorithm = jws.header.algorithm else {
      XCTFail("No algorithm in JWT header")
      return
    }

    guard let secKey = KeyController.convertPEMToPublicKey(pem, algorithm: algorithm) else {
      XCTFail("Failed to convert PEM to SecKey")
      return
    }

    let joseController = JOSEController()
    let verified = try joseController.verify(jws: jws, publicKey: secKey, algorithm: algorithm)

    XCTAssertTrue(verified, "Remote WRPRC signature should verify successfully")

    print("✓ Fetched and verified WRPRC for intended use: \(intendedUseId)")
  }
}
