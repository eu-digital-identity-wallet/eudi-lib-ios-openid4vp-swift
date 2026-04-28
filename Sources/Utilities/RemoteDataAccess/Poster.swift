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

public enum PostError: Error {
  case invalidUrl
  case invalidResponse
  case networkError(Error)
  
  /**
   Provides a localized description of the post error.
   
   - Returns: A string describing the post error.
   */
  public var localizedDescription: String {
    switch self {
    case .invalidResponse:
      return "Inalid response"
    case .invalidUrl:
      return "Invalid URL"
    case .networkError(let error):
      return "Network Error: \(error.localizedDescription)"
    }
  }
}

public protocol Posting: Sendable {
  
  var session: Networking { get set }
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with the response data or an error.
   */
  func post<Response: Codable>(request: URLRequest) async -> Result<Response, PostError>
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with a success boolean (based on status code) or an error.
   */
  func check(key: String, request: URLRequest) async -> Result<(String, Bool), PostError>
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A String or an error.
   */
  func postString(request: URLRequest) async -> Result<String, PostError>
}

public struct Poster: Posting {
  
  public var session: Networking
  
  /**
   Initializes a Poster instance.
   */
  public init(
    session: Networking = URLSession.shared
  ) {
    self.session = session
  }
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with the response data or an error.
   */
  public func post<Response: Codable>(request: URLRequest) async -> Result<Response, PostError> {
    do {
      let (data, _) = try await self.session.data(for: request)
      let object = try JSONDecoder().decode(Response.self, from: data)
      
      return .success(object)
    } catch {
      return .failure(.networkError(error))
    }
  }
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A Result type with a success boolean (based on status code) or an error.
   */
  public func check(key: String, request: URLRequest) async -> Result<(String, Bool), PostError> {
    do {
      let (data, response) = try await session.data(for: request)
      let success = (response as? HTTPURLResponse)?
        .statusCode
        .isWithinRange(200...299) ?? false
      
      let description = success
      ? descriptionForKey(key, in: data)
      : errorDescription(in: data)
      
      return .success((description, success))
    } catch {
      return .failure(.networkError(error))
    }
  }
  
  /**
   Performs a POST request with the provided URLRequest.
   
   - Parameters:
   - request: The URLRequest to be used for the POST request.
   
   - Returns: A String or an error.
   */
  public func postString(request: URLRequest) async -> Result<String, PostError> {
    do {
      let (data, response) = try await self.session.data(for: request)
      let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
      if !statusCode.isWithinRange(200...299) {
        return .failure(.invalidResponse)
      }
      
      if let string = String(data: data, encoding: .utf8) {
        return .success(string)
      } else {
        return .failure(.invalidResponse)
      }
    } catch {
      return .failure(.networkError(error))
    }
  }
}

private extension Poster {
  private func descriptionForKey(_ key: String, in data: Data) -> String {
    // Avoid String -> Dict conversions; go straight from Data to [String: Any]
    guard
      let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
      let value = json[key] as? String
    else {
      return ""
    }
    return value
  }
  
  private func errorDescription(in data: Data) -> String {
    String(data: data, encoding: .utf8) ?? ""
  }
}
