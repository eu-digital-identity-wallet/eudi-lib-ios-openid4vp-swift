// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "OpenID4VP",
  platforms: [.iOS(.v15), .macOS(.v12)],
  products: [
    .library(
      name: "OpenID4VP",
      targets: ["OpenID4VP"])
  ],
  dependencies: [
    .package(
      url: "https://github.com/airsidemobile/JOSESwift.git",
      from: "3.0.0"
    ),
    .package(
      url: "https://github.com/apple/swift-certificates.git",
      .upToNextMajor(from: "1.15.0")
    ),
    .package(
      url: "https://github.com/apple/swift-asn1.git",
      .upToNextMajor(from: "1.5.0")
    ),
    .package(
      url: "https://github.com/krzyzanowskim/CryptoSwift.git",
      from: "1.8.4"
    ),
    .package(
      url: "https://github.com/SwiftyJSON/SwiftyJSON.git",
      from: "5.0.1"
    ),
  ],
  targets: [
    .target(
      name: "OpenID4VP",
      dependencies: [
        .product(
          name: "JOSESwift",
          package: "JOSESwift"
        ),
        .product(
          name: "X509",
          package: "swift-certificates"
        ),
        .product(
          name: "SwiftASN1",
          package: "swift-asn1"
        ),
        .product(
          name: "SwiftyJSON",
          package: "SwiftyJSON"
        ),
      ],
      path: "Sources",
      resources: [
        .process("Resources")
      ]
    ),
    .testTarget(
      name: "OpenID4VPTests",
      dependencies: [
        "OpenID4VP",
        .product(
          name: "JOSESwift",
          package: "JOSESwift"
        ),
        .product(
          name: "CryptoSwift",
          package: "CryptoSwift"
        ),
        .product(
          name: "SwiftyJSON",
          package: "SwiftyJSON"
        )
      ],
      path: "Tests"
    )
  ]
)
