//
//  VaultNamespace.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// A logical partition of stored data that can be cleared on its own, for example on logout.
public struct VaultNamespace: RawRepresentable, Hashable, Sendable, Codable, ExpressibleByStringLiteral, CustomStringConvertible {
    public let rawValue: String

    public init(rawValue: String) {
        precondition(!rawValue.isEmpty, "VaultNamespace must not be empty")
        self.rawValue = rawValue
    }

    public init(_ rawValue: String) { self.init(rawValue: rawValue) }
    public init(stringLiteral value: String) { self.init(rawValue: value) }

    public var description: String { rawValue }

    public static let `default`: VaultNamespace = "default"
    public static let auth: VaultNamespace = "auth"
    public static let session: VaultNamespace = "session"
    public static let user: VaultNamespace = "user"
    public static let preferences: VaultNamespace = "preferences"
    public static let medical: VaultNamespace = "medical"
    public static let financial: VaultNamespace = "financial"
    public static let cache: VaultNamespace = "cache"

    /// A per-account namespace, e.g. `VaultNamespace.user(id: accountID)` → `user.<id>`.
    public static func user(id: String) -> VaultNamespace { VaultNamespace("user.\(id)") }
}
