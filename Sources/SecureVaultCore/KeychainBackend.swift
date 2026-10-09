//
//  KeychainBackend.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// Attributes used when writing a Keychain item.
public struct KeychainWriteOptions: Sendable, Equatable {
    public var accessibility: Accessibility
    public var deviceOnly: Bool
    public var userAuthentication: UserAuthentication?
    /// When `false`, writing over an existing item fails with `KeychainStatus.duplicateItem`.
    public var overwrite: Bool

    public init(accessibility: Accessibility, deviceOnly: Bool, userAuthentication: UserAuthentication? = nil, overwrite: Bool = true) {
        self.accessibility = accessibility
        self.deviceOnly = deviceOnly
        self.userAuthentication = userAuthentication
        self.overwrite = overwrite
    }
}

/// What can be learned about an item without reading its data (never prompts).
public struct KeychainItemInfo: Sendable, Equatable {
    public var service: String
    public var account: String
    public var requiresUserAuthentication: Bool
    public var accessibility: Accessibility?
    public var deviceOnly: Bool

    public init(service: String, account: String, requiresUserAuthentication: Bool, accessibility: Accessibility?, deviceOnly: Bool) {
        self.service = service
        self.account = account
        self.requiresUserAuthentication = requiresUserAuthentication
        self.accessibility = accessibility
        self.deviceOnly = deviceOnly
    }
}

public enum KeychainStatus {
    public static let duplicateItem: Int32 = -25299
}

/// Generic-password storage. `SystemKeychain` is the real implementation; `InMemoryKeychain` is for tests.
public protocol KeychainBackend: Sendable {
    func set(_ data: Data, service: String, account: String, options: KeychainWriteOptions) async throws
    /// Replaces only the data, keeping every attribute. Throws `itemNotFound`.
    func updateData(_ data: Data, service: String, account: String) async throws
    /// Throws `itemNotFound` when absent.
    func get(service: String, account: String, authentication: AuthenticationContext?) async throws -> Data
    /// `nil` when absent. Never prompts.
    func info(service: String, account: String) async throws -> KeychainItemInfo?
    /// No error when absent.
    func delete(service: String, account: String) async throws
    func deleteAll(service: String) async throws
    func accounts(service: String) async throws -> [String]
    /// Every service name starting with `prefix` that holds at least one item.
    func services(withPrefix prefix: String) async throws -> [String]
    /// `true` for test doubles; reported by diagnostics.
    var isEphemeral: Bool { get }
}

extension KeychainBackend {
    public var isEphemeral: Bool { false }
}
