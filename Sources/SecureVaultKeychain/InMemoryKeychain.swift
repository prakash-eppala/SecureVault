//
//  InMemoryKeychain.swift
//  SecureVaultKeychain
//
//  Created by Prakash on 09/10/26.
//

import Foundation
#if canImport(SecureVaultCore)
import SecureVaultCore
#endif

/// A Keychain double for unit tests and SwiftUI previews. Never use it in production:
/// nothing persists and access control is not enforced. Diagnostics flag it as critical.
public final class InMemoryKeychain: KeychainBackend, @unchecked Sendable {
    private struct Item {
        var data: Data
        var options: KeychainWriteOptions
    }

    private let lock = NSLock()
    private var items: [String: [String: Item]] = [:]

    public init() {}

    public var isEphemeral: Bool { true }

    public func set(_ data: Data, service: String, account: String, options: KeychainWriteOptions) async throws {
        try withLock {
            if items[service]?[account] != nil, !options.overwrite {
                throw SecureVaultError.keychainFailure(status: KeychainStatus.duplicateItem)
            }
            items[service, default: [:]][account] = Item(data: data, options: options)
        }
    }

    public func updateData(_ data: Data, service: String, account: String) async throws {
        try withLock {
            guard items[service]?[account] != nil else { throw SecureVaultError.itemNotFound }
            items[service]?[account]?.data = data
        }
    }

    public func get(service: String, account: String, authentication: AuthenticationContext?) async throws -> Data {
        try withLock {
            guard let item = items[service]?[account] else { throw SecureVaultError.itemNotFound }
            return item.data
        }
    }

    public func info(service: String, account: String) async throws -> KeychainItemInfo? {
        withLock {
            items[service]?[account].map {
                KeychainItemInfo(
                    service: service, account: account,
                    requiresUserAuthentication: $0.options.userAuthentication != nil,
                    accessibility: $0.options.accessibility, deviceOnly: $0.options.deviceOnly
                )
            }
        }
    }

    public func delete(service: String, account: String) async throws {
        withLock { _ = items[service]?.removeValue(forKey: account) }
    }

    public func deleteAll(service: String) async throws {
        withLock { _ = items.removeValue(forKey: service) }
    }

    public func accounts(service: String) async throws -> [String] {
        withLock { (items[service].map { Array($0.keys) } ?? []).sorted() }
    }

    public func services(withPrefix prefix: String) async throws -> [String] {
        withLock { items.filter { !$0.value.isEmpty && $0.key.hasPrefix(prefix) }.keys.sorted() }
    }

    /// Test hook: the options an item was written with.
    public func options(service: String, account: String) -> KeychainWriteOptions? {
        withLock { items[service]?[account]?.options }
    }

    /// Test hook: overwrite raw bytes to simulate tampering.
    public func tamper(service: String, account: String, _ transform: (inout Data) -> Void) {
        withLock {
            guard var item = items[service]?[account] else { return }
            transform(&item.data)
            items[service]?[account] = item
        }
    }

    private func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }
}
