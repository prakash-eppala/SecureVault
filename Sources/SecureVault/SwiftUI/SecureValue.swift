//
//  SecureValue.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Combine
import Foundation

/// An observable vault value for SwiftUI and view models. Loads asynchronously; setting `nil` deletes it.
@MainActor
public final class SecureValue<Value: Codable & Sendable>: ObservableObject {
    @Published public private(set) var value: Value?
    @Published public private(set) var isLoading = false
    @Published public private(set) var error: SecureVaultError?

    public let key: String
    public let namespace: VaultNamespace
    public let policy: StoragePolicy
    public private(set) var vault: SecureVault?

    private var hasLoaded = false
    private var generation = 0

    public init(_ key: String, namespace: VaultNamespace = .default, policy: StoragePolicy = .sensitive, vault: SecureVault? = nil) {
        self.key = key
        self.namespace = namespace
        self.policy = policy
        self.vault = vault
    }

    /// Uses `vault` unless one was given at init, then loads once.
    public func attach(_ vault: SecureVault) {
        if self.vault == nil { self.vault = vault }
        guard !hasLoaded else { return }
        hasLoaded = true
        Task { await load() }
    }

    public func load(authentication: AuthenticationContext? = nil) async {
        guard let vault else { return }
        generation += 1
        let current = generation
        isLoading = true
        defer { if current == generation { isLoading = false } }
        do {
            let loaded = try await vault.value(Value.self, forKey: key, namespace: namespace, authentication: authentication)
            guard current == generation else { return }
            value = loaded
            error = nil
        } catch {
            guard current == generation else { return }
            self.error = SecureVaultError.wrap(error)
        }
    }

    /// Updates the published value immediately and persists it. On failure the previous value is restored.
    public func set(_ newValue: Value?) async {
        guard let vault else { return }
        generation += 1
        let previous = value
        value = newValue
        do {
            if let newValue {
                try await vault.store(newValue, forKey: key, namespace: namespace, policy: policy)
            } else {
                try await vault.delete(forKey: key, namespace: namespace)
            }
            error = nil
        } catch {
            value = previous
            self.error = SecureVaultError.wrap(error)
        }
    }

    public func delete() async { await set(nil) }
}
