//
//  SecureStorage.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import SwiftUI

private struct SecureVaultKey: EnvironmentKey {
    static let defaultValue: SecureVault = .shared
}

extension EnvironmentValues {
    /// The vault used by `@SecureStorage` and `BiometricGate`. Defaults to `SecureVault.shared`.
    public var secureVault: SecureVault {
        get { self[SecureVaultKey.self] }
        set { self[SecureVaultKey.self] = newValue }
    }
}

extension View {
    /// Injects a vault for `@SecureStorage` in this view hierarchy.
    public func secureVault(_ vault: SecureVault) -> some View {
        environment(\.secureVault, vault)
    }
}

/// A vault-backed value for SwiftUI views, like `@AppStorage` but encrypted:
///
///     @SecureStorage("accessToken", namespace: .auth, policy: .accessToken) var token: String?
///
/// The value starts `nil` and loads asynchronously. Assigning stores it; assigning `nil` deletes it.
/// `$token` is the underlying `SecureValue`, exposing `isLoading`, `error` and `binding`.
@MainActor
@propertyWrapper
public struct SecureStorage<Value: Codable & Sendable>: DynamicProperty {
    @StateObject private var model: SecureValue<Value>
    @Environment(\.secureVault) private var environmentVault

    public init(_ key: String, namespace: VaultNamespace = .default, policy: StoragePolicy = .sensitive, vault: SecureVault? = nil) {
        _model = StateObject(wrappedValue: SecureValue(key, namespace: namespace, policy: policy, vault: vault))
    }

    public var wrappedValue: Value? {
        get { model.value }
        nonmutating set {
            let model = model
            Task { await model.set(newValue) }
        }
    }

    public var projectedValue: SecureValue<Value> { model }

    public nonisolated func update() {
        MainActor.assumeIsolated {
            model.attach(environmentVault)
        }
    }
}

extension SecureValue {
    /// A binding that writes through to the vault.
    public var binding: Binding<Value?> {
        Binding(
            get: { self.value },
            set: { newValue in Task { await self.set(newValue) } }
        )
    }
}
