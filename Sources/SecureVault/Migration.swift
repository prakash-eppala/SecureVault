//
//  Migration.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// One value to move into SecureVault (PRD §24). SecureVault never scans for sources on its own.
public struct MigrationItem: Sendable {
    /// Describes the source and target for the report. Never contains the value.
    public let label: String
    let key: String
    let namespace: VaultNamespace
    let policy: StoragePolicy
    let readSource: @Sendable () async throws -> Data?
    let deleteSource: @Sendable () async throws -> Void

    /// A UserDefaults value. Plist types (String, numbers, Bool, Data, Date, arrays, dictionaries) are read directly;
    /// other Codable types are decoded from JSON or property-list `Data`.
    public static func userDefaults<T: Codable & Sendable>(
        _ defaultsKey: String, suiteName: String? = nil, as type: T.Type,
        to key: String, namespace: VaultNamespace = .default, policy: StoragePolicy
    ) -> MigrationItem {
        let defaults: @Sendable () -> UserDefaults = {
            suiteName.flatMap(UserDefaults.init(suiteName:)) ?? .standard
        }
        return MigrationItem(
            label: "UserDefaults[\(defaultsKey)] → \(namespace)/\(key)",
            key: key, namespace: namespace, policy: policy,
            readSource: {
                guard let object = defaults().object(forKey: defaultsKey) else { return nil }
                let value: T
                if let direct = object as? T {
                    value = direct
                } else if let data = object as? Data, let decoded = try? JSONDecoder().decode(T.self, from: data) {
                    value = decoded
                } else if let data = object as? Data, let decoded = try? PropertyListDecoder().decode(T.self, from: data) {
                    value = decoded
                } else {
                    throw SecureVaultError.migrationFailed(reason: "UserDefaults value does not convert to \(T.self)")
                }
                return try JSONEncoder().encode(value)
            },
            deleteSource: { defaults().removeObject(forKey: defaultsKey) }
        )
    }

    public enum KeychainValue: Sendable {
        /// UTF-8 text, read back in SecureVault as `String`.
        case string
        /// Raw bytes, read back as `Data`.
        case data
    }

    /// A generic-password Keychain item from an earlier implementation.
    public static func keychain(
        service: String, account: String, accessGroup: String? = nil, as kind: KeychainValue = .string,
        to key: String, namespace: VaultNamespace = .default, policy: StoragePolicy,
        source: (any KeychainBackend)? = nil
    ) -> MigrationItem {
        let backend = source ?? SystemKeychain(accessGroup: accessGroup)
        return MigrationItem(
            label: "Keychain[\(service)/\(account)] → \(namespace)/\(key)",
            key: key, namespace: namespace, policy: policy,
            readSource: {
                let data: Data
                do {
                    data = try await backend.get(service: service, account: account, authentication: nil)
                } catch SecureVaultError.itemNotFound {
                    return nil
                }
                switch kind {
                case .data:
                    return try JSONEncoder().encode(data)
                case .string:
                    guard let text = String(data: data, encoding: .utf8) else {
                        throw SecureVaultError.migrationFailed(reason: "Keychain item is not UTF-8 text")
                    }
                    return try JSONEncoder().encode(text)
                }
            },
            deleteSource: { try await backend.delete(service: service, account: account) }
        )
    }
}

public struct MigrationReport: Sendable {
    public struct Failure: Sendable {
        public let label: String
        public let error: SecureVaultError
    }

    public internal(set) var migrated: [String] = []
    /// Sources that were absent, usually because an earlier launch already migrated them.
    public internal(set) var skipped: [String] = []
    /// Failed items. Their sources are untouched.
    public internal(set) var failed: [Failure] = []

    public var isComplete: Bool { failed.isEmpty }
}

extension SecureVault {
    /// Moves values into the vault. Each source is deleted only after the stored copy is read back and
    /// matches byte for byte. Safe to call on every launch.
    ///
    /// Targets that require user authentication are verified by presence, not content, so migration never prompts.
    public func migrate(_ items: [MigrationItem]) async -> MigrationReport {
        var report = MigrationReport()
        for item in items {
            do {
                guard let encoded = try await item.readSource() else {
                    report.skipped.append(item.label)
                    continue
                }
                try await storeEncoded(encoded, forKey: item.key, namespace: item.namespace, policy: item.policy)
                if item.policy.userAuthentication != nil {
                    guard try await exists(forKey: item.key, namespace: item.namespace) else {
                        throw SecureVaultError.migrationFailed(reason: "stored copy not found")
                    }
                } else {
                    let readBack = try await retrieveEncoded(forKey: item.key, namespace: item.namespace, authentication: nil)
                    guard readBack == encoded else {
                        throw SecureVaultError.migrationFailed(reason: "stored copy does not match the source")
                    }
                }
                try await item.deleteSource()
                report.migrated.append(item.label)
            } catch {
                report.failed.append(.init(label: item.label, error: SecureVaultError.wrap(error)))
            }
        }
        return report
    }
}
