//
//  KeyManager.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation

/// Identifies a family of data keys: a purpose (`kv`, `files`, `db.<name>`) in a protection domain.
public struct KeyID: Hashable, Sendable, CustomStringConvertible {
    public let purpose: String
    public let domain: KeyDomain

    public init(purpose: String, domain: KeyDomain) {
        precondition(!purpose.contains("|"), "Key purpose must not contain '|'")
        self.purpose = purpose
        self.domain = domain
    }

    public var description: String { "\(purpose)|\(domain.id)" }

    func account(version: Int) -> String { "\(purpose)|\(domain.id)|v\(version)" }

    static func parse(account: String) -> (KeyID, Int)? {
        let parts = account.split(separator: "|")
        guard parts.count == 3, let domain = KeyDomain(id: String(parts[1])),
              parts[2].hasPrefix("v"), let version = Int(parts[2].dropFirst()) else { return nil }
        return (KeyID(purpose: String(parts[0]), domain: domain), version)
    }
}

/// How the Secure Enclave is used to wrap device-only data keys (PRD §15.2).
public enum SecureEnclaveUsage: String, Sendable, Codable {
    case never
    case whenAvailable
    case required
}

/// Generates, protects, versions and destroys data keys (PRD §15–16).
public actor KeyManager {
    private let service: String
    private let keychain: any KeychainBackend
    private let protector: (any KeyProtector)?
    private let protectorAccount = "kek|secure-enclave"

    private var cache: [String: SymmetricKey] = [:]
    private var inFlight: [String: Task<(Int, SymmetricKey), any Error>] = [:]
    private var protectionKey: Data?

    /// - Parameter protector: wraps device-only keys when non-nil (the Secure Enclave in production).
    public init(vaultID: String, keychain: any KeychainBackend, protector: (any KeyProtector)?) {
        self.service = "\(vaultID).keys"
        self.keychain = keychain
        self.protector = protector
    }

    public var keyService: String { service }

    /// The newest key version, creating version 1 on first use.
    public func currentKey(for id: KeyID) async throws -> (version: Int, key: SymmetricKey) {
        let flightKey = "current|\(id)"
        if let task = inFlight[flightKey] { return try await task.value }
        let task = Task<(Int, SymmetricKey), any Error> {
            let versions = try await self.versions(for: id)
            if let latest = versions.max() {
                return (latest, try await self.key(for: id, version: latest))
            }
            return try await self.create(id, version: 1)
        }
        inFlight[flightKey] = task
        defer { inFlight[flightKey] = nil }
        return try await task.value
    }

    /// A specific version. Throws `keyUnavailable` if that version no longer exists.
    public func key(for id: KeyID, version: Int) async throws -> SymmetricKey {
        let account = id.account(version: version)
        if let cached = cache[account] { return cached }
        let stored: Data
        do {
            stored = try await keychain.get(service: service, account: account, authentication: nil)
        } catch SecureVaultError.itemNotFound {
            throw SecureVaultError.keyUnavailable
        }
        let key = try await decode(stored, account: account)
        cache[account] = key
        return key
    }

    /// All versions present for a key family, ascending.
    public func versions(for id: KeyID) async throws -> [Int] {
        try await keychain.accounts(service: service)
            .compactMap(KeyID.parse(account:))
            .filter { $0.0 == id }
            .map(\.1)
            .sorted()
    }

    /// Every key family that has at least one version.
    public func allKeyIDs() async throws -> [KeyID: [Int]] {
        var result: [KeyID: [Int]] = [:]
        for (id, version) in try await keychain.accounts(service: service).compactMap(KeyID.parse(account:)) {
            result[id, default: []].append(version)
        }
        return result.mapValues { $0.sorted() }
    }

    /// Creates the next version and returns it. Older versions stay until `destroy` (PRD §16).
    public func rotate(_ id: KeyID) async throws -> (version: Int, key: SymmetricKey) {
        let next = (try await versions(for: id).max() ?? 0) + 1
        return try await create(id, version: next)
    }

    /// Crypto-shreds one version.
    public func destroy(_ id: KeyID, version: Int) async throws {
        let account = id.account(version: version)
        try await keychain.delete(service: service, account: account)
        cache[account] = nil
    }

    /// Crypto-shreds every version of a key family.
    public func destroyAll(_ id: KeyID) async throws {
        for version in try await versions(for: id) {
            try await destroy(id, version: version)
        }
    }

    /// Crypto-shreds every key, including the Secure Enclave protection key.
    public func destroyEverything() async throws {
        try await keychain.deleteAll(service: service)
        cache.removeAll()
        protectionKey = nil
    }

    /// Drops cached keys. With `onlyWhenUnlockedDomains`, keeps after-first-unlock keys for background work.
    public func clearCache(onlyWhenUnlockedDomains: Bool = false) {
        guard onlyWhenUnlockedDomains else { cache.removeAll(); return }
        cache = cache.filter { account, _ in
            KeyID.parse(account: account)?.0.domain.accessibility == .afterFirstUnlock
        }
    }

    public var usesKeyProtector: Bool { protector != nil }

    // MARK: - Storage format: [0x00 ‖ raw key] or [0x01 ‖ wrapped key]

    private func create(_ id: KeyID, version: Int) async throws -> (Int, SymmetricKey) {
        let key = SymmetricKey(size: .bits256)
        let raw = key.withUnsafeBytes { Data($0) }
        let account = id.account(version: version)
        var stored: Data
        if let protector, id.domain.deviceOnly {
            let kek = try await loadProtectionKey(protector)
            stored = Data([0x01])
            stored.append(try protector.wrap(raw, protectionKey: kek, context: Data(account.utf8)))
        } else {
            stored = Data([0x00]) + raw
        }
        let options = KeychainWriteOptions(accessibility: id.domain.accessibility, deviceOnly: id.domain.deviceOnly, overwrite: false)
        do {
            try await keychain.set(stored, service: service, account: account, options: options)
        } catch SecureVaultError.keychainFailure(let status) where status == KeychainStatus.duplicateItem {
            // Another writer won the race; use its key so nothing is sealed with a lost key.
            return (version, try await self.key(for: id, version: version))
        }
        cache[account] = key
        return (version, key)
    }

    private func decode(_ stored: Data, account: String) async throws -> SymmetricKey {
        guard let format = stored.first else { throw SecureVaultError.keyUnavailable }
        let body = Data(stored.dropFirst())
        switch format {
        case 0x00:
            guard body.count == 32 else { throw SecureVaultError.invalidData(reason: "bad key length") }
            return SymmetricKey(data: body)
        case 0x01:
            guard let protector else { throw SecureVaultError.keyUnavailable }
            let kek = try await loadProtectionKey(protector)
            let raw = try protector.unwrap(body, protectionKey: kek, context: Data(account.utf8))
            return SymmetricKey(data: raw)
        default:
            throw SecureVaultError.invalidData(reason: "unknown key format")
        }
    }

    private func loadProtectionKey(_ protector: any KeyProtector) async throws -> Data {
        if let protectionKey { return protectionKey }
        do {
            let existing = try await keychain.get(service: service, account: protectorAccount, authentication: nil)
            protectionKey = existing
            return existing
        } catch SecureVaultError.itemNotFound {
            let created = try protector.makeProtectionKey()
            let options = KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: true, overwrite: false)
            do {
                try await keychain.set(created, service: service, account: protectorAccount, options: options)
                protectionKey = created
                return created
            } catch SecureVaultError.keychainFailure(let status) where status == KeychainStatus.duplicateItem {
                let existing = try await keychain.get(service: service, account: protectorAccount, authentication: nil)
                protectionKey = existing
                return existing
            }
        }
    }
}
