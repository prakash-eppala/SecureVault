//
//  Lifecycle.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Foundation
#if canImport(SecureVaultCore)
import SecureVaultCore
#endif
#if canImport(SecureVaultDatabase)
import SecureVaultDatabase
#endif

/// One-time setup (reinstall handling) and the registry of open databases.
actor VaultLifecycle {
    private let root: URL
    private let vaultID: String
    private let keychain: any KeychainBackend
    private let resetOnReinstall: Bool
    private let log: VaultLog
    private var preparation: Task<Void, any Error>?
    private var databases: [String: SecureDatabase] = [:]

    init(root: URL, vaultID: String, keychain: any KeychainBackend, resetOnReinstall: Bool, log: VaultLog) {
        self.root = root
        self.vaultID = vaultID
        self.keychain = keychain
        self.resetOnReinstall = resetOnReinstall
        self.log = log
    }

    private var marker: URL { root.appendingPathComponent(".securevault-installed") }

    /// Runs once per process. If the install marker is missing, items left in the Keychain by a previous
    /// install are deleted before anything else touches them.
    func prepare() async throws {
        if let preparation { return try await preparation.value }
        let task = Task { [root, marker, vaultID, keychain, resetOnReinstall, log] in
            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: marker.path) {
                if resetOnReinstall {
                    let stale = try await Self.ownedServices(vaultID: vaultID, keychain: keychain)
                    for service in stale { try await keychain.deleteAll(service: service) }
                    if !stale.isEmpty { log.warning("removed Keychain items from a previous install") }
                }
                do {
                    try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
                    try Data().write(to: marker, options: .atomic)
                } catch {
                    throw SecureVaultError.fileFailure(reason: "vault directory")
                }
            }
        }
        preparation = task
        do {
            try await task.value
        } catch {
            preparation = nil
            throw error
        }
    }

    /// The Keychain services SecureVault writes: `<vaultID>.keys` and `<vaultID>.kv.<namespace>`.
    /// Other items that happen to share the prefix (for example legacy items waiting for migration) are never touched.
    static func ownedServices(vaultID: String, keychain: any KeychainBackend) async throws -> [String] {
        let keys = "\(vaultID).keys"
        let values = try await keychain.services(withPrefix: "\(vaultID).kv.")
        let keyServices = try await keychain.services(withPrefix: keys).filter { $0 == keys }
        return keyServices + values
    }

    /// Forces `prepare()` to run again, e.g. after `reset()` removed the directory.
    func invalidate() { preparation = nil }

    func database(_ name: String, make: () -> SecureDatabase) -> SecureDatabase {
        if let existing = databases[name] { return existing }
        let database = make()
        databases[name] = database
        return database
    }

    func existingDatabase(_ name: String) -> SecureDatabase? { databases[name] }

    func removeDatabase(_ name: String) { databases[name] = nil }

    var openDatabases: [SecureDatabase] { Array(databases.values) }

    func closeAll() async {
        for database in databases.values { await database.close() }
    }

    /// Closes only the databases whose files become unreadable when the device locks.
    func closeForDeviceLock() async {
        for database in databases.values where database.closesWhenDeviceLocks { await database.close() }
    }
}

/// Clears when-unlocked keys and closes databases when the device locks (PRD §17.4, §33).
final class ProtectedDataObserver: @unchecked Sendable {
    private var token: (any NSObjectProtocol)?

    /// Posted by UIKit on iOS and Mac Catalyst. Never posted on macOS, where observing it is harmless.
    static let protectedDataWillBecomeUnavailable = Notification.Name("UIApplicationProtectedDataWillBecomeUnavailable")

    init(name: Notification.Name = protectedDataWillBecomeUnavailable, onLock: @escaping @Sendable () -> Void) {
        token = NotificationCenter.default.addObserver(forName: name, object: nil, queue: nil) { _ in onLock() }
    }

    deinit {
        if let token { NotificationCenter.default.removeObserver(token) }
    }
}
