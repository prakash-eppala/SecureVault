//
//  Lifecycle.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import SecureVaultCore
import SecureVaultDatabase

/// One-time setup (reinstall handling) and the registry of open databases.
actor VaultLifecycle {
    private let root: URL
    private let servicePrefix: String
    private let keychain: any KeychainBackend
    private let resetOnReinstall: Bool
    private let log: VaultLog
    private var preparation: Task<Void, any Error>?
    private var databases: [String: SecureDatabase] = [:]

    init(root: URL, servicePrefix: String, keychain: any KeychainBackend, resetOnReinstall: Bool, log: VaultLog) {
        self.root = root
        self.servicePrefix = servicePrefix
        self.keychain = keychain
        self.resetOnReinstall = resetOnReinstall
        self.log = log
    }

    private var marker: URL { root.appendingPathComponent(".securevault-installed") }

    /// Runs once per process. If the install marker is missing, items left in the Keychain by a previous
    /// install are deleted before anything else touches them.
    func prepare() async throws {
        if let preparation { return try await preparation.value }
        let task = Task { [root, marker, servicePrefix, keychain, resetOnReinstall, log] in
            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: marker.path) {
                if resetOnReinstall {
                    let stale = try await keychain.services(withPrefix: servicePrefix)
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
}

/// Clears when-unlocked keys and closes databases when the device locks (PRD §17.4, §33).
final class ProtectedDataObserver: @unchecked Sendable {
    private var token: (any NSObjectProtocol)?

    init(onLock: @escaping @Sendable () -> Void) {
        #if os(iOS)
        token = NotificationCenter.default.addObserver(
            forName: Notification.Name("UIApplicationProtectedDataWillBecomeUnavailable"),
            object: nil, queue: nil
        ) { _ in onLock() }
        #endif
    }

    deinit {
        if let token { NotificationCenter.default.removeObserver(token) }
    }
}
