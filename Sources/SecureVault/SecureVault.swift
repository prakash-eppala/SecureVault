//
//  SecureVault.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// One API for every level of data protection.
///
///     let vault = SecureVault.shared
///     try await vault.store(token, forKey: "accessToken", namespace: .auth, policy: .accessToken)
///     let token: String = try await vault.retrieve(forKey: "accessToken", namespace: .auth)
public final class SecureVault: Sendable {
    /// A vault with the default configuration, identified by the main bundle identifier.
    public static let shared = SecureVault()

    public let configuration: Configuration
    /// Where encrypted files and databases live.
    public let rootDirectory: URL
    /// Encrypted, streaming file storage (PRD §19).
    public let files: ProtectedFileStore

    let keychain: any KeychainBackend
    let capabilities: any DeviceCapabilities
    let keys: KeyManager
    let objects: EncryptedObjectStore
    let crypto: any CryptoProvider = AESGCMProvider()
    let log: VaultLog
    let lifecycle: VaultLifecycle
    private let observer: ProtectedDataObserver

    static let kvPurpose = "kv"

    public init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
        let root = configuration.directory ?? FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SecureVault", isDirectory: true)
            .appendingPathComponent(configuration.identifier, isDirectory: true)
        self.rootDirectory = root

        let keychain = configuration.keychain ?? SystemKeychain(accessGroup: configuration.keychainAccessGroup)
        let capabilities = configuration.capabilities ?? SystemDeviceCapabilities()
        let log = VaultLog(enabled: configuration.loggingEnabled)

        let protector: (any KeyProtector)?
        if let custom = configuration.keyProtector {
            protector = custom
        } else if configuration.secureEnclave != .never, capabilities.isSecureEnclaveAvailable {
            protector = SecureEnclaveKeyProtector()
        } else {
            protector = nil
        }

        let keys = KeyManager(vaultID: configuration.identifier, keychain: keychain, protector: protector)
        self.keychain = keychain
        self.capabilities = capabilities
        self.log = log
        self.keys = keys
        self.objects = EncryptedObjectStore(root: root.appendingPathComponent("objects", isDirectory: true), vaultID: configuration.identifier)
        let lifecycle = VaultLifecycle(
            root: root, vaultID: configuration.identifier, keychain: keychain,
            resetOnReinstall: configuration.resetKeychainOnReinstall, log: log
        )
        self.lifecycle = lifecycle
        self.files = ProtectedFileStore(
            root: root.appendingPathComponent("files", isDirectory: true), vaultID: configuration.identifier,
            keys: keys, capabilities: capabilities, log: log, now: configuration.clock,
            requireSecureEnclave: configuration.secureEnclave == .required,
            prepare: { try await lifecycle.prepare() }
        )
        self.observer = ProtectedDataObserver {
            Task { await Self.handleDeviceLock(keys: keys, lifecycle: lifecycle) }
        }
    }

    // MARK: - Key-value storage (PRD §11)

    /// Stores a Codable value. Storing a key again replaces it, moving it if the placement changed.
    public func store<T: Encodable & Sendable>(
        _ value: T, forKey key: String, namespace: VaultNamespace = .default, policy: StoragePolicy = .sensitive
    ) async throws {
        try await storeEncoded(try encode(value), forKey: key, namespace: namespace, policy: policy)
    }

    /// Reads a value. Throws `itemNotFound`, `expired`, `typeMismatch`, `decryptionFailed`, …
    public func retrieve<T: Decodable>(
        _ type: T.Type = T.self, forKey key: String, namespace: VaultNamespace = .default,
        authentication: AuthenticationContext? = nil
    ) async throws -> T {
        try decode(T.self, try await retrieveEncoded(forKey: key, namespace: namespace, authentication: authentication))
    }

    /// Reads a value, returning `nil` when it is absent or expired. Other errors still throw.
    public func value<T: Decodable>(
        _ type: T.Type = T.self, forKey key: String, namespace: VaultNamespace = .default,
        authentication: AuthenticationContext? = nil
    ) async throws -> T? {
        do {
            return try await retrieve(type, forKey: key, namespace: namespace, authentication: authentication)
        } catch SecureVaultError.itemNotFound, SecureVaultError.expired {
            return nil
        }
    }

    /// Whether a non-expired value exists. Never prompts; items that need authentication report `true`.
    public func exists(forKey key: String, namespace: VaultNamespace = .default) async throws -> Bool {
        try await lifecycle.prepare()
        let envelope: Data
        if let info = try await keychain.info(service: kvService(namespace), account: key) {
            if info.requiresUserAuthentication { return true }
            envelope = try await keychain.get(service: kvService(namespace), account: key, authentication: nil)
        } else if await objects.exists(namespace: namespace.rawValue, key: key) {
            envelope = try await objects.read(namespace: namespace.rawValue, key: key)
        } else {
            return false
        }
        // An unauthenticated hint; retrieve() enforces expiry with the authenticated header.
        if let expiry = try Envelope.peekHeader(envelope).expiresAt, expiry <= now() { return false }
        return true
    }

    public func delete(forKey key: String, namespace: VaultNamespace = .default) async throws {
        try await lifecycle.prepare()
        try await keychain.delete(service: kvService(namespace), account: key)
        try await objects.delete(namespace: namespace.rawValue, key: key)
        log.event("delete", namespace: namespace.rawValue, key: key)
    }

    /// Removes every key-value item and protected file in a namespace.
    public func clear(namespace: VaultNamespace) async throws {
        try await lifecycle.prepare()
        try await keychain.deleteAll(service: kvService(namespace))
        try await objects.deleteNamespace(namespace.rawValue)
        try await files.clear(namespace: namespace)
        log.event("clear", namespace: namespace.rawValue)
    }

    // MARK: - Session lifecycle (PRD §23, §31)

    /// Clears the session namespaces (default `auth`, `session`, `cache`) and anything in `options`.
    /// Keys are kept; use `reset()` to crypto-shred everything.
    public func logout(_ options: LogoutOptions = LogoutOptions()) async throws {
        for namespace in configuration.sessionNamespaces.union(options.additionalNamespaces) {
            try await lifecycle.prepare()
            try await keychain.deleteAll(service: kvService(namespace))
            try await objects.deleteNamespace(namespace.rawValue)
            if options.includeFiles { try await files.clear(namespace: namespace) }
        }
        for name in options.databases { try await deleteDatabase(name) }
        log.event("logout")
    }

    /// Destroys every key, item, file and database in this vault.
    public func reset() async throws {
        await lifecycle.closeAll()
        for service in try await VaultLifecycle.ownedServices(vaultID: configuration.identifier, keychain: keychain) {
            try await keychain.deleteAll(service: service)
        }
        try await keys.destroyEverything()
        if FileManager.default.fileExists(atPath: rootDirectory.path) {
            do { try FileManager.default.removeItem(at: rootDirectory) } catch {
                throw SecureVaultError.fileFailure(reason: "reset")
            }
        }
        for database in await lifecycle.openDatabases { await lifecycle.removeDatabase(database.name) }
        await lifecycle.invalidate()
        log.event("reset")
    }

    /// What happens when the device locks: keys that need an unlocked device are dropped and databases readable
    /// only while unlocked are closed. After-first-unlock keys and databases keep working for background tasks.
    static func handleDeviceLock(keys: KeyManager, lifecycle: VaultLifecycle) async {
        await keys.clearCache(onlyWhenUnlockedDomains: true)
        await lifecycle.closeForDeviceLock()
    }

    /// Drops cached keys and closes databases. The next access reloads them from the Keychain.
    public func lock() async {
        await keys.clearCache()
        await lifecycle.closeAll()
    }

    /// Deletes key-value items and files whose key no longer exists, e.g. device-only data after a backup
    /// restore. Nothing is deleted automatically (PRD principle 8). Returns the number removed.
    @discardableResult
    public func purgeUnreadableItems() async throws -> Int {
        try await lifecycle.prepare()
        var removed = 0
        try await forEachItem { item in
            guard let envelope = item.envelope else { return }
            let header = try Envelope.peekHeader(envelope)
            guard let id = header.keyID else { return }
            do {
                _ = try await self.keys.key(for: id, version: header.keyVersion)
            } catch SecureVaultError.keyUnavailable {
                try await item.remove()
                removed += 1
            }
        }
        removed += try await files.purgeUnreadable()
        return removed
    }

    /// Deletes every expired item. Returns the number removed.
    @discardableResult
    public func purgeExpired() async throws -> Int {
        try await lifecycle.prepare()
        var removed = 0
        let now = now()
        try await forEachItem { item in
            guard let envelope = item.envelope else { return }
            let header = try Envelope.peekHeader(envelope)
            guard let expiry = header.expiresAt, expiry <= now, let id = header.keyID else { return }
            // Confirm with the authenticated header before deleting.
            let key = try await self.keys.key(for: id, version: header.keyVersion)
            let verified = try Envelope.open(envelope, key: key, context: item.context, crypto: self.crypto).header
            if let verifiedExpiry = verified.expiresAt, verifiedExpiry <= now {
                try await item.remove()
                removed += 1
            }
        }
        return removed
    }

    // MARK: - Databases (PRD §17)

    /// Opens (creating on first use) an encrypted record database. The policy is fixed at creation.
    public func database(_ name: String, policy: StoragePolicy = .highlySensitive) async throws -> SecureDatabase {
        precondition(!name.isEmpty, "database name must not be empty")
        try PolicyEngine.validate(policy, capabilities: capabilities, requireSecureEnclave: configuration.secureEnclave == .required)
        if policy.userAuthentication != nil {
            throw SecureVaultError.securityPolicyViolation(reason: "biometric-gated databases are not supported in V1")
        }
        try await lifecycle.prepare()
        let domain = KeyDomain(accessibility: policy.accessibility, deviceOnly: policy.deviceOnly)
        return await lifecycle.database(name) {
            SecureDatabase(
                name: name, directory: rootDirectory.appendingPathComponent("databases", isDirectory: true),
                domain: domain, keys: keys, crypto: crypto, log: log, now: configuration.clock
            )
        }
    }

    /// Deletes a database file and crypto-shreds its keys.
    public func deleteDatabase(_ name: String) async throws {
        try await lifecycle.prepare()
        let database = await lifecycle.existingDatabase(name) ?? SecureDatabase(
            name: name, directory: rootDirectory.appendingPathComponent("databases", isDirectory: true),
            domain: KeyDomain(accessibility: .whenUnlocked, deviceOnly: true), keys: keys, crypto: crypto,
            log: log, now: configuration.clock
        )
        await database.destroyFiles()
        await lifecycle.removeDatabase(name)
        let purpose = SecureDatabase.keyPurpose(name)
        for id in try await keys.allKeyIDs().keys where id.purpose == purpose {
            try await keys.destroyAll(id)
        }
    }

    // MARK: - Key rotation (PRD §16)

    /// Rotates every key in use and re-encrypts data under the new versions. Old versions are deleted once
    /// nothing references them. Databases rotate when opened in this process or listed in `databases`.
    @discardableResult
    public func rotateKeys(databases: [String] = []) async throws -> KeyRotationReport {
        try await lifecycle.prepare()
        for id in try await keys.allKeyIDs().keys where id.purpose == Self.kvPurpose {
            _ = try await keys.rotate(id)
        }
        var report = try await completePendingRotations()

        for name in databases { _ = try await database(name) }
        for database in await lifecycle.openDatabases {
            report.reencryptedRecords += try await database.rotateKey()
        }
        report.reencryptedFiles = try await files.rotateKeys()
        log.event("rotate")
        return report
    }

    /// Finishes an interrupted rotation: re-encrypts items still on an old key version and retires old versions.
    @discardableResult
    public func completePendingRotations() async throws -> KeyRotationReport {
        try await lifecycle.prepare()
        var report = KeyRotationReport()
        try await forEachItem { item in
            guard let envelope = item.envelope else {
                report.skippedItems += 1
                return
            }
            let header = try Envelope.peekHeader(envelope)
            guard let id = header.keyID else { return }
            let current = try await self.keys.currentKey(for: id)
            guard header.keyVersion < current.version else { return }
            let oldKey = try await self.keys.key(for: id, version: header.keyVersion)
            let opened = try Envelope.open(envelope, key: oldKey, context: item.context, crypto: self.crypto)
            var newHeader = opened.header
            newHeader.keyVersion = current.version
            let resealed = try Envelope.seal(opened.plaintext, header: newHeader, key: current.key, context: item.context, crypto: self.crypto)
            try await item.replace(resealed)
            report.reencryptedItems += 1
        }
        // Items that need authentication could not be read, so their key version is unknown: keep old versions.
        if report.skippedItems == 0 {
            for (id, versions) in try await keys.allKeyIDs() where id.purpose == Self.kvPurpose {
                for stale in versions.dropLast() {
                    try await keys.destroy(id, version: stale)
                    report.retiredKeyVersions += 1
                }
            }
        }
        return report
    }

    // MARK: - Diagnostics (PRD §25)

    public func securityReport() async -> SecurityReport {
        let input = SecurityReportInput(
            now: now(),
            capabilities: capabilities,
            keychainIsEphemeral: keychain.isEphemeral,
            secureEnclaveInUse: await keys.usesKeyProtector,
            keyVersions: (try? await keys.allKeyIDs()) ?? [:],
            storedObjectFiles: await objects.count(),
            loggingEnabled: log.isEnabled
        )
        return SecurityReportBuilder.build(input)
    }

    // MARK: - Internals

    func kvService(_ namespace: VaultNamespace) -> String { "\(configuration.identifier).kv.\(namespace.rawValue)" }
    var kvServicePrefix: String { "\(configuration.identifier).kv." }
    func now() -> Date { configuration.clock() }

    package func storeEncoded(_ plaintext: Data, forKey key: String, namespace: VaultNamespace, policy: StoragePolicy) async throws {
        guard !key.isEmpty else { throw SecureVaultError.invalidData(reason: "key must not be empty") }
        if Task.isCancelled { throw SecureVaultError.cancelled }
        try await lifecycle.prepare()
        let placement = try PolicyEngine.resolve(
            policy, payloadSize: plaintext.count, capabilities: capabilities,
            requireSecureEnclave: configuration.secureEnclave == .required
        )
        let (version, dataKey) = try await keys.currentKey(for: KeyID(purpose: Self.kvPurpose, domain: placement.domain))
        let created = now()
        let header = EnvelopeHeader(
            algorithm: crypto.algorithm, keyPurpose: Self.kvPurpose, keyDomain: placement.domain.id,
            keyVersion: version, createdAt: created, expiresAt: policy.expiresAfter.map { created.addingTimeInterval($0) }
        )
        let context = objects.context(namespace: namespace.rawValue, key: key)
        let envelope = try Envelope.seal(plaintext, header: header, key: dataKey, context: context, crypto: crypto)

        switch placement.backend {
        case .keychain:
            let options = KeychainWriteOptions(
                accessibility: placement.domain.accessibility, deviceOnly: placement.domain.deviceOnly,
                userAuthentication: placement.userAuthentication
            )
            try await keychain.set(envelope, service: kvService(namespace), account: key, options: options)
            try await objects.delete(namespace: namespace.rawValue, key: key)
        case .encryptedFile:
            try await objects.write(
                envelope, namespace: namespace.rawValue, key: key,
                protection: placement.fileProtection, excludeFromBackup: placement.domain.deviceOnly
            )
            try await keychain.delete(service: kvService(namespace), account: key)
        }
        log.event("store", namespace: namespace.rawValue, key: key)
    }

    package func retrieveEncoded(forKey key: String, namespace: VaultNamespace, authentication: AuthenticationContext?) async throws -> Data {
        if Task.isCancelled { throw SecureVaultError.cancelled }
        try await lifecycle.prepare()
        let service = kvService(namespace)
        let envelope: Data
        if try await keychain.info(service: service, account: key) != nil {
            envelope = try await keychain.get(service: service, account: key, authentication: authentication)
        } else {
            envelope = try await objects.read(namespace: namespace.rawValue, key: key)
        }
        let hint = try Envelope.peekHeader(envelope)
        guard let id = hint.keyID else { throw SecureVaultError.invalidData(reason: "unknown key domain") }
        let dataKey = try await keys.key(for: id, version: hint.keyVersion)
        let context = objects.context(namespace: namespace.rawValue, key: key)
        let (header, plaintext) = try Envelope.open(envelope, key: dataKey, context: context, crypto: crypto)
        if let expiry = header.expiresAt, expiry <= now() {
            try? await delete(forKey: key, namespace: namespace)
            throw SecureVaultError.expired
        }
        log.event("retrieve", namespace: namespace.rawValue, key: key)
        return plaintext
    }

    /// A stored key-value item, independent of backend.
    struct StoredItem {
        /// `nil` when reading would need user authentication.
        let envelope: Data?
        let context: Data
        let replace: (Data) async throws -> Void
        let remove: () async throws -> Void
    }

    /// Visits every key-value item in the Keychain and the object store.
    func forEachItem(_ visit: (StoredItem) async throws -> Void) async throws {
        let prefix = kvServicePrefix
        for service in try await keychain.services(withPrefix: prefix) {
            let namespace = String(service.dropFirst(prefix.count))
            for account in try await keychain.accounts(service: service) {
                guard let info = try await keychain.info(service: service, account: account) else { continue }
                let envelope = info.requiresUserAuthentication
                    ? nil
                    : try await keychain.get(service: service, account: account, authentication: nil)
                let keychain = self.keychain
                try await visit(StoredItem(
                    envelope: envelope,
                    context: objects.context(namespace: namespace, key: account),
                    replace: { try await keychain.updateData($0, service: service, account: account) },
                    remove: { try await keychain.delete(service: service, account: account) }
                ))
            }
        }
        let objects = self.objects
        for (url, context) in await objects.allFiles() {
            let envelope = try await objects.read(at: url)
            try await visit(StoredItem(
                envelope: envelope,
                context: context,
                replace: { try await objects.replace(at: url, with: $0) },
                remove: { try await objects.removeFile(at: url) }
            ))
        }
    }

    private static let encoder = JSONEncoder()
    private static let decoder = JSONDecoder()

    func encode<T: Encodable>(_ value: T) throws -> Data {
        do { return try Self.encoder.encode(value) } catch {
            throw SecureVaultError.invalidData(reason: "value does not encode as JSON")
        }
    }

    func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try Self.decoder.decode(T.self, from: data) } catch {
            throw SecureVaultError.typeMismatch(expected: String(describing: T.self))
        }
    }
}
