//
//  SecureDatabase.swift
//  SecureVaultDatabase
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation
import SecureVaultCore
import SecureVaultCrypto

/// An encrypted record store on the system SQLite (PRD §17).
///
/// Every record is sealed with AES-256-GCM; record types and ids are stored only as HMAC blind indexes,
/// so the file reveals record counts and sizes but no names, ids or contents.
public actor SecureDatabase {
    public nonisolated let name: String
    public nonisolated let fileURL: URL

    private let keys: KeyManager
    private let crypto: any CryptoProvider
    private let requestedDomain: KeyDomain
    private let protection: FileProtectionLevel
    private let log: VaultLog
    private let now: @Sendable () -> Date

    private var connection: SQLiteConnection?
    private var state: KeyState?
    /// Set while `rotateKey()` holds a new key version that is not yet committed, so a reopen never deletes it.
    private var isRotating = false

    private struct KeyState {
        var domain: KeyDomain
        var version: Int
        var recordKey: SymmetricKey
        var indexKey: SymmetricKey
    }

    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    package init(
        name: String, directory: URL, domain: KeyDomain, keys: KeyManager, crypto: any CryptoProvider,
        log: VaultLog, now: @escaping @Sendable () -> Date
    ) {
        self.name = name
        let folder = directory.appendingPathComponent(Digest.hex(Digest.sha256("db", name)), isDirectory: true)
        self.fileURL = folder.appendingPathComponent("records.sqlite")
        self.requestedDomain = domain
        self.protection = domain.accessibility.fileProtection
        self.keys = keys
        self.crypto = crypto
        self.log = log
        self.now = now
    }

    public nonisolated var keyPurpose: String { Self.keyPurpose(name) }

    /// Databases readable only while unlocked close when the device locks; after-first-unlock ones stay open.
    package nonisolated var closesWhenDeviceLocks: Bool { protection == .complete }
    package static func keyPurpose(_ name: String) -> String { "db.\(Digest.hex(Digest.sha256(name)).prefix(16))" }

    // MARK: - Typed API

    /// Inserts or replaces a record.
    public func insert<R: SecureRecord>(_ record: R) async throws {
        try await putData(try encode(record), id: record.id.description, type: R.recordType)
    }

    /// Inserts or replaces many records in one transaction.
    public func insert<R: SecureRecord>(contentsOf records: [R]) async throws {
        let state = try await ready()
        let rows = try records.map { record -> [SQLiteConnection.Value] in
            try row(type: R.recordType, id: record.id.description, json: try encode(record), state: state)
        }
        try perform { connection in
            try connection.transaction {
                for values in rows {
                    try connection.execute("INSERT OR REPLACE INTO records (type_tag, id_tag, payload) VALUES (?, ?, ?)", values)
                }
            }
        }
    }

    public func get<R: SecureRecord>(_ type: R.Type, id: R.ID) async throws -> R? {
        guard let data = try await data(id: id.description, type: R.recordType) else { return nil }
        return try decode(R.self, data)
    }

    public func all<R: SecureRecord>(_ type: R.Type) async throws -> [R] {
        try await allData(type: R.recordType).map { try decode(R.self, $0) }
    }

    /// Loads every record of a type and filters in memory. Indexed queries are V2.
    public func all<R: SecureRecord>(_ type: R.Type, where isIncluded: (R) throws -> Bool) async throws -> [R] {
        try await all(type).filter(isIncluded)
    }

    public func count<R: SecureRecord>(_ type: R.Type) async throws -> Int {
        try await count(type: R.recordType)
    }

    public func delete<R: SecureRecord>(_ type: R.Type, id: R.ID) async throws {
        try await delete(id: id.description, type: R.recordType)
    }

    public func deleteAll<R: SecureRecord>(_ type: R.Type) async throws {
        try await deleteAll(type: R.recordType)
    }

    // MARK: - Untyped API (used by Objective-C)

    public func putData(_ json: Data, id: String, type: String) async throws {
        let state = try await ready()
        let values = try row(type: type, id: id, json: json, state: state)
        try perform { try $0.execute("INSERT OR REPLACE INTO records (type_tag, id_tag, payload) VALUES (?, ?, ?)", values) }
        log.event("db.put", namespace: name, key: type)
    }

    public func data(id: String, type: String) async throws -> Data? {
        let state = try await ready()
        let typeTag = tag(type: type, state)
        let idTag = tag(type: type, id: id, state)
        let rows = try perform { try $0.query("SELECT payload FROM records WHERE type_tag = ? AND id_tag = ?", [.blob(typeTag), .blob(idTag)]) }
        guard let payload = rows.first?.first else { return nil }
        return try open(payload, typeTag: typeTag, idTag: idTag, state: state).json
    }

    public func allData(type: String) async throws -> [Data] {
        let state = try await ready()
        let typeTag = tag(type: type, state)
        let rows = try perform { try $0.query("SELECT id_tag, payload FROM records WHERE type_tag = ?", [.blob(typeTag)]) }
        return try rows.map { try open($0[1], typeTag: typeTag, idTag: $0[0], state: state).json }
    }

    public func count(type: String) async throws -> Int {
        let state = try await ready()
        let rows = try perform { try $0.query("SELECT COUNT(*) FROM records WHERE type_tag = ?", [.blob(tag(type: type, state))]) }
        // COUNT(*) comes back as an integer column read through the blob accessor (text bytes).
        return rows.first?.first.flatMap { Int(String(decoding: $0, as: UTF8.self)) } ?? 0
    }

    public func delete(id: String, type: String) async throws {
        let state = try await ready()
        try perform {
            try $0.execute("DELETE FROM records WHERE type_tag = ? AND id_tag = ?", [.blob(tag(type: type, state)), .blob(tag(type: type, id: id, state))])
        }
    }

    public func deleteAll(type: String) async throws {
        let state = try await ready()
        try perform { try $0.execute("DELETE FROM records WHERE type_tag = ?", [.blob(tag(type: type, state))]) }
    }

    // MARK: - Lifecycle

    /// Re-encrypts every record under a new key version in one transaction (PRD §16–17).
    /// Returns the number of records re-encrypted.
    @discardableResult
    public func rotateKey() async throws -> Int {
        let old = try await ready()
        let id = KeyID(purpose: keyPurpose, domain: old.domain)
        isRotating = true
        defer { isRotating = false }
        let (version, key) = try await keys.rotate(id)
        let new = Self.derive(key, version: version, domain: old.domain)

        let count: Int
        do {
            count = try perform { connection in
                try connection.transaction {
                    let rows = try connection.query("SELECT type_tag, id_tag, payload FROM records")
                    let rewritten = try rows.map { row -> [SQLiteConnection.Value] in
                        let record = try self.open(row[2], typeTag: row[0], idTag: row[1], state: old)
                        return try self.row(type: record.type, id: record.id, json: record.json, state: new)
                    }
                    try connection.execute("DELETE FROM records")
                    for values in rewritten {
                        try connection.execute("INSERT INTO records (type_tag, id_tag, payload) VALUES (?, ?, ?)", values)
                    }
                    try connection.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('keyVersion', ?)", [.blob(Data(String(version).utf8))])
                    return rows.count
                }
            }
        } catch {
            try? await keys.destroy(id, version: version)
            throw SecureVaultError.keyRotationFailed(reason: "\(SecureVaultError.wrap(error).code)")
        }
        state = new
        try? await keys.destroy(id, version: old.version)
        log.event("db.rotate", namespace: name)
        return count
    }

    /// Closes the connection. The next call reopens it. Called when the device locks (PRD §17.4).
    public func close() {
        connection?.close()
        connection = nil
        state = nil
    }

    package func destroyFiles() {
        close()
        try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent())
    }

    package var currentKeyVersion: Int? { state?.version }

    // MARK: - Internals

    private func ready() async throws -> KeyState {
        if let state, connection != nil { return state }
        let fileManager = FileManager.default
        let directory = fileURL.deletingLastPathComponent()
        do {
            var attributes: [FileAttributeKey: Any] = [:]
            #if os(iOS)
            attributes[.protectionKey] = protection.attribute
            #endif
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: attributes)
        } catch {
            throw SecureVaultError.fileFailure(reason: "database directory")
        }
        let isNew = !fileManager.fileExists(atPath: fileURL.path)
        let connection = try SQLiteConnection(path: fileURL.path)
        try connection.execute("PRAGMA journal_mode = WAL")
        try connection.execute("PRAGMA secure_delete = ON")
        try connection.execute("CREATE TABLE IF NOT EXISTS records (type_tag BLOB NOT NULL, id_tag BLOB NOT NULL, payload BLOB NOT NULL, PRIMARY KEY (type_tag, id_tag)) WITHOUT ROWID")
        try connection.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB)")

        let meta = Dictionary(uniqueKeysWithValues: try connection.query("SELECT k, v FROM meta").map {
            (String(decoding: $0[0], as: UTF8.self), String(decoding: $0[1], as: UTF8.self))
        })

        let state: KeyState
        if let versionText = meta["keyVersion"], let version = Int(versionText),
           let domainID = meta["domain"], let domain = KeyDomain(id: domainID) {
            if domain != requestedDomain {
                log.warning("database \(Digest.hex(Digest.sha256(name)).prefix(8)) keeps the policy it was created with")
            }
            let id = KeyID(purpose: keyPurpose, domain: domain)
            let key = try await keys.key(for: id, version: version)
            // Remove versions left by an interrupted rotation (newer, never committed) or a crash after commit (older).
            for stale in try await keys.versions(for: id) where stale != version && !isRotating {
                try? await keys.destroy(id, version: stale)
            }
            state = Self.derive(key, version: version, domain: domain)
        } else {
            let id = KeyID(purpose: keyPurpose, domain: requestedDomain)
            let (version, key) = try await keys.currentKey(for: id)
            try connection.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('keyVersion', ?)", [.blob(Data(String(version).utf8))])
            try connection.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('domain', ?)", [.blob(Data(requestedDomain.id.utf8))])
            try connection.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('format', ?)", [.blob(Data("1".utf8))])
            state = Self.derive(key, version: version, domain: requestedDomain)
        }

        if isNew {
            // Set on the folder so the -wal and -shm files are covered too.
            var folder = directory
            var values = URLResourceValues()
            values.isExcludedFromBackup = state.domain.deviceOnly
            try? folder.setResourceValues(values)
        }
        self.connection = connection
        self.state = state
        return state
    }

    private func perform<T>(_ body: (SQLiteConnection) throws -> T) throws -> T {
        guard let connection else { throw SecureVaultError.databaseFailure(reason: "database is closed") }
        return try body(connection)
    }

    private static func derive(_ key: SymmetricKey, version: Int, domain: KeyDomain) -> KeyState {
        KeyState(
            domain: domain,
            version: version,
            recordKey: KeyDerivation.derive(key, label: "db.records"),
            indexKey: KeyDerivation.derive(key, label: "db.index")
        )
    }

    private func tag(type: String, _ state: KeyState) -> Data {
        KeyDerivation.blindIndex("t|\(type)", key: state.indexKey)
    }

    private func tag(type: String, id: String, _ state: KeyState) -> Data {
        KeyDerivation.blindIndex("i|\(type)|\(id)", key: state.indexKey)
    }

    /// Plaintext layout: typeLength(4) ‖ type ‖ idLength(4) ‖ id ‖ JSON. Type and id travel encrypted so rotation can rebuild the indexes.
    private func row(type: String, id: String, json: Data, state: KeyState) throws -> [SQLiteConnection.Value] {
        let typeTag = tag(type: type, state)
        let idTag = tag(type: type, id: id, state)
        var plaintext = Data()
        for part in [Data(type.utf8), Data(id.utf8)] {
            var length = UInt32(part.count).bigEndian
            withUnsafeBytes(of: &length) { plaintext.append(contentsOf: $0) }
            plaintext.append(part)
        }
        plaintext.append(json)
        let header = EnvelopeHeader(
            algorithm: crypto.algorithm, keyPurpose: keyPurpose, keyDomain: state.domain.id,
            keyVersion: state.version, createdAt: now(), expiresAt: nil
        )
        let payload = try Envelope.seal(plaintext, header: header, key: state.recordKey, context: typeTag + idTag, crypto: crypto)
        return [.blob(typeTag), .blob(idTag), .blob(payload)]
    }

    private func open(_ payload: Data, typeTag: Data, idTag: Data, state: KeyState) throws -> (type: String, id: String, json: Data) {
        let plaintext = try Envelope.open(payload, key: state.recordKey, context: typeTag + idTag, crypto: crypto).plaintext
        var cursor = plaintext.startIndex
        func next() throws -> Data {
            guard plaintext.distance(from: cursor, to: plaintext.endIndex) >= 4 else { throw SecureVaultError.invalidData(reason: "record") }
            let length = plaintext[cursor..<cursor + 4].reduce(0) { ($0 << 8) | Int($1) }
            cursor += 4
            guard plaintext.distance(from: cursor, to: plaintext.endIndex) >= length else { throw SecureVaultError.invalidData(reason: "record") }
            defer { cursor += length }
            return plaintext[cursor..<cursor + length]
        }
        let type = String(decoding: try next(), as: UTF8.self)
        let id = String(decoding: try next(), as: UTF8.self)
        return (type, id, Data(plaintext[cursor...]))
    }

    private func encode<R: Encodable>(_ record: R) throws -> Data {
        do { return try encoder.encode(record) } catch { throw SecureVaultError.invalidData(reason: "record does not encode") }
    }

    private func decode<R: Decodable>(_ type: R.Type, _ data: Data) throws -> R {
        do { return try decoder.decode(R.self, from: data) } catch { throw SecureVaultError.typeMismatch(expected: String(describing: R.self)) }
    }
}
