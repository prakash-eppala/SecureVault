//
//  ProtectedFileStore.swift
//  SecureVaultFiles
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation
#if canImport(SecureVaultCore)
import SecureVaultCore
#endif
#if canImport(SecureVaultCrypto)
import SecureVaultCrypto
#endif

/// What `list(namespace:)` reports. Decrypted from the file; never stored in plaintext.
public struct ProtectedFileInfo: Sendable, Codable, Equatable {
    public let name: String
    public let size: Int64
    public let createdAt: Date
}

/// Encrypted, streaming file storage with Data Protection (PRD §19).
///
/// File layout: `SVF1` ‖ headerLength(4) ‖ header JSON ‖ metadataLength(4) ‖ sealed metadata ‖ chunks.
/// Chunks are 64 KiB of plaintext plus a 16-byte tag, sealed by `StreamCipher`.
public actor ProtectedFileStore {
    public nonisolated let root: URL
    private let vaultID: String
    private let keys: KeyManager
    private let capabilities: any DeviceCapabilities
    private let log: VaultLog
    private let now: @Sendable () -> Date
    /// The vault's one-time setup (reinstall handling). Runs before any key is touched.
    private let prepare: @Sendable () async throws -> Void
    private let requireSecureEnclave: Bool
    private let fileManager = FileManager.default

    static let purpose = "files"
    static let magic = Data("SVF1".utf8)
    static let algorithm = "A256GCM-STREAM64K"

    private struct Header: Codable {
        var alg: String
        var kp: String
        var kd: String
        var kv: Int
        var salt: Data
        var np: Data
    }

    package init(root: URL, vaultID: String, keys: KeyManager, capabilities: any DeviceCapabilities,
                 log: VaultLog, now: @escaping @Sendable () -> Date,
                 requireSecureEnclave: Bool = false,
                 prepare: @escaping @Sendable () async throws -> Void = {}) {
        self.prepare = prepare
        self.requireSecureEnclave = requireSecureEnclave
        self.root = root
        self.vaultID = vaultID
        self.keys = keys
        self.capabilities = capabilities
        self.log = log
        self.now = now
    }

    // MARK: - Public API

    public func write(_ data: Data, named name: String, namespace: VaultNamespace = .default, policy: StoragePolicy = .sensitive) async throws {
        var offset = 0
        try await write(named: name, namespace: namespace, policy: policy, size: Int64(data.count)) {
            let end = min(offset + StreamCipher.chunkSize, data.count)
            defer { offset = end }
            return data.subdata(in: offset..<end)
        }
    }

    /// Streams `source` into encrypted storage without loading it into memory.
    public func write(contentsOf source: URL, named name: String, namespace: VaultNamespace = .default, policy: StoragePolicy = .sensitive) async throws {
        let handle: FileHandle
        do { handle = try FileHandle(forReadingFrom: source) } catch { throw SecureVaultError.fileFailure(reason: "source unreadable") }
        defer { try? handle.close() }
        let size = (try? fileManager.attributesOfItem(atPath: source.path)[.size] as? NSNumber)?.int64Value ?? 0
        try await write(named: name, namespace: namespace, policy: policy, size: size) {
            try handle.read(upToCount: StreamCipher.chunkSize) ?? Data()
        }
    }

    public func read(named name: String, namespace: VaultNamespace = .default) async throws -> Data {
        try await prepare()
        var output = Data()
        try await decrypt(at: fileURL(name, namespace), context: context(name, namespace)) { output.append($0) }
        return output
    }

    /// Streams the decrypted file to `destination`. The output is plaintext: protect or delete it after use.
    public func export(named name: String, namespace: VaultNamespace = .default, to destination: URL) async throws {
        try await prepare()
        guard fileManager.createFile(atPath: destination.path, contents: nil, attributes: Self.protectionAttributes(.complete)) else {
            throw SecureVaultError.fileFailure(reason: "destination unwritable")
        }
        let handle = try FileHandle(forWritingTo: destination)
        defer { try? handle.close() }
        do {
            try await decrypt(at: fileURL(name, namespace), context: context(name, namespace)) { try handle.write(contentsOf: $0) }
        } catch {
            try? fileManager.removeItem(at: destination)
            throw error
        }
    }

    public func exists(named name: String, namespace: VaultNamespace = .default) -> Bool {
        fileManager.fileExists(atPath: fileURL(name, namespace).path)
    }

    public func delete(named name: String, namespace: VaultNamespace = .default) throws {
        let url = fileURL(name, namespace)
        guard fileManager.fileExists(atPath: url.path) else { return }
        do { try fileManager.removeItem(at: url) } catch { throw SecureVaultError.fileFailure(reason: "delete") }
    }

    public func list(namespace: VaultNamespace = .default) async throws -> [ProtectedFileInfo] {
        try await prepare()
        var result: [ProtectedFileInfo] = []
        for url in files(in: namespaceDirectory(namespace)) {
            let (_, info, _) = try await openHeader(at: url, context: nil)
            result.append(info)
        }
        return result.sorted { $0.name < $1.name }
    }

    public func clear(namespace: VaultNamespace) throws {
        let directory = namespaceDirectory(namespace)
        guard fileManager.fileExists(atPath: directory.path) else { return }
        do { try fileManager.removeItem(at: directory) } catch { throw SecureVaultError.fileFailure(reason: "clear") }
    }

    public func clearAll() throws {
        guard fileManager.fileExists(atPath: root.path) else { return }
        do { try fileManager.removeItem(at: root) } catch { throw SecureVaultError.fileFailure(reason: "clear") }
    }

    /// Deletes files whose key version no longer exists (e.g. device-only files after a restore). Returns files removed.
    @discardableResult
    public func purgeUnreadable() async throws -> Int {
        try await prepare()
        var removed = 0
        let namespaces = (try? fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
        for url in namespaces.flatMap(files(in:)) {
            do {
                _ = try await openHeader(at: url, context: nil)
            } catch SecureVaultError.keyUnavailable {
                try? fileManager.removeItem(at: url)
                removed += 1
            }
        }
        return removed
    }

    public func count() -> Int {
        let namespaces = (try? fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
        return namespaces.reduce(0) { $0 + files(in: $1).count }
    }

    /// Re-encrypts every file under the newest key version, then deletes old versions. Returns files rewritten.
    @discardableResult
    public func rotateKeys() async throws -> Int {
        try await prepare()
        var rewritten = 0
        let families = try await keys.allKeyIDs().filter { $0.key.purpose == Self.purpose }
        for (id, _) in families {
            _ = try await keys.rotate(id)
        }
        let namespaces = (try? fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
        for url in namespaces.flatMap(files(in:)) {
            let (header, info, context) = try await openHeader(at: url, context: nil)
            guard let domain = KeyDomain(id: header.kd) else { continue }
            let id = KeyID(purpose: Self.purpose, domain: domain)
            let current = try await keys.currentKey(for: id)
            guard header.kv < current.version else { continue }
            try await reencrypt(url, info: info, context: context, domain: domain)
            rewritten += 1
        }
        for (id, _) in try await keys.allKeyIDs().filter({ $0.key.purpose == Self.purpose }) {
            let versions = try await keys.versions(for: id)
            for stale in versions.dropLast() { try await keys.destroy(id, version: stale) }
        }
        log.event("files.rotate")
        return rewritten
    }

    // MARK: - Encryption

    private func write(named name: String, namespace: VaultNamespace, policy: StoragePolicy, size: Int64,
                       next: () throws -> Data) async throws {
        try await prepare()
        try PolicyEngine.validate(policy, capabilities: capabilities, requireSecureEnclave: requireSecureEnclave)
        if policy.userAuthentication != nil {
            throw SecureVaultError.securityPolicyViolation(reason: "biometric-gated files are not supported in V1")
        }
        let domain = KeyDomain(accessibility: policy.accessibility, deviceOnly: policy.deviceOnly)
        let destination = fileURL(name, namespace)
        let info = ProtectedFileInfo(name: name, size: size, createdAt: now())
        try await encrypt(to: destination, info: info, context: context(name, namespace), domain: domain, next: next)
        log.event("files.write", namespace: namespace.rawValue, key: name)
    }

    private func encrypt(to destination: URL, info: ProtectedFileInfo, context: Data, domain: KeyDomain, next: () throws -> Data) async throws {
        let (version, key) = try await keys.currentKey(for: KeyID(purpose: Self.purpose, domain: domain))
        let header = Header(alg: Self.algorithm, kp: Self.purpose, kd: domain.id, kv: version,
                            salt: KeyDerivation.randomBytes(32), np: KeyDerivation.randomBytes(7))
        let headerJSON = try JSONEncoder().encode(header)
        var prefix = Self.magic
        prefix.append(Self.uint32(headerJSON.count))
        prefix.append(headerJSON)

        let cipher = StreamCipher(dataKey: key, salt: header.salt, noncePrefix: header.np, header: prefix, context: context)
        let metadataKey = StreamCipher.metadataKey(dataKey: key, salt: header.salt)
        let metadata = try AESGCMProvider().seal(try JSONEncoder().encode(info), using: metadataKey,
                                                  authenticating: Data(SHA256.hash(data: prefix + context)))

        let directory = destination.deletingLastPathComponent()
        let protection = domain.accessibility.fileProtection
        let temporary = directory.appendingPathComponent(".\(UUID().uuidString).tmp")
        do {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            guard fileManager.createFile(atPath: temporary.path, contents: nil, attributes: Self.protectionAttributes(protection)) else {
                throw SecureVaultError.fileFailure(reason: "temporary file")
            }
            let handle = try FileHandle(forWritingTo: temporary)
            defer { try? handle.close() }
            try handle.write(contentsOf: prefix + Self.uint32(metadata.count) + metadata)

            var index: UInt32 = 0
            var current = try next()
            while true {
                try Task.checkCancellation()
                let following = current.count == StreamCipher.chunkSize ? try next() : Data()
                let isLast = following.isEmpty
                try handle.write(contentsOf: try cipher.seal(chunk: current, index: index, isLast: isLast))
                if isLast { break }
                current = following
                index += 1
            }
            try handle.synchronize()
            try handle.close()

            if fileManager.fileExists(atPath: destination.path) {
                _ = try fileManager.replaceItemAt(destination, withItemAt: temporary)
            } else {
                try fileManager.moveItem(at: temporary, to: destination)
            }
            var url = destination
            var values = URLResourceValues()
            values.isExcludedFromBackup = domain.deviceOnly
            try? url.setResourceValues(values)
        } catch {
            try? fileManager.removeItem(at: temporary)
            if let error = error as? SecureVaultError { throw error }
            if error is CancellationError { throw SecureVaultError.cancelled }
            throw SecureVaultError.fileFailure(reason: "write")
        }
    }

    private func decrypt(at url: URL, context: Data, sink: (Data) throws -> Void) async throws {
        let reader = try await chunks(at: url, context: context)
        defer { reader.close() }
        while !reader.isFinished {
            try Task.checkCancellation()
            try sink(try reader.next())
        }
    }

    /// Opens a file for pull-style decryption. The caller closes the reader.
    private func chunks(at url: URL, context: Data) async throws -> ChunkReader {
        guard fileManager.fileExists(atPath: url.path) else { throw SecureVaultError.itemNotFound }
        let (header, _, prefix, handle) = try await openFile(at: url, context: context)
        do {
            guard let domain = KeyDomain(id: header.kd) else { throw SecureVaultError.invalidData(reason: "file key domain") }
            let key = try await keys.key(for: KeyID(purpose: Self.purpose, domain: domain), version: header.kv)
            let cipher = StreamCipher(dataKey: key, salt: header.salt, noncePrefix: header.np, header: prefix, context: context)
            return try ChunkReader(handle: handle, cipher: cipher)
        } catch {
            try? handle.close()
            throw error
        }
    }

    /// Re-encrypts straight from the old file into the new one, so no plaintext ever reaches the disk.
    private func reencrypt(_ url: URL, info: ProtectedFileInfo, context: Data, domain: KeyDomain) async throws {
        let reader = try await chunks(at: url, context: context)
        defer { reader.close() }
        try await encrypt(to: url, info: info, context: context, domain: domain) {
            reader.isFinished ? Data() : try reader.next()
        }
    }

    // MARK: - Header

    private func openHeader(at url: URL, context: Data?) async throws -> (Header, ProtectedFileInfo, Data) {
        let context = context ?? (EncryptedObjectStore.data(fromHex: url.deletingPathExtension().lastPathComponent) ?? Data())
        let (header, info, _, handle) = try await openFile(at: url, context: context)
        try? handle.close()
        return (header, info, context)
    }

    private func openFile(at url: URL, context: Data) async throws -> (Header, ProtectedFileInfo, Data, FileHandle) {
        let handle: FileHandle
        do { handle = try FileHandle(forReadingFrom: url) } catch { throw EncryptedObjectStore.map(error) }
        do {
            let start = try read(handle, 8)
            guard start.count == 8, start.prefix(4) == Self.magic else { throw SecureVaultError.invalidData(reason: "not a SecureVault file") }
            let headerLength = Self.readUInt32(start.suffix(4))
            let headerJSON = try read(handle, headerLength)
            guard headerJSON.count == headerLength, let header = try? JSONDecoder().decode(Header.self, from: headerJSON),
                  header.alg == Self.algorithm, header.np.count == 7 else {
                throw SecureVaultError.invalidData(reason: "file header")
            }
            let prefix = start + headerJSON
            let metadataLength = Self.readUInt32(try read(handle, 4))
            let metadata = try read(handle, metadataLength)
            guard let domain = KeyDomain(id: header.kd) else { throw SecureVaultError.invalidData(reason: "file key domain") }
            let key = try await keys.key(for: KeyID(purpose: Self.purpose, domain: domain), version: header.kv)
            let metadataKey = StreamCipher.metadataKey(dataKey: key, salt: header.salt)
            let infoJSON: Data
            do {
                infoJSON = try AESGCMProvider().open(metadata, using: metadataKey, authenticating: Data(SHA256.hash(data: prefix + context)))
            } catch {
                throw SecureVaultError.decryptionFailed
            }
            guard let info = try? JSONDecoder().decode(ProtectedFileInfo.self, from: infoJSON) else {
                throw SecureVaultError.invalidData(reason: "file metadata")
            }
            return (header, info, prefix, handle)
        } catch {
            try? handle.close()
            throw error
        }
    }

    // MARK: - Paths and helpers

    private func namespaceDirectory(_ namespace: VaultNamespace) -> URL {
        root.appendingPathComponent(Digest.hex(Digest.sha256(namespace.rawValue)), isDirectory: true)
    }

    private func context(_ name: String, _ namespace: VaultNamespace) -> Data {
        Digest.sha256(vaultID, "files", namespace.rawValue, name)
    }

    private func fileURL(_ name: String, _ namespace: VaultNamespace) -> URL {
        namespaceDirectory(namespace).appendingPathComponent(Digest.hex(context(name, namespace))).appendingPathExtension("svf")
    }

    private func files(in directory: URL) -> [URL] {
        ((try? fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.pathExtension == "svf" }
    }

    private func read(_ handle: FileHandle, _ count: Int) throws -> Data {
        do { return try handle.read(upToCount: count) ?? Data() } catch { throw SecureVaultError.fileFailure(reason: "read") }
    }

    static func protectionAttributes(_ level: FileProtectionLevel) -> [FileAttributeKey: Any]? {
        #if os(iOS)
        return [.protectionKey: level.attribute]
        #else
        return nil
        #endif
    }

    static func uint32(_ value: Int) -> Data {
        var big = UInt32(value).bigEndian
        return withUnsafeBytes(of: &big) { Data($0) }
    }

    static func readUInt32(_ data: Data) -> Int {
        data.reduce(0) { ($0 << 8) | Int($1) }
    }
}

/// Yields a file's plaintext one authenticated chunk at a time. The final chunk is only accepted once the
/// reader has seen that nothing follows it, so truncation fails.
private final class ChunkReader {
    private let handle: FileHandle
    private let cipher: StreamCipher
    private var pending: Data
    private var index: UInt32 = 0
    private(set) var isFinished = false

    init(handle: FileHandle, cipher: StreamCipher) throws {
        self.handle = handle
        self.cipher = cipher
        self.pending = try Self.read(handle)
        guard !pending.isEmpty else { throw SecureVaultError.decryptionFailed } // truncated before the final chunk
    }

    func next() throws -> Data {
        let following = try Self.read(handle)
        let isLast = following.isEmpty
        let plaintext = try cipher.open(chunk: pending, index: index, isLast: isLast)
        if isLast { isFinished = true } else { pending = following; index += 1 }
        return plaintext
    }

    func close() { try? handle.close() }

    private static func read(_ handle: FileHandle) throws -> Data {
        do { return try handle.read(upToCount: StreamCipher.chunkSize + StreamCipher.tagSize) ?? Data() } catch {
            throw SecureVaultError.fileFailure(reason: "read")
        }
    }
}
