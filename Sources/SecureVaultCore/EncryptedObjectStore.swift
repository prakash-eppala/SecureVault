//
//  EncryptedObjectStore.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// Envelope files for values not placed in the Keychain (PRD §11).
/// Layout: `<root>/<sha256(namespace)>/<sha256(vaultID|namespace|key)>`. Key names never reach the disk.
public actor EncryptedObjectStore {
    public let root: URL
    private let vaultID: String
    private let fileManager = FileManager.default

    public init(root: URL, vaultID: String) {
        self.root = root
        self.vaultID = vaultID
    }

    /// The associated-data context binding a value to its location.
    public nonisolated func context(namespace: String, key: String) -> Data {
        Digest.sha256(vaultID, namespace, key)
    }

    public func write(_ data: Data, namespace: String, key: String, protection: FileProtectionLevel, excludeFromBackup: Bool) throws {
        let directory = namespaceDirectory(namespace)
        let file = directory.appendingPathComponent(Digest.hex(context(namespace: namespace, key: key)))
        do {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            var options: Data.WritingOptions = [.atomic]
            #if os(iOS)
            switch protection {
            case .complete: options.insert(.completeFileProtection)
            case .completeUntilFirstUserAuthentication: options.insert(.completeFileProtectionUntilFirstUserAuthentication)
            }
            #endif
            try data.write(to: file, options: options)
            var url = file
            var values = URLResourceValues()
            values.isExcludedFromBackup = excludeFromBackup
            try url.setResourceValues(values)
        } catch {
            throw Self.map(error)
        }
    }

    public func read(namespace: String, key: String) throws -> Data {
        try read(at: fileURL(namespace: namespace, key: key))
    }

    public func read(at url: URL) throws -> Data {
        do {
            return try Data(contentsOf: url)
        } catch {
            throw Self.map(error)
        }
    }

    public func exists(namespace: String, key: String) -> Bool {
        fileManager.fileExists(atPath: fileURL(namespace: namespace, key: key).path)
    }

    public func delete(namespace: String, key: String) throws {
        let url = fileURL(namespace: namespace, key: key)
        guard fileManager.fileExists(atPath: url.path) else { return }
        do { try fileManager.removeItem(at: url) } catch { throw Self.map(error) }
    }

    public func deleteNamespace(_ namespace: String) throws {
        let url = namespaceDirectory(namespace)
        guard fileManager.fileExists(atPath: url.path) else { return }
        do { try fileManager.removeItem(at: url) } catch { throw Self.map(error) }
    }

    public func deleteAll() throws {
        guard fileManager.fileExists(atPath: root.path) else { return }
        do { try fileManager.removeItem(at: root) } catch { throw Self.map(error) }
    }

    /// Every stored file with its location context, for rotation and sweeps.
    public func allFiles() -> [(url: URL, context: Data)] {
        guard let namespaces = try? fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else { return [] }
        return namespaces.flatMap { directory -> [(URL, Data)] in
            let files = (try? fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
            return files.compactMap { url in Self.data(fromHex: url.lastPathComponent).map { (url, $0) } }
        }
    }

    /// Atomically replaces a file found through `allFiles()`, keeping its protection.
    public func replace(at url: URL, with data: Data) throws {
        do {
            let attributes = try? fileManager.attributesOfItem(atPath: url.path)
            try data.write(to: url, options: .atomic)
            if let protection = attributes?[.protectionKey] {
                try? fileManager.setAttributes([.protectionKey: protection], ofItemAtPath: url.path)
            }
        } catch {
            throw Self.map(error)
        }
    }

    public func removeFile(at url: URL) throws {
        do { try fileManager.removeItem(at: url) } catch { throw Self.map(error) }
    }

    public func count(namespace: String? = nil) -> Int {
        if let namespace {
            return (try? fileManager.contentsOfDirectory(atPath: namespaceDirectory(namespace).path).count) ?? 0
        }
        return allFiles().count
    }

    // MARK: -

    private func namespaceDirectory(_ namespace: String) -> URL {
        root.appendingPathComponent(Digest.hex(Digest.sha256(namespace)), isDirectory: true)
    }

    private func fileURL(namespace: String, key: String) -> URL {
        namespaceDirectory(namespace).appendingPathComponent(Digest.hex(context(namespace: namespace, key: key)))
    }

    package static func data(fromHex hex: String) -> Data? {
        guard hex.count == 64 else { return nil }
        var data = Data(capacity: 32)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }

    package static func map(_ error: any Error) -> SecureVaultError {
        let nsError = error as NSError
        if nsError.domain == NSCocoaErrorDomain {
            switch nsError.code {
            case NSFileReadNoSuchFileError, NSFileNoSuchFileError: return .itemNotFound
            case NSFileReadNoPermissionError, NSFileWriteNoPermissionError: return .protectedDataUnavailable
            default: break
            }
        }
        if nsError.domain == NSPOSIXErrorDomain, nsError.code == Int(EPERM) || nsError.code == Int(EACCES) {
            return .protectedDataUnavailable
        }
        return .fileFailure(reason: "\(nsError.domain) \(nsError.code)")
    }
}
