//
//  SVDatabase.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// Encrypted records for Objective-C. Records are JSON dictionaries, so the same data is readable from Swift
/// with a matching `SecureRecord` type whose `recordType` equals `type`.
@objc(SVDatabase) public final class SVDatabase: NSObject, @unchecked Sendable {
    public let database: SecureDatabase

    init(_ database: SecureDatabase) { self.database = database }

    @objc public var name: String { database.name }

    @objc(putRecord:withID:type:completion:)
    public func put(_ record: [String: Any], id: String, type: String, completion: (@Sendable (NSError?) -> Void)?) {
        guard JSONSerialization.isValidJSONObject(record), let json = try? JSONSerialization.data(withJSONObject: record) else {
            deliver(completion) { throw SecureVaultError.invalidData(reason: "record is not JSON-compatible") }
            return
        }
        deliver(completion) { try await self.database.putData(json, id: id, type: type) }
    }

    /// Calls back with `nil` and no error when the record does not exist.
    @objc(recordWithID:type:completion:)
    public func record(id: String, type: String, completion: @escaping @Sendable ([String: Any]?, NSError?) -> Void) {
        deliver({ (value: [String: Any]??, error: NSError?) in completion(value ?? nil, error) }) {
            SendableBox(try await self.database.data(id: id, type: type).map(Self.dictionary))
        } map: { $0.value }
    }

    @objc(allRecordsOfType:completion:)
    public func allRecords(type: String, completion: @escaping @Sendable ([[String: Any]]?, NSError?) -> Void) {
        deliver(completion) {
            SendableBox(try await self.database.allData(type: type).map(Self.dictionary))
        } map: { $0.value }
    }

    @objc(deleteRecordWithID:type:completion:)
    public func delete(id: String, type: String, completion: (@Sendable (NSError?) -> Void)?) {
        deliver(completion) { try await self.database.delete(id: id, type: type) }
    }

    @objc(deleteAllRecordsOfType:completion:)
    public func deleteAll(type: String, completion: (@Sendable (NSError?) -> Void)?) {
        deliver(completion) { try await self.database.deleteAll(type: type) }
    }

    @objc(countRecordsOfType:completion:)
    public func count(type: String, completion: @escaping @Sendable (Int, NSError?) -> Void) {
        deliver({ (value: Int?, error) in completion(value ?? 0, error) }) { try await self.database.count(type: type) }
    }

    private static func dictionary(_ json: Data) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: json) as? [String: Any]) ?? [:]
    }
}

/// Encrypted file storage for Objective-C.
@objc(SVFileStore) public final class SVFileStore: NSObject, @unchecked Sendable {
    public let store: ProtectedFileStore

    init(_ store: ProtectedFileStore) { self.store = store }

    @objc(writeData:named:namespace:policy:completion:)
    public func write(_ data: Data, named name: String, namespace: String?, policy: SVPolicy?, completion: (@Sendable (NSError?) -> Void)?) {
        let target = SVVault.namespace(namespace), resolved = SVVault.policy(policy)
        deliver(completion) { try await self.store.write(data, named: name, namespace: target, policy: resolved) }
    }

    @objc(writeContentsOfURL:named:namespace:policy:completion:)
    public func write(contentsOf url: URL, named name: String, namespace: String?, policy: SVPolicy?, completion: (@Sendable (NSError?) -> Void)?) {
        let target = SVVault.namespace(namespace), resolved = SVVault.policy(policy)
        deliver(completion) { try await self.store.write(contentsOf: url, named: name, namespace: target, policy: resolved) }
    }

    @objc(readDataNamed:namespace:completion:)
    public func read(named name: String, namespace: String?, completion: @escaping @Sendable (Data?, NSError?) -> Void) {
        let target = SVVault.namespace(namespace)
        deliver(completion) { try await self.store.read(named: name, namespace: target) }
    }

    @objc(exportFileNamed:namespace:toURL:completion:)
    public func export(named name: String, namespace: String?, to url: URL, completion: (@Sendable (NSError?) -> Void)?) {
        let target = SVVault.namespace(namespace)
        deliver(completion) { try await self.store.export(named: name, namespace: target, to: url) }
    }

    @objc(deleteFileNamed:namespace:completion:)
    public func delete(named name: String, namespace: String?, completion: (@Sendable (NSError?) -> Void)?) {
        let target = SVVault.namespace(namespace)
        deliver(completion) { try await self.store.delete(named: name, namespace: target) }
    }

    /// File names in a namespace.
    @objc(listFilesInNamespace:completion:)
    public func list(namespace: String?, completion: @escaping @Sendable ([String]?, NSError?) -> Void) {
        let target = SVVault.namespace(namespace)
        deliver(completion) { try await self.store.list(namespace: target).map(\.name) }
    }
}

/// Biometric helpers for Objective-C.
@objc(SVBiometrics) public final class SVBiometrics: NSObject {
    /// `none`, `touchID`, `faceID` or `opticID`.
    @objc public static var biometryType: String { BiometricAuthenticator().biometryKind.rawValue }
    @objc public static var isAvailable: Bool { BiometricAuthenticator().isBiometryAvailable }

    @objc(authenticateWithReason:completion:)
    public static func authenticate(reason: String, completion: @escaping @Sendable (Bool, NSError?) -> Void) {
        authenticate(reason: reason, using: BiometricAuthenticator(), completion: completion)
    }

    static func authenticate(reason: String, using authenticator: BiometricAuthenticator, completion: @escaping @Sendable (Bool, NSError?) -> Void) {
        deliver({ (value: Bool?, error) in completion(value ?? false, error) }) {
            _ = try await authenticator.authenticate(reason: reason)
            return true
        }
    }
}
