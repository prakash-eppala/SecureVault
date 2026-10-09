//
//  SVVault.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// The Objective-C entry point. Completion blocks are always called on the main queue.
///
///     [SVVault.sharedVault setString:token forKey:@"accessToken" namespace:@"auth"
///                             policy:SVPolicy.accessToken completion:^(NSError *error) { … }];
@objc(SVVault) public final class SVVault: NSObject, @unchecked Sendable {
    /// The underlying Swift vault, for mixed codebases.
    public let vault: SecureVault

    @objc public static let sharedVault = SVVault(vault: .shared)

    /// SDK version, e.g. `1.0.0`.
    @objc public static var sdkVersion: String { SecureVault.version }
    /// SDK build number.
    @objc public static var sdkBuild: Int { SecureVault.build }

    public init(vault: SecureVault) {
        self.vault = vault
    }

    /// A vault with its own identifier (separate Keychain items and files).
    @objc public convenience init(identifier: String) {
        self.init(vault: SecureVault(configuration: .init(identifier: identifier)))
    }

    /// An isolated, non-persistent vault for unit tests. Never use it in production.
    @objc public static func inMemoryVaultForTesting() -> SVVault {
        SVVault(vault: SecureVault(configuration: .testing()))
    }

    // MARK: Write

    @objc(setData:forKey:namespace:policy:completion:)
    public func set(_ data: Data, forKey key: String, namespace: String?, policy: SVPolicy?, completion: (@Sendable (NSError?) -> Void)?) {
        let target = Self.namespace(namespace), resolved = Self.policy(policy)
        deliver(completion) { try await self.vault.store(data, forKey: key, namespace: target, policy: resolved) }
    }

    @objc(setString:forKey:namespace:policy:completion:)
    public func set(_ string: String, forKey key: String, namespace: String?, policy: SVPolicy?, completion: (@Sendable (NSError?) -> Void)?) {
        let target = Self.namespace(namespace), resolved = Self.policy(policy)
        deliver(completion) { try await self.vault.store(string, forKey: key, namespace: target, policy: resolved) }
    }

    /// Stores an `NSNumber` as a JSON number (readable in Swift as `Double`, or `Int` for integral values).
    @objc(setNumber:forKey:namespace:policy:completion:)
    public func set(_ number: NSNumber, forKey key: String, namespace: String?, policy: SVPolicy?, completion: (@Sendable (NSError?) -> Void)?) {
        let target = Self.namespace(namespace), resolved = Self.policy(policy)
        // JSONSerialization raises an Objective-C exception for NaN and infinity, so reject them first.
        guard number.doubleValue.isFinite,
              let json = try? JSONSerialization.data(withJSONObject: number, options: .fragmentsAllowed) else {
            deliver(completion) { throw SecureVaultError.invalidData(reason: "number does not encode as JSON") }
            return
        }
        deliver(completion) { try await self.vault.storeEncoded(json, forKey: key, namespace: target, policy: resolved) }
    }

    /// Archives any `NSSecureCoding` object with secure coding.
    @objc(setObject:forKey:namespace:policy:completion:)
    public func set(_ object: NSObject & NSSecureCoding, forKey key: String, namespace: String?, policy: SVPolicy?, completion: (@Sendable (NSError?) -> Void)?) {
        let archived: Data
        do {
            archived = try NSKeyedArchiver.archivedData(withRootObject: object, requiringSecureCoding: true)
        } catch {
            deliver(completion) { throw SecureVaultError.invalidData(reason: "object does not archive") }
            return
        }
        set(archived, forKey: key, namespace: namespace, policy: policy, completion: completion)
    }

    // MARK: Read

    /// Returns `nil` with `SVErrorCodeItemNotFound` when absent.
    @objc(dataForKey:namespace:completion:)
    public func data(forKey key: String, namespace: String?, completion: @escaping @Sendable (Data?, NSError?) -> Void) {
        let target = Self.namespace(namespace)
        deliver(completion) { try await self.vault.retrieve(Data.self, forKey: key, namespace: target) }
    }

    @objc(stringForKey:namespace:completion:)
    public func string(forKey key: String, namespace: String?, completion: @escaping @Sendable (String?, NSError?) -> Void) {
        let target = Self.namespace(namespace)
        deliver(completion) { try await self.vault.retrieve(String.self, forKey: key, namespace: target) }
    }

    @objc(numberForKey:namespace:completion:)
    public func number(forKey key: String, namespace: String?, completion: @escaping @Sendable (NSNumber?, NSError?) -> Void) {
        let target = Self.namespace(namespace)
        deliver(completion) {
            let json = try await self.vault.retrieveEncoded(forKey: key, namespace: target, authentication: nil)
            guard let number = try? JSONSerialization.jsonObject(with: json, options: .fragmentsAllowed) as? NSNumber else {
                throw SecureVaultError.typeMismatch(expected: "NSNumber")
            }
            return SendableBox(number)
        } map: { $0.value }
    }

    @objc(objectOfClasses:forKey:namespace:completion:)
    public func object(ofClasses classes: [AnyClass], forKey key: String, namespace: String?, completion: @escaping @Sendable (Any?, NSError?) -> Void) {
        let target = Self.namespace(namespace)
        let allowed = SendableBox(classes)
        deliver(completion) {
            let data = try await self.vault.retrieve(Data.self, forKey: key, namespace: target)
            guard let object = try? NSKeyedUnarchiver.unarchivedObject(ofClasses: allowed.value, from: data) else {
                throw SecureVaultError.typeMismatch(expected: "archived object")
            }
            return SendableBox(object)
        } map: { $0.value }
    }

    // MARK: Manage

    @objc(containsKey:namespace:completion:)
    public func contains(key: String, namespace: String?, completion: @escaping @Sendable (Bool, NSError?) -> Void) {
        let target = Self.namespace(namespace)
        deliver({ (value: Bool?, error) in completion(value ?? false, error) }) {
            try await self.vault.exists(forKey: key, namespace: target)
        }
    }

    @objc(removeKey:namespace:completion:)
    public func remove(key: String, namespace: String?, completion: (@Sendable (NSError?) -> Void)?) {
        let target = Self.namespace(namespace)
        deliver(completion) { try await self.vault.delete(forKey: key, namespace: target) }
    }

    @objc(clearNamespace:completion:)
    public func clear(namespace: String, completion: (@Sendable (NSError?) -> Void)?) {
        deliver(completion) { try await self.vault.clear(namespace: VaultNamespace(namespace)) }
    }

    /// Clears the session namespaces (`auth`, `session`, `cache` by default).
    @objc(logoutWithCompletion:)
    public func logout(completion: (@Sendable (NSError?) -> Void)?) {
        deliver(completion) { try await self.vault.logout() }
    }

    /// Destroys every key, item, file and database in this vault.
    @objc(resetWithCompletion:)
    public func reset(completion: (@Sendable (NSError?) -> Void)?) {
        deliver(completion) { try await self.vault.reset() }
    }

    @objc(rotateKeysWithCompletion:)
    public func rotateKeys(completion: (@Sendable (NSError?) -> Void)?) {
        deliver(completion) { _ = try await self.vault.rotateKeys() }
    }

    @objc(purgeExpiredWithCompletion:)
    public func purgeExpired(completion: (@Sendable (NSError?) -> Void)?) {
        deliver(completion) { _ = try await self.vault.purgeExpired() }
    }

    /// Migrates a UserDefaults string into the vault, deleting the source only after verification.
    @objc(migrateUserDefaultsStringForKey:suiteName:toKey:namespace:policy:completion:)
    public func migrateUserDefaultsString(
        _ defaultsKey: String, suiteName: String?, toKey key: String, namespace: String?, policy: SVPolicy?,
        completion: (@Sendable (NSError?) -> Void)?
    ) {
        let item = MigrationItem.userDefaults(
            defaultsKey, suiteName: suiteName, as: String.self, to: key,
            namespace: Self.namespace(namespace), policy: Self.policy(policy)
        )
        deliver(completion) {
            let report = await self.vault.migrate([item])
            if let failure = report.failed.first { throw failure.error }
        }
    }

    // MARK: Databases, files, diagnostics

    @objc(databaseNamed:policy:completion:)
    public func database(named name: String, policy: SVPolicy?, completion: @escaping @Sendable (SVDatabase?, NSError?) -> Void) {
        let resolved = policy?.swiftPolicy ?? .highlySensitive
        deliver(completion) { SVDatabase(try await self.vault.database(name, policy: resolved)) }
    }

    @objc(deleteDatabaseNamed:completion:)
    public func deleteDatabase(named name: String, completion: (@Sendable (NSError?) -> Void)?) {
        deliver(completion) { try await self.vault.deleteDatabase(name) }
    }

    @objc public var fileStore: SVFileStore { SVFileStore(vault.files) }

    /// The security report as a JSON-compatible dictionary (never contains values or key names).
    @objc(securityReportWithCompletion:)
    public func securityReport(completion: @escaping @Sendable ([String: Any]?, NSError?) -> Void) {
        deliver(completion) {
            let data = try JSONEncoder().encode(await self.vault.securityReport())
            return SendableBox(try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:])
        } map: { $0.value }
    }

    // MARK: Helpers

    static func namespace(_ value: String?) -> VaultNamespace {
        value.map { VaultNamespace($0) } ?? .default
    }

    static func policy(_ value: SVPolicy?) -> StoragePolicy {
        value?.swiftPolicy ?? .sensitive
    }
}

/// Carries a non-Sendable Objective-C value to the main queue, where it is handed straight to the caller.
struct SendableBox<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
}

func deliver<Boxed: Sendable, T>(
    _ completion: @escaping @Sendable (T?, NSError?) -> Void,
    _ work: @escaping @Sendable () async throws -> Boxed,
    map: @escaping @Sendable (Boxed) -> T
) {
    deliver({ (boxed: Boxed?, error: NSError?) in completion(boxed.map(map), error) }, work)
}
