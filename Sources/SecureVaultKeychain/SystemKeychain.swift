//
//  SystemKeychain.swift
//  SecureVaultKeychain
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import LocalAuthentication
import Security
import SecureVaultCore

/// The data-protection Keychain (PRD §12). Blocking Security calls run on a dedicated queue.
public final class SystemKeychain: KeychainBackend {
    public let accessGroup: String?
    /// Always `true` in apps. Tests on macOS turn it off to reach the login keychain, which needs no entitlement.
    let usesDataProtectionKeychain: Bool
    private let queue = DispatchQueue(label: "com.securevault.keychain", qos: .userInitiated, attributes: .concurrent)

    public init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
        self.usesDataProtectionKeychain = true
    }

    init(accessGroup: String? = nil, usesDataProtectionKeychain: Bool) {
        self.accessGroup = accessGroup
        self.usesDataProtectionKeychain = usesDataProtectionKeychain
    }

    public func set(_ data: Data, service: String, account: String, options: KeychainWriteOptions) async throws {
        try await run {
            var attributes = self.baseQuery(service: service, account: account)
            let access = try Self.accessAttributes(options)
            attributes.merge(access) { $1 }
            attributes[kSecValueData] = data

            var status = SecItemAdd(attributes as CFDictionary, nil)
            guard status == errSecDuplicateItem, options.overwrite else {
                try Self.check(status)
                return
            }
            let existingNeedsAuth = (try? self.infoSync(service: service, account: account))??.requiresUserAuthentication ?? false
            if options.userAuthentication != nil || existingNeedsAuth {
                // Updating an access-controlled item needs a prompt; replace it instead (documented, non-atomic).
                SecItemDelete(self.baseQuery(service: service, account: account) as CFDictionary)
                status = SecItemAdd(attributes as CFDictionary, nil)
            } else {
                var update = access
                update[kSecValueData] = data
                status = SecItemUpdate(self.baseQuery(service: service, account: account) as CFDictionary, update as CFDictionary)
            }
            try Self.check(status)
        }
    }

    public func updateData(_ data: Data, service: String, account: String) async throws {
        try await run {
            let status = SecItemUpdate(
                self.baseQuery(service: service, account: account) as CFDictionary,
                [kSecValueData: data] as CFDictionary
            )
            try Self.check(status)
        }
    }

    public func get(service: String, account: String, authentication: AuthenticationContext?) async throws -> Data {
        try await run {
            var query = self.baseQuery(service: service, account: account)
            query[kSecReturnData] = true
            query[kSecMatchLimit] = kSecMatchLimitOne
            if let authentication {
                query[kSecUseAuthenticationContext] = authentication.laContext
            }
            var result: CFTypeRef?
            try Self.check(SecItemCopyMatching(query as CFDictionary, &result))
            guard let data = result as? Data else { throw SecureVaultError.invalidData(reason: "keychain returned no data") }
            return data
        }
    }

    public func info(service: String, account: String) async throws -> KeychainItemInfo? {
        try await run { try self.infoSync(service: service, account: account) }
    }

    public func delete(service: String, account: String) async throws {
        try await run {
            let status = SecItemDelete(self.baseQuery(service: service, account: account) as CFDictionary)
            if status != errSecItemNotFound { try Self.check(status) }
        }
    }

    public func deleteAll(service: String) async throws {
        try await run {
            let status = SecItemDelete(self.baseQuery(service: service, account: nil) as CFDictionary)
            if status != errSecItemNotFound { try Self.check(status) }
        }
    }

    public func accounts(service: String) async throws -> [String] {
        try await run {
            try self.allAttributes(service: service).compactMap { $0[kSecAttrAccount as String] as? String }
        }
    }

    public func services(withPrefix prefix: String) async throws -> [String] {
        try await run {
            let services = try self.allAttributes(service: nil).compactMap { $0[kSecAttrService as String] as? String }
            return Array(Set(services.filter { $0.hasPrefix(prefix) })).sorted()
        }
    }

    // MARK: - Helpers

    private func run<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        try Task.checkCancellation()
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try body() })
            }
        }
    }

    private func baseQuery(service: String?, account: String?) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain: usesDataProtectionKeychain,
        ]
        if let service { query[kSecAttrService] = service }
        if let account { query[kSecAttrAccount] = account }
        if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
        return query
    }

    private func infoSync(service: String, account: String) throws -> KeychainItemInfo? {
        var query = baseQuery(service: service, account: account)
        query[kSecReturnAttributes] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        // Attributes never require authentication, but make sure no UI can appear.
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        if status == errSecInteractionNotAllowed {
            return KeychainItemInfo(service: service, account: account, requiresUserAuthentication: true, accessibility: nil, deviceOnly: true)
        }
        try Self.check(status)
        guard let attributes = result as? [String: Any] else { return nil }
        let accessible = attributes[kSecAttrAccessible as String] as? String
        let (accessibility, deviceOnly) = Self.decodeAccessible(accessible)
        return KeychainItemInfo(
            service: service,
            account: account,
            requiresUserAuthentication: (attributes[kSecAttrGeneric as String] as? Data) == Self.userAuthenticationMarker,
            accessibility: accessibility,
            deviceOnly: deviceOnly
        )
    }

    private func allAttributes(service: String?) throws -> [[String: Any]] {
        var query = baseQuery(service: service, account: nil)
        query[kSecReturnAttributes] = true
        query[kSecMatchLimit] = kSecMatchLimitAll
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        try Self.check(status)
        return result as? [[String: Any]] ?? []
    }

    /// Written into kSecAttrGeneric so item info can tell, without a prompt, that reads need authentication.
    static let userAuthenticationMarker = Data("sv.ua=1".utf8)
    static let noAuthenticationMarker = Data("sv.ua=0".utf8)

    static func accessAttributes(_ options: KeychainWriteOptions) throws -> [CFString: Any] {
        let accessible = accessibleValue(options.accessibility, deviceOnly: options.deviceOnly)
        guard let authentication = options.userAuthentication else {
            return [kSecAttrAccessible: accessible, kSecAttrGeneric: noAuthenticationMarker]
        }
        let flags: SecAccessControlCreateFlags = switch authentication {
        case .userPresence: .userPresence
        case .biometryAny: .biometryAny
        case .biometryCurrentSet: .biometryCurrentSet
        case .devicePasscode: .devicePasscode
        }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, accessible, flags, &error) else {
            throw SecureVaultError.securityPolicyViolation(reason: "access control could not be created")
        }
        return [kSecAttrAccessControl: control, kSecAttrGeneric: userAuthenticationMarker]
    }

    static func accessibleValue(_ accessibility: Accessibility, deviceOnly: Bool) -> CFString {
        switch (accessibility, deviceOnly) {
        case (.whenUnlocked, true): kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case (.whenUnlocked, false): kSecAttrAccessibleWhenUnlocked
        case (.afterFirstUnlock, true): kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case (.afterFirstUnlock, false): kSecAttrAccessibleAfterFirstUnlock
        case (.whenPasscodeSet, _): kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        }
    }

    static func decodeAccessible(_ value: String?) -> (Accessibility?, Bool) {
        switch value as CFString? {
        case kSecAttrAccessibleWhenUnlockedThisDeviceOnly?: (.whenUnlocked, true)
        case kSecAttrAccessibleWhenUnlocked?: (.whenUnlocked, false)
        case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly?: (.afterFirstUnlock, true)
        case kSecAttrAccessibleAfterFirstUnlock?: (.afterFirstUnlock, false)
        case kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly?: (.whenPasscodeSet, true)
        default: (nil, true)
        }
    }

    static func check(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess: return
        case errSecItemNotFound: throw SecureVaultError.itemNotFound
        case errSecUserCanceled: throw SecureVaultError.userCancelled
        case errSecAuthFailed: throw SecureVaultError.authenticationFailed
        case errSecInteractionNotAllowed: throw SecureVaultError.protectedDataUnavailable
        case errSecMissingEntitlement, -34018: throw SecureVaultError.accessDenied
        case errSecNotAvailable: throw SecureVaultError.accessDenied
        default: throw SecureVaultError.keychainFailure(status: status)
        }
    }
}
