//
//  SVTypes.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// Mirrors `SecureVaultError.code`. Errors arrive as `NSError` in domain `SVErrorDomain`.
@objc public enum SVErrorCode: Int {
    case itemNotFound = 1
    case invalidData = 2
    case typeMismatch = 3
    case encryptionFailed = 4
    case decryptionFailed = 5
    case keyUnavailable = 6
    case keyRotationFailed = 7
    case authenticationRequired = 8
    case authenticationFailed = 9
    case userCancelled = 10
    case biometryNotAvailable = 11
    case biometryLockout = 12
    case accessDenied = 13
    case protectedDataUnavailable = 14
    case expired = 15
    case migrationFailed = 16
    case databaseFailure = 17
    case fileFailure = 18
    case securityPolicyViolation = 19
    case keychainFailure = 20
    case cancelled = 21
}

@objc public enum SVClassification: Int {
    case standard, sensitive, secret, highlySensitive, biometricProtected

    var swift: DataClassification { DataClassification(rawValue: rawValue)! }
}

@objc public enum SVAccessibility: Int {
    case whenUnlocked, afterFirstUnlock, whenPasscodeSet

    init(_ value: Accessibility) {
        switch value {
        case .whenUnlocked: self = .whenUnlocked
        case .afterFirstUnlock: self = .afterFirstUnlock
        case .whenPasscodeSet: self = .whenPasscodeSet
        }
    }

    var swift: Accessibility {
        switch self {
        case .whenUnlocked: .whenUnlocked
        case .afterFirstUnlock: .afterFirstUnlock
        case .whenPasscodeSet: .whenPasscodeSet
        }
    }
}

@objc public enum SVUserAuthentication: Int {
    case none, userPresence, biometryAny, biometryCurrentSet, devicePasscode

    init(_ value: UserAuthentication?) {
        switch value {
        case nil: self = .none
        case .userPresence?: self = .userPresence
        case .biometryAny?: self = .biometryAny
        case .biometryCurrentSet?: self = .biometryCurrentSet
        case .devicePasscode?: self = .devicePasscode
        }
    }

    var swift: UserAuthentication? {
        switch self {
        case .none: nil
        case .userPresence: .userPresence
        case .biometryAny: .biometryAny
        case .biometryCurrentSet: .biometryCurrentSet
        case .devicePasscode: .devicePasscode
        }
    }
}

@objc public enum SVStorageBackend: Int {
    case automatic, keychain, encryptedFile

    var swift: StorageBackend {
        switch self {
        case .automatic: .automatic
        case .keychain: .keychain
        case .encryptedFile: .encryptedFile
        }
    }
}

/// The error domain for every `NSError` SecureVault reports.
@objc public final class SVError: NSObject {
    @objc public static let domain = SecureVaultError.errorDomain

    static func ns(_ error: any Error) -> NSError {
        SecureVaultError.wrap(error) as NSError
    }
}

/// A storage policy for Objective-C. Start from a preset and copy it to adjust:
///
///     SVPolicy *policy = [SVPolicy.accessToken copy];
///     policy.expiresAfter = 3600;
@objc(SVPolicy) public final class SVPolicy: NSObject, NSCopying, @unchecked Sendable {
    @objc public var classification: SVClassification
    @objc public var accessibility: SVAccessibility
    @objc public var deviceOnly: Bool
    @objc public var userAuthentication: SVUserAuthentication
    @objc public var backend: SVStorageBackend
    /// Seconds; 0 means never.
    @objc public var expiresAfter: TimeInterval
    @objc public var requiresDevicePasscode: Bool

    init(_ policy: StoragePolicy) {
        classification = SVClassification(rawValue: policy.classification.rawValue) ?? .sensitive
        accessibility = SVAccessibility(policy.accessibility)
        deviceOnly = policy.deviceOnly
        userAuthentication = SVUserAuthentication(policy.userAuthentication)
        backend = switch policy.backend {
        case .automatic: .automatic
        case .keychain: .keychain
        case .encryptedFile: .encryptedFile
        }
        expiresAfter = policy.expiresAfter ?? 0
        requiresDevicePasscode = policy.requiresDevicePasscode
    }

    /// A policy with the class defaults.
    @objc public convenience init(classification: SVClassification) {
        self.init(StoragePolicy(classification: classification.swift))
    }

    public var swiftPolicy: StoragePolicy {
        StoragePolicy(
            classification: classification.swift,
            accessibility: accessibility.swift,
            deviceOnly: deviceOnly,
            userAuthentication: userAuthentication.swift,
            backend: backend.swift,
            expiresAfter: expiresAfter > 0 ? expiresAfter : nil,
            requiresDevicePasscode: requiresDevicePasscode
        )
    }

    public func copy(with zone: NSZone? = nil) -> Any { SVPolicy(swiftPolicy) }

    @objc public class var standard: SVPolicy { SVPolicy(.standard) }
    @objc public class var preference: SVPolicy { SVPolicy(.preference) }
    @objc public class var sensitive: SVPolicy { SVPolicy(.sensitive) }
    @objc public class var secret: SVPolicy { SVPolicy(.secret) }
    @objc public class var accessToken: SVPolicy { SVPolicy(.accessToken) }
    @objc public class var refreshToken: SVPolicy { SVPolicy(.refreshToken) }
    @objc public class var session: SVPolicy { SVPolicy(.session) }
    @objc public class var credential: SVPolicy { SVPolicy(.credential) }
    @objc public class var otp: SVPolicy { SVPolicy(.otp) }
    @objc public class var highlySensitive: SVPolicy { SVPolicy(.highlySensitive) }
    @objc public class var biometric: SVPolicy { SVPolicy(.biometric) }
}

/// Runs async work and delivers the result on the main queue.
func deliver<T: Sendable>(
    _ completion: @escaping @Sendable (T?, NSError?) -> Void,
    _ work: @escaping @Sendable () async throws -> T
) {
    Task {
        do {
            let value = try await work()
            await MainActor.run { completion(value, nil) }
        } catch {
            let nsError = SVError.ns(error)
            await MainActor.run { completion(nil, nsError) }
        }
    }
}

func deliver(_ completion: (@Sendable (NSError?) -> Void)?, _ work: @escaping @Sendable () async throws -> Void) {
    Task {
        do {
            try await work()
            await MainActor.run { completion?(nil) }
        } catch {
            let nsError = SVError.ns(error)
            await MainActor.run { completion?(nsError) }
        }
    }
}
