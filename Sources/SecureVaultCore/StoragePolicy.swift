//
//  StoragePolicy.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// What protection a value needs. Start from a preset and adjust with modifiers:
/// `.accessToken.expiring(after: 3600)`, `.sensitive.allowingBackup()`.
public struct StoragePolicy: Sendable, Hashable, Codable {
    public var classification: DataClassification
    public var accessibility: Accessibility
    /// When `false`, the value and its key are included in encrypted device backups.
    public var deviceOnly: Bool
    public var userAuthentication: UserAuthentication?
    public var backend: StorageBackend
    /// Seconds until the value expires; `nil` never expires.
    public var expiresAfter: TimeInterval?
    /// Fail closed when the device has no passcode (rule R8).
    public var requiresDevicePasscode: Bool
    /// iCloud Keychain synchronisation. Not supported in V1: `true` is rejected (rule R1).
    public var allowsSynchronization: Bool

    /// A policy with the class defaults from PRD §10.2.
    public init(classification: DataClassification) {
        self.classification = classification
        self.backend = .automatic
        self.expiresAfter = nil
        self.allowsSynchronization = false
        switch classification {
        case .standard:
            accessibility = .afterFirstUnlock; deviceOnly = false; userAuthentication = nil; requiresDevicePasscode = false
        case .sensitive, .secret:
            accessibility = .afterFirstUnlock; deviceOnly = true; userAuthentication = nil; requiresDevicePasscode = false
        case .highlySensitive:
            accessibility = .whenUnlocked; deviceOnly = true; userAuthentication = nil; requiresDevicePasscode = true
        case .biometricProtected:
            accessibility = .whenPasscodeSet; deviceOnly = true; userAuthentication = .biometryCurrentSet; requiresDevicePasscode = true
            backend = .keychain
        }
    }

    public init(
        classification: DataClassification,
        accessibility: Accessibility,
        deviceOnly: Bool,
        userAuthentication: UserAuthentication? = nil,
        backend: StorageBackend = .automatic,
        expiresAfter: TimeInterval? = nil,
        requiresDevicePasscode: Bool = false
    ) {
        self.classification = classification
        self.accessibility = accessibility
        self.deviceOnly = deviceOnly
        self.userAuthentication = userAuthentication
        self.backend = backend
        self.expiresAfter = expiresAfter
        self.requiresDevicePasscode = requiresDevicePasscode
        self.allowsSynchronization = false
    }

    // MARK: Presets (PRD §10.3)

    public static let standard = StoragePolicy(classification: .standard)
    public static let preference = StoragePolicy(classification: .standard)
    public static let sensitive = StoragePolicy(classification: .sensitive)
    public static let secret = StoragePolicy(classification: .secret)
    public static let accessToken = StoragePolicy(classification: .secret)
    public static let refreshToken = StoragePolicy(classification: .secret)
    public static let session = StoragePolicy(classification: .secret)
    public static let credential = StoragePolicy(classification: .secret).accessible(.whenUnlocked)
    public static let otp = StoragePolicy(classification: .secret).expiring(after: 300)
    public static let highlySensitive = StoragePolicy(classification: .highlySensitive)
    public static let biometric = StoragePolicy(classification: .biometricProtected)

    // MARK: Modifiers

    public func expiring(after seconds: TimeInterval) -> StoragePolicy {
        var copy = self; copy.expiresAfter = seconds; return copy
    }

    public func requiringUserAuthentication(_ authentication: UserAuthentication) -> StoragePolicy {
        var copy = self
        copy.userAuthentication = authentication
        copy.backend = .keychain
        copy.deviceOnly = true
        return copy
    }

    /// Lets the value travel in encrypted device backups. Rejected for Highly Sensitive and Biometric data (rule R2).
    public func allowingBackup() -> StoragePolicy {
        var copy = self; copy.deviceOnly = false; return copy
    }

    public func deviceOnly(_ value: Bool = true) -> StoragePolicy {
        var copy = self; copy.deviceOnly = value; return copy
    }

    public func stored(in backend: StorageBackend) -> StoragePolicy {
        var copy = self; copy.backend = backend; return copy
    }

    public func accessible(_ accessibility: Accessibility) -> StoragePolicy {
        var copy = self; copy.accessibility = accessibility; return copy
    }

    public func requiringDevicePasscode(_ value: Bool = true) -> StoragePolicy {
        var copy = self; copy.requiresDevicePasscode = value; return copy
    }
}
