//
//  Classification.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// How sensitive a piece of data is. Each class maps to a fixed default protection (PRD §10.2).
public enum DataClassification: Int, Sendable, CaseIterable, Codable, Comparable {
    case standard = 0
    case sensitive = 1
    case secret = 2
    case highlySensitive = 3
    case biometricProtected = 4

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }

    /// The weakest accessibility this class accepts (rule R3).
    var minimumAccessibility: Accessibility {
        switch self {
        case .standard, .sensitive, .secret: .afterFirstUnlock
        case .highlySensitive: .whenUnlocked
        case .biometricProtected: .whenPasscodeSet
        }
    }
}

/// When stored data can be read, mirroring the Keychain accessibility classes.
public enum Accessibility: String, Sendable, Codable, CaseIterable {
    /// Readable only while the device is unlocked.
    case whenUnlocked
    /// Readable after the first unlock since boot, including in the background.
    case afterFirstUnlock
    /// Readable only while unlocked and only while a passcode is set. Always device-only.
    case whenPasscodeSet

    /// Higher is stricter.
    var strength: Int {
        switch self {
        case .afterFirstUnlock: 0
        case .whenUnlocked: 1
        case .whenPasscodeSet: 2
        }
    }

    package var shortCode: String {
        switch self {
        case .whenUnlocked: "wu"
        case .afterFirstUnlock: "afu"
        case .whenPasscodeSet: "wps"
        }
    }

    package var fileProtection: FileProtectionLevel {
        switch self {
        case .afterFirstUnlock: .completeUntilFirstUserAuthentication
        case .whenUnlocked, .whenPasscodeSet: .complete
        }
    }
}

/// User authentication required on every read of a Keychain item.
public enum UserAuthentication: String, Sendable, Codable, CaseIterable {
    /// Biometry, falling back to the device passcode.
    case userPresence
    /// Any enrolled biometry; survives enrollment changes.
    case biometryAny
    /// Biometry as enrolled when the item was written. Adding or removing a face or finger invalidates the item.
    case biometryCurrentSet
    /// Device passcode only.
    case devicePasscode

    var requiresBiometry: Bool { self == .biometryAny || self == .biometryCurrentSet }
}

/// Where a value is stored.
public enum StorageBackend: String, Sendable, Codable {
    /// Let the policy engine decide (PRD §10.4).
    case automatic
    case keychain
    case encryptedFile
}

/// Data Protection class applied to files.
public enum FileProtectionLevel: String, Sendable, Codable {
    case complete
    case completeUntilFirstUserAuthentication

    package var attribute: FileProtectionType {
        switch self {
        case .complete: .complete
        case .completeUntilFirstUserAuthentication: .completeUntilFirstUserAuthentication
        }
    }
}
