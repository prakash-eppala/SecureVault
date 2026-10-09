//
//  SecureVaultError.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// Every error SecureVault throws. Associated reasons never contain stored values.
public enum SecureVaultError: Error, Sendable, Equatable, Hashable {
    case itemNotFound
    case invalidData(reason: String)
    case typeMismatch(expected: String)
    case encryptionFailed
    /// Authentication of the ciphertext failed: tampered data, wrong key, or ciphertext moved to another location.
    case decryptionFailed
    /// The key version that sealed the data is gone (for example after restoring to a new device).
    case keyUnavailable
    case keyRotationFailed(reason: String)
    case authenticationRequired
    case authenticationFailed
    case userCancelled
    case biometryNotAvailable
    case biometryLockout
    case accessDenied
    /// The device is locked and the data is only readable while unlocked.
    case protectedDataUnavailable
    case expired
    case migrationFailed(reason: String)
    case databaseFailure(reason: String)
    case fileFailure(reason: String)
    case securityPolicyViolation(reason: String)
    case keychainFailure(status: Int32)
    case cancelled

    /// Stable numeric code, shared with the Objective-C `SVErrorCode` enum.
    public var code: Int {
        switch self {
        case .itemNotFound: 1
        case .invalidData: 2
        case .typeMismatch: 3
        case .encryptionFailed: 4
        case .decryptionFailed: 5
        case .keyUnavailable: 6
        case .keyRotationFailed: 7
        case .authenticationRequired: 8
        case .authenticationFailed: 9
        case .userCancelled: 10
        case .biometryNotAvailable: 11
        case .biometryLockout: 12
        case .accessDenied: 13
        case .protectedDataUnavailable: 14
        case .expired: 15
        case .migrationFailed: 16
        case .databaseFailure: 17
        case .fileFailure: 18
        case .securityPolicyViolation: 19
        case .keychainFailure: 20
        case .cancelled: 21
        }
    }
}

extension SecureVaultError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .itemNotFound: "No value is stored for this key."
        case .invalidData(let reason): "Stored data is malformed: \(reason)"
        case .typeMismatch(let expected): "Stored value does not decode as \(expected)."
        case .encryptionFailed: "Encryption failed."
        case .decryptionFailed: "Decryption failed. The data was modified, moved, or sealed with a different key."
        case .keyUnavailable: "The encryption key for this data is no longer available."
        case .keyRotationFailed(let reason): "Key rotation failed: \(reason)"
        case .authenticationRequired: "User authentication is required."
        case .authenticationFailed: "User authentication failed."
        case .userCancelled: "Authentication was cancelled."
        case .biometryNotAvailable: "Biometric authentication is not available on this device."
        case .biometryLockout: "Biometric authentication is locked after too many attempts."
        case .accessDenied: "Keychain access was denied. Check entitlements and access groups."
        case .protectedDataUnavailable: "The device is locked and this data is only readable while unlocked."
        case .expired: "The value has expired."
        case .migrationFailed(let reason): "Migration failed: \(reason)"
        case .databaseFailure(let reason): "Database error: \(reason)"
        case .fileFailure(let reason): "File error: \(reason)"
        case .securityPolicyViolation(let reason): "Security policy cannot be satisfied: \(reason)"
        case .keychainFailure(let status): "Keychain error \(status)."
        case .cancelled: "The operation was cancelled."
        }
    }
}

extension SecureVaultError: CustomNSError {
    public static var errorDomain: String { "com.securevault.error" }
    public var errorCode: Int { code }
    public var errorUserInfo: [String: Any] {
        [NSLocalizedDescriptionKey: errorDescription ?? "SecureVault error \(code)"]
    }
}

extension SecureVaultError {
    /// Normalises any error thrown inside the SDK into a `SecureVaultError`.
    package static func wrap(_ error: any Error) -> SecureVaultError {
        if let error = error as? SecureVaultError { return error }
        if error is CancellationError { return .cancelled }
        return .invalidData(reason: String(describing: type(of: error)))
    }
}
