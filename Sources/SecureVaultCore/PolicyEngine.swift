//
//  PolicyEngine.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// A protection domain: the (accessibility, device-only) pair that a data key is bound to (PRD §15.1).
public struct KeyDomain: Hashable, Sendable, Codable, CustomStringConvertible {
    public let accessibility: Accessibility
    public let deviceOnly: Bool

    public init(accessibility: Accessibility, deviceOnly: Bool) {
        self.accessibility = accessibility
        // when-passcode-set is always device-only.
        self.deviceOnly = accessibility == .whenPasscodeSet ? true : deviceOnly
    }

    /// e.g. `afu.local`, `wu.portable`.
    public var id: String { "\(accessibility.shortCode).\(deviceOnly ? "local" : "portable")" }
    public var description: String { id }

    public init?(id: String) {
        let parts = id.split(separator: ".")
        guard parts.count == 2,
              let access = Accessibility.allCases.first(where: { $0.shortCode == parts[0] }),
              parts[1] == "local" || parts[1] == "portable" else { return nil }
        self.init(accessibility: access, deviceOnly: parts[1] == "local")
    }

    public static let all: [KeyDomain] = [
        KeyDomain(accessibility: .whenUnlocked, deviceOnly: true),
        KeyDomain(accessibility: .whenUnlocked, deviceOnly: false),
        KeyDomain(accessibility: .afterFirstUnlock, deviceOnly: true),
        KeyDomain(accessibility: .afterFirstUnlock, deviceOnly: false),
        KeyDomain(accessibility: .whenPasscodeSet, deviceOnly: true),
    ]
}

/// Where and how a value will be stored, after policy resolution.
public struct Placement: Sendable, Equatable {
    public enum Backend: String, Sendable { case keychain, encryptedFile }
    public let backend: Backend
    public let domain: KeyDomain
    public let userAuthentication: UserAuthentication?
    public var fileProtection: FileProtectionLevel { domain.accessibility.fileProtection }
}

/// Resolves a `StoragePolicy` to a `Placement`, failing closed (PRD §10.4–10.5).
public enum PolicyEngine {
    /// Values at or below this size go to the Keychain when the class is Secret or higher.
    public static let keychainAutomaticLimit = 4 * 1024
    /// Hard ceiling for any Keychain placement (rule R6).
    public static let keychainMaximumSize = 64 * 1024

    public static func resolve(
        _ policy: StoragePolicy,
        payloadSize: Int,
        capabilities: any DeviceCapabilities,
        requireSecureEnclave: Bool = false
    ) throws -> Placement {
        try validate(policy, capabilities: capabilities, requireSecureEnclave: requireSecureEnclave)

        let backend: Placement.Backend
        switch policy.backend {
        case .keychain: backend = .keychain
        case .encryptedFile: backend = .encryptedFile
        case .automatic:
            if policy.userAuthentication != nil {
                backend = .keychain
            } else if policy.classification >= .secret, policy.classification != .highlySensitive,
                      payloadSize <= keychainAutomaticLimit {
                backend = .keychain
            } else {
                backend = .encryptedFile
            }
        }
        if backend == .keychain, payloadSize > keychainMaximumSize {
            throw SecureVaultError.securityPolicyViolation(reason: "values over \(keychainMaximumSize / 1024) KB cannot be stored in the Keychain")
        }
        return Placement(
            backend: backend,
            domain: KeyDomain(accessibility: policy.accessibility, deviceOnly: policy.deviceOnly),
            userAuthentication: policy.userAuthentication
        )
    }

    /// Checks rules that do not depend on the payload. Also used for databases and files.
    public static func validate(_ policy: StoragePolicy, capabilities: any DeviceCapabilities, requireSecureEnclave: Bool = false) throws {
        func violation(_ reason: String) -> SecureVaultError { .securityPolicyViolation(reason: reason) }

        // R1
        if policy.allowsSynchronization {
            throw violation("iCloud Keychain synchronisation is not supported")
        }
        // R2
        if policy.classification >= .highlySensitive, !policy.deviceOnly {
            throw violation("\(policy.classification) data must be device-only")
        }
        // R3
        if policy.accessibility.strength < policy.classification.minimumAccessibility.strength {
            throw violation("accessibility \(policy.accessibility.rawValue) is weaker than \(policy.classification) allows")
        }
        // R7
        if policy.classification == .biometricProtected, policy.userAuthentication == nil {
            throw violation("biometric-protected data needs a user-authentication requirement")
        }
        if let auth = policy.userAuthentication {
            // R4
            if policy.backend == .encryptedFile {
                throw violation("user authentication is only supported on Keychain items")
            }
            // R5
            if !policy.deviceOnly {
                throw violation("items requiring user authentication must be device-only")
            }
            // R9
            if auth.requiresBiometry, !capabilities.isBiometryAvailable {
                throw SecureVaultError.biometryNotAvailable
            }
            if !capabilities.isDevicePasscodeSet {
                throw violation("user authentication requires a device passcode")
            }
        }
        // R5 (when-passcode-set)
        if policy.accessibility == .whenPasscodeSet, !policy.deviceOnly {
            throw violation("when-passcode-set items must be device-only")
        }
        // R8
        if (policy.requiresDevicePasscode || policy.accessibility == .whenPasscodeSet), !capabilities.isDevicePasscodeSet {
            throw violation("a device passcode is required")
        }
        // R10
        if requireSecureEnclave, policy.deviceOnly, !capabilities.isSecureEnclaveAvailable {
            throw violation("the Secure Enclave is required but not available")
        }
    }
}
