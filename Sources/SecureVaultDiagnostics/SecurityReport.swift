//
//  SecurityReport.swift
//  SecureVaultDiagnostics
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import SecureVaultCore

/// A security posture report. It never contains values, key material or key names (PRD §25).
public struct SecurityReport: Sendable, Codable, Equatable {
    public struct Finding: Sendable, Codable, Equatable, Identifiable {
        public enum Severity: String, Sendable, Codable, Comparable {
            case info, warning, critical
            var rank: Int { switch self { case .info: 0; case .warning: 1; case .critical: 2 } }
            public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
        }

        public var id: String { code }
        public let code: String
        public let severity: Severity
        public let message: String
    }

    public struct KeySummary: Sendable, Codable, Equatable {
        public let purpose: String
        public let domain: String
        public let versions: Int
    }

    public let generatedAt: Date
    public let passcodeSet: Bool
    public let biometry: BiometryKind
    public let secureEnclaveAvailable: Bool
    public let secureEnclaveInUse: Bool
    public let keys: [KeySummary]
    public let storedObjectFiles: Int
    public let findings: [Finding]

    public var highestSeverity: Finding.Severity? { findings.map(\.severity).max() }
}

/// Inputs gathered by the vault; the builder turns them into findings.
public struct SecurityReportInput: Sendable {
    public var now: Date
    public var capabilities: any DeviceCapabilities
    public var keychainIsEphemeral: Bool
    public var secureEnclaveInUse: Bool
    public var keyVersions: [KeyID: [Int]]
    public var storedObjectFiles: Int
    public var loggingEnabled: Bool

    public init(now: Date, capabilities: any DeviceCapabilities, keychainIsEphemeral: Bool, secureEnclaveInUse: Bool,
                keyVersions: [KeyID: [Int]], storedObjectFiles: Int, loggingEnabled: Bool) {
        self.now = now
        self.capabilities = capabilities
        self.keychainIsEphemeral = keychainIsEphemeral
        self.secureEnclaveInUse = secureEnclaveInUse
        self.keyVersions = keyVersions
        self.storedObjectFiles = storedObjectFiles
        self.loggingEnabled = loggingEnabled
    }
}

public enum SecurityReportBuilder {
    public static func build(_ input: SecurityReportInput) -> SecurityReport {
        var findings: [SecurityReport.Finding] = []
        func add(_ code: String, _ severity: SecurityReport.Finding.Severity, _ message: String) {
            findings.append(.init(code: code, severity: severity, message: message))
        }

        let caps = input.capabilities
        if input.keychainIsEphemeral {
            add("keychain.in-memory", .critical, "An in-memory Keychain is in use. Nothing persists and access control is not enforced.")
        }
        if !caps.isDevicePasscodeSet {
            add("device.no-passcode", .critical, "No device passcode is set. Data Protection is weak and highly sensitive policies will fail.")
        }
        if !caps.isBiometryAvailable {
            add("device.no-biometry", .info, "Biometry is unavailable or not enrolled. Biometric policies will fail closed.")
        }
        if !caps.isSecureEnclaveAvailable {
            add("device.no-secure-enclave", .info, "No Secure Enclave. Device-only keys are protected by the Keychain alone.")
        } else if !input.secureEnclaveInUse {
            add("keys.secure-enclave-off", .warning, "A Secure Enclave is available but key wrapping is turned off.")
        }
        if input.keyVersions.values.contains(where: { $0.count > 1 }) {
            add("keys.rotation-pending", .warning, "Some keys have more than one version. Finish rotation with completePendingRotations().")
        }
        if input.keyVersions.keys.contains(where: { !$0.domain.deviceOnly }) {
            add("storage.backup-enabled", .info, "Some data is allowed in encrypted device backups.")
        }
        if input.keyVersions.keys.contains(where: { $0.domain.accessibility == .afterFirstUnlock }) {
            add("storage.background-readable", .info, "Some data is readable while the device is locked (after first unlock).")
        }
        if input.loggingEnabled {
            add("logging.enabled", .info, "SDK logging is on. It never records values, but turn it off in release builds.")
        }

        let keys = input.keyVersions
            .map { SecurityReport.KeySummary(purpose: $0.key.purpose.hasPrefix("db.") ? "db" : $0.key.purpose, domain: $0.key.domain.id, versions: $0.value.count) }
            .sorted { ($0.purpose, $0.domain) < ($1.purpose, $1.domain) }

        return SecurityReport(
            generatedAt: input.now,
            passcodeSet: caps.isDevicePasscodeSet,
            biometry: caps.biometryKind,
            secureEnclaveAvailable: caps.isSecureEnclaveAvailable,
            secureEnclaveInUse: input.secureEnclaveInUse,
            keys: keys,
            storedObjectFiles: input.storedObjectFiles,
            findings: findings.sorted { $0.severity > $1.severity }
        )
    }
}
