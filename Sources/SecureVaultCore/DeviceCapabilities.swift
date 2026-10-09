//
//  DeviceCapabilities.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation

public enum BiometryKind: String, Sendable, Codable {
    case none, touchID, faceID, opticID
}

/// What the device can enforce. The policy engine fails closed against this (rules R8–R10).
public protocol DeviceCapabilities: Sendable {
    var isDevicePasscodeSet: Bool { get }
    var biometryKind: BiometryKind { get }
    var isBiometryAvailable: Bool { get }
    var isSecureEnclaveAvailable: Bool { get }
}

/// Fixed capabilities, for tests and previews.
public struct FixedDeviceCapabilities: DeviceCapabilities {
    public var isDevicePasscodeSet: Bool
    public var biometryKind: BiometryKind
    public var isBiometryAvailable: Bool
    public var isSecureEnclaveAvailable: Bool

    public init(passcodeSet: Bool = true, biometry: BiometryKind = .faceID, biometryAvailable: Bool = true, secureEnclave: Bool = false) {
        self.isDevicePasscodeSet = passcodeSet
        self.biometryKind = biometry
        self.isBiometryAvailable = biometryAvailable
        self.isSecureEnclaveAvailable = secureEnclave
    }
}
