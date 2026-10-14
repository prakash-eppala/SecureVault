//
//  BiometricAuthenticator.swift
//  SecureVaultBiometrics
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation
import LocalAuthentication
#if canImport(SecureVaultCore)
import SecureVaultCore
#endif

/// LocalAuthentication integration (PRD §20). Biometrics are a local layer; servers stay authoritative.
public struct BiometricAuthenticator: Sendable {
    private let makeContext: @Sendable () -> LAContext

    public init() {
        self.makeContext = { LAContext() }
    }

    /// Supplies the `LAContext` used for every check and prompt. Tests pass a stub so no system prompt appears.
    init(makeContext: @escaping @Sendable () -> LAContext) {
        self.makeContext = makeContext
    }

    public var biometryKind: BiometryKind {
        let context = makeContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return Self.kind(context.biometryType)
    }

    /// Biometry is present and enrolled.
    public var isBiometryAvailable: Bool {
        makeContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    public func canAuthenticate(allowingPasscodeFallback: Bool = true) -> Bool {
        makeContext().canEvaluatePolicy(policy(allowingPasscodeFallback), error: nil)
    }

    /// Prompts once and returns a context to pass to several `retrieve` calls.
    public func authenticate(
        reason: String,
        allowingPasscodeFallback: Bool = true,
        reuseDuration: TimeInterval = 0
    ) async throws -> AuthenticationContext {
        let context = makeContext()
        context.localizedReason = reason
        #if os(iOS) || os(macOS)
        context.touchIDAuthenticationAllowableReuseDuration = min(reuseDuration, LATouchIDAuthenticationMaximumAllowableReuseDuration)
        #endif
        let authentication = AuthenticationContext(context: context)
        let policy = policy(allowingPasscodeFallback)
        var error: NSError?
        guard context.canEvaluatePolicy(policy, error: &error) else {
            throw Self.map(error)
        }
        do {
            // A failure must never count as success, even if the system reports it without an error.
            guard try await evaluate(context, policy: policy, reason: reason) else { throw SecureVaultError.authenticationFailed }
        } catch let error as SecureVaultError {
            throw error
        } catch {
            throw Self.map(error as NSError)
        }
        return authentication
    }

    /// An opaque fingerprint of the enrolled biometry. Compare with a saved value to detect enrollment changes.
    public var enrollmentFingerprint: Data? {
        let context = makeContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return nil }
        return context.evaluatedPolicyDomainState.map { Data(SHA256.hash(data: $0)) }
    }

    private func policy(_ fallback: Bool) -> LAPolicy {
        fallback ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics
    }

    private func evaluate(_ context: LAContext, policy: LAPolicy, reason: String) async throws -> Bool {
        let box = UncheckedContext(context)
        return try await withCheckedThrowingContinuation { continuation in
            box.context.evaluatePolicy(policy, localizedReason: reason) { success, error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume(returning: success) }
            }
        }
    }

    static func kind(_ type: LABiometryType) -> BiometryKind {
        switch type {
        case .touchID: return .touchID
        case .faceID: return .faceID
        default:
            if #available(iOS 17.0, macOS 14.0, *), type == .opticID { return .opticID }
            return .none
        }
    }

    static func map(_ error: NSError?) -> SecureVaultError {
        guard let error, error.domain == LAError.errorDomain, let code = LAError.Code(rawValue: error.code) else {
            return .authenticationFailed
        }
        switch code {
        case .userCancel, .appCancel, .systemCancel, .userFallback: return .userCancelled
        case .biometryLockout: return .biometryLockout
        case .biometryNotAvailable, .biometryNotEnrolled: return .biometryNotAvailable
        case .passcodeNotSet: return .securityPolicyViolation(reason: "a device passcode is required")
        case .authenticationFailed: return .authenticationFailed
        default: return .authenticationFailed
        }
    }
}

private struct UncheckedContext: @unchecked Sendable {
    let context: LAContext
    init(_ context: LAContext) { self.context = context }
}

/// Reads the real device capabilities (PRD §29). The Simulator reports a passcode as set; devices never do this.
public struct SystemDeviceCapabilities: DeviceCapabilities {
    public init() {}

    public var isDevicePasscodeSet: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
        #endif
    }

    public var biometryKind: BiometryKind { BiometricAuthenticator().biometryKind }
    public var isBiometryAvailable: Bool { BiometricAuthenticator().isBiometryAvailable }
    public var isSecureEnclaveAvailable: Bool { SecureEnclave.isAvailable }
}
