//
//  BiometricsTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import LocalAuthentication
import Testing
@testable import SecureVault
@testable import SecureVaultBiometrics

/// What a stub `LAContext` reports. A struct so the factory closure stays `Sendable`.
struct StubBehaviour: Sendable {
    var canUseBiometry = true
    var canUseOwnerAuthentication = true
    var biometryType: LABiometryType = .faceID
    var cannotEvaluateCode: LAError.Code? = nil
    var evaluateFailure: LAError.Code? = nil
    var domainState: Data? = Data([1, 2, 3])
}

final class StubContext: LAContext, @unchecked Sendable {
    let behaviour: StubBehaviour
    private(set) var evaluatedPolicies: [LAPolicy] = []

    init(_ behaviour: StubBehaviour) {
        self.behaviour = behaviour
        super.init()
    }

    override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        let allowed = policy == .deviceOwnerAuthenticationWithBiometrics ? behaviour.canUseBiometry : behaviour.canUseOwnerAuthentication
        if !allowed, let code = behaviour.cannotEvaluateCode {
            error?.pointee = NSError(domain: LAError.errorDomain, code: code.rawValue)
        }
        return allowed
    }

    override var biometryType: LABiometryType { behaviour.biometryType }

    override var evaluatedPolicyDomainState: Data? { behaviour.domainState }

    override func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, (any Error)?) -> Void) {
        evaluatedPolicies.append(policy)
        if let code = behaviour.evaluateFailure {
            reply(false, NSError(domain: LAError.errorDomain, code: code.rawValue))
        } else {
            reply(true, nil)
        }
    }
}

extension BiometricAuthenticator {
    static func stub(_ behaviour: StubBehaviour = StubBehaviour()) -> BiometricAuthenticator {
        BiometricAuthenticator { StubContext(behaviour) }
    }
}

@Suite("Biometric authenticator (PRD §20)")
struct BiometricsTests {
    @Test("reports biometry kind and availability")
    func availability() {
        #expect(BiometricAuthenticator.stub().biometryKind == .faceID)
        #expect(BiometricAuthenticator.stub(StubBehaviour(biometryType: .touchID)).biometryKind == .touchID)
        #expect(BiometricAuthenticator.stub(StubBehaviour(biometryType: .none)).biometryKind == .none)
        #expect(BiometricAuthenticator.stub().isBiometryAvailable)
        #expect(!BiometricAuthenticator.stub(StubBehaviour(canUseBiometry: false)).isBiometryAvailable)
        let passcodeOnly = BiometricAuthenticator.stub(StubBehaviour(canUseBiometry: false))
        #expect(passcodeOnly.canAuthenticate(allowingPasscodeFallback: true))
        #expect(!passcodeOnly.canAuthenticate(allowingPasscodeFallback: false))
    }

    @Test("biometry types map to kinds")
    func kinds() {
        #expect(BiometricAuthenticator.kind(.touchID) == .touchID)
        #expect(BiometricAuthenticator.kind(.faceID) == .faceID)
        #expect(BiometricAuthenticator.kind(.none) == .none)
        if #available(iOS 17.0, macOS 14.0, *) {
            #expect(BiometricAuthenticator.kind(.opticID) == .opticID)
        }
    }

    @Test("a successful prompt returns a reusable context carrying the reason")
    func success() async throws {
        let context = try await BiometricAuthenticator.stub().authenticate(reason: "Unlock records", reuseDuration: 30)
        #expect(context.laContext.localizedReason == "Unlock records")
        #expect(context.laContext.touchIDAuthenticationAllowableReuseDuration == 30)
        context.invalidate()
    }

    @Test("passcode fallback chooses the owner-authentication policy")
    func policyChoice() async throws {
        let withFallback = try await BiometricAuthenticator.stub().authenticate(reason: "r", allowingPasscodeFallback: true)
        #expect((withFallback.laContext as? StubContext)?.evaluatedPolicies == [.deviceOwnerAuthentication])
        let biometryOnly = try await BiometricAuthenticator.stub().authenticate(reason: "r", allowingPasscodeFallback: false)
        #expect((biometryOnly.laContext as? StubContext)?.evaluatedPolicies == [.deviceOwnerAuthenticationWithBiometrics])
    }

    @Test("an unavailable policy fails before prompting")
    func unavailable() async {
        let authenticator = BiometricAuthenticator.stub(StubBehaviour(canUseBiometry: false, canUseOwnerAuthentication: false, cannotEvaluateCode: .biometryNotEnrolled))
        await expectError(.biometryNotAvailable) { try await authenticator.authenticate(reason: "r") }
    }

    @Test("prompt failures map to SecureVault errors", arguments: [
        (LAError.Code.userCancel, SecureVaultError.userCancelled),
        (.biometryLockout, .biometryLockout),
        (.authenticationFailed, .authenticationFailed),
    ])
    func failures(_ code: LAError.Code, _ expected: SecureVaultError) async {
        let authenticator = BiometricAuthenticator.stub(StubBehaviour(evaluateFailure: code))
        await expectError(expected) { try await authenticator.authenticate(reason: "r") }
    }

    @Test("every LAError code has a mapping")
    func mapping() {
        let cases: [(LAError.Code, SecureVaultError)] = [
            (.userCancel, .userCancelled), (.appCancel, .userCancelled), (.systemCancel, .userCancelled), (.userFallback, .userCancelled),
            (.biometryLockout, .biometryLockout),
            (.biometryNotAvailable, .biometryNotAvailable), (.biometryNotEnrolled, .biometryNotAvailable),
            (.passcodeNotSet, .securityPolicyViolation(reason: "a device passcode is required")),
            (.authenticationFailed, .authenticationFailed),
            (.invalidContext, .authenticationFailed),
        ]
        for (code, expected) in cases {
            #expect(BiometricAuthenticator.map(NSError(domain: LAError.errorDomain, code: code.rawValue)) == expected)
        }
        #expect(BiometricAuthenticator.map(nil) == .authenticationFailed)
        #expect(BiometricAuthenticator.map(NSError(domain: "other", code: 1)) == .authenticationFailed)
        #expect(BiometricAuthenticator.map(NSError(domain: LAError.errorDomain, code: 999_999)) == .authenticationFailed)
    }

    @Test("enrollment fingerprint is a hash of the domain state")
    func fingerprint() {
        let fingerprint = BiometricAuthenticator.stub().enrollmentFingerprint
        #expect(fingerprint?.count == 32)
        #expect(fingerprint != Data([1, 2, 3]))
        #expect(BiometricAuthenticator.stub(StubBehaviour(canUseBiometry: false)).enrollmentFingerprint == nil)
        #expect(BiometricAuthenticator.stub(StubBehaviour(domainState: nil)).enrollmentFingerprint == nil)
    }

    @Test("system capabilities and the default authenticator answer without prompting")
    func system() {
        let capabilities = SystemDeviceCapabilities()
        _ = capabilities.isDevicePasscodeSet
        _ = capabilities.isSecureEnclaveAvailable
        #expect(capabilities.isBiometryAvailable == (capabilities.biometryKind != .none) || !capabilities.isBiometryAvailable)
        let real = BiometricAuthenticator()
        _ = real.canAuthenticate(allowingPasscodeFallback: false)
        _ = real.enrollmentFingerprint
    }

    @Test("authentication contexts")
    func contexts() {
        let direct = AuthenticationContext(reason: "Show card", reuseDuration: 10_000)
        #expect(direct.laContext.localizedReason == "Show card")
        #expect(direct.laContext.touchIDAuthenticationAllowableReuseDuration == LATouchIDAuthenticationMaximumAllowableReuseDuration)
        let wrapped = AuthenticationContext(context: LAContext())
        wrapped.invalidate()
    }
}
