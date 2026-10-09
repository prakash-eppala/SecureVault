//
//  PolicyEngineTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
@testable import SecureVault

@Suite("Policy engine (PRD §10)")
struct PolicyEngineTests {
    let caps = FixedDeviceCapabilities()

    func place(_ policy: StoragePolicy, size: Int = 100, caps: FixedDeviceCapabilities? = nil) throws -> Placement {
        try PolicyEngine.resolve(policy, payloadSize: size, capabilities: caps ?? self.caps)
    }

    @Test("default mapping table")
    func defaults() throws {
        let standard = try place(.standard)
        #expect(standard.backend == .encryptedFile)
        #expect(standard.domain.id == "afu.portable")

        let sensitive = try place(.sensitive)
        #expect(sensitive.backend == .encryptedFile)
        #expect(sensitive.domain.id == "afu.local")

        let token = try place(.accessToken)
        #expect(token.backend == .keychain)
        #expect(token.domain.id == "afu.local")

        let highly = try place(.highlySensitive)
        #expect(highly.backend == .encryptedFile)
        #expect(highly.domain.id == "wu.local")
        #expect(highly.fileProtection == .complete)

        let biometric = try place(.biometric)
        #expect(biometric.backend == .keychain)
        #expect(biometric.domain.id == "wps.local")
        #expect(biometric.userAuthentication == .biometryCurrentSet)

        #expect(try place(.credential).domain.accessibility == .whenUnlocked)
        #expect(StoragePolicy.otp.expiresAfter == 300)
    }

    @Test("large secrets move to the encrypted file store")
    func largeSecret() throws {
        #expect(try place(.secret, size: 4096).backend == .keychain)
        #expect(try place(.secret, size: 4097).backend == .encryptedFile)
    }

    @Test("R1 synchronisation is rejected")
    func r1() async {
        var policy = StoragePolicy.secret
        policy.allowsSynchronization = true
        await expectPolicyViolation { try place(policy) }
    }

    @Test("R2 highly sensitive data cannot be backed up")
    func r2() async {
        await expectPolicyViolation { try place(.highlySensitive.allowingBackup()) }
        #expect(throws: Never.self) { try place(.sensitive.allowingBackup()) }
    }

    @Test("R3 accessibility weaker than the class minimum")
    func r3() async {
        await expectPolicyViolation { try place(.highlySensitive.accessible(.afterFirstUnlock)) }
    }

    @Test("R4 user authentication on the file backend")
    func r4() async {
        var policy = StoragePolicy.secret.requiringUserAuthentication(.userPresence)
        policy.backend = .encryptedFile
        await expectPolicyViolation { try place(policy) }
    }

    @Test("R5 user authentication with backup")
    func r5() async {
        var policy = StoragePolicy.secret.requiringUserAuthentication(.userPresence)
        policy.deviceOnly = false
        await expectPolicyViolation { try place(policy) }
    }

    @Test("R6 Keychain values over 64 KB")
    func r6() async {
        await expectPolicyViolation { try place(.secret.stored(in: .keychain), size: 70_000) }
    }

    @Test("R7 biometric class without authentication")
    func r7() async {
        var policy = StoragePolicy.biometric
        policy.userAuthentication = nil
        await expectPolicyViolation { try place(policy) }
    }

    @Test("R8 passcode required but not set")
    func r8() async {
        let noPasscode = FixedDeviceCapabilities(passcodeSet: false)
        await expectPolicyViolation { try place(.highlySensitive, caps: noPasscode) }
        #expect(throws: Never.self) { try place(.sensitive, caps: noPasscode) }
    }

    @Test("R9 biometry required but unavailable")
    func r9() async {
        let noBiometry = FixedDeviceCapabilities(biometryAvailable: false)
        await expectError(.biometryNotAvailable) { try place(.biometric, caps: noBiometry) }
        // userPresence falls back to the passcode, so it still works.
        #expect(throws: Never.self) { try place(.secret.requiringUserAuthentication(.userPresence), caps: noBiometry) }
    }

    @Test("R10 Secure Enclave required but unavailable")
    func r10() async {
        await expectPolicyViolation {
            try PolicyEngine.resolve(.secret, payloadSize: 10, capabilities: FixedDeviceCapabilities(secureEnclave: false), requireSecureEnclave: true)
        }
    }

    @Test("key domain ids round-trip")
    func domains() {
        for domain in KeyDomain.all {
            #expect(KeyDomain(id: domain.id) == domain)
        }
        #expect(KeyDomain(accessibility: .whenPasscodeSet, deviceOnly: false).deviceOnly)
    }
}
