//
//  EnvelopeTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation
import Testing
@testable import SecureVault

@Suite("Envelope (PRD §14)")
struct EnvelopeTests {
    let crypto = AESGCMProvider()
    let key = SymmetricKey(size: .bits256)
    let context = Data("namespace|key".utf8)

    func header(expires: Date? = nil) -> EnvelopeHeader {
        EnvelopeHeader(algorithm: "A256GCM", keyPurpose: "kv", keyDomain: "afu.local", keyVersion: 1,
                       createdAt: Date(timeIntervalSince1970: 1_000), expiresAt: expires)
    }

    @Test func roundTrip() throws {
        let sealed = try Envelope.seal(Data("secret".utf8), header: header(), key: key, context: context, crypto: crypto)
        let opened = try Envelope.open(sealed, key: key, context: context, crypto: crypto)
        #expect(opened.plaintext == Data("secret".utf8))
        #expect(opened.header == header())
        #expect(!sealed.contains("secret"))
    }

    @Test("tampered ciphertext fails")
    func tamperedCiphertext() throws {
        var sealed = try Envelope.seal(Data("secret".utf8), header: header(), key: key, context: context, crypto: crypto)
        sealed[sealed.count - 1] ^= 0x01
        #expect(throws: SecureVaultError.decryptionFailed) { try Envelope.open(sealed, key: key, context: context, crypto: crypto) }
    }

    @Test("an extended expiry in the header fails authentication")
    func tamperedHeader() throws {
        let sealed = try Envelope.seal(Data("x".utf8), header: header(expires: Date(timeIntervalSince1970: 2_000)), key: key, context: context, crypto: crypto)
        let original = String(decoding: sealed, as: UTF8.self)
        let forged = Data(original.replacingOccurrences(of: "\"ea\":2000", with: "\"ea\":9000").utf8)
        #expect(forged != sealed)
        #expect(throws: SecureVaultError.decryptionFailed) { try Envelope.open(forged, key: key, context: context, crypto: crypto) }
    }

    @Test("moving a ciphertext to another location fails")
    func relocated() throws {
        let sealed = try Envelope.seal(Data("x".utf8), header: header(), key: key, context: context, crypto: crypto)
        #expect(throws: SecureVaultError.decryptionFailed) {
            try Envelope.open(sealed, key: key, context: Data("other|key".utf8), crypto: crypto)
        }
    }

    @Test("wrong key fails")
    func wrongKey() throws {
        let sealed = try Envelope.seal(Data("x".utf8), header: header(), key: key, context: context, crypto: crypto)
        #expect(throws: SecureVaultError.decryptionFailed) {
            try Envelope.open(sealed, key: SymmetricKey(size: .bits256), context: context, crypto: crypto)
        }
    }

    @Test("garbage is rejected as invalid data")
    func garbage() {
        #expect(throws: SecureVaultError.self) { try Envelope.peekHeader(Data("hello world".utf8)) }
    }

    @Test("Secure Enclave-style ECIES wrapping round-trips and binds context")
    func keyWrapping() throws {
        let protector = SoftwareKeyProtector()
        let kek = try protector.makeProtectionKey()
        let raw = Data((0..<32).map { UInt8($0) })
        let wrapped = try protector.wrap(raw, protectionKey: kek, context: Data("a".utf8))
        #expect(try protector.unwrap(wrapped, protectionKey: kek, context: Data("a".utf8)) == raw)
        #expect(throws: SecureVaultError.keyUnavailable) { try protector.unwrap(wrapped, protectionKey: kek, context: Data("b".utf8)) }
    }
}
