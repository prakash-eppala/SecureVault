//
//  KeyProtectors.swift
//  SecureVaultCrypto
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation
#if canImport(SecureVaultCore)
import SecureVaultCore
#endif

/// ECIES wrapping: ephemeral P-256 ECDH with a long-lived key-agreement key, HKDF-SHA256, AES-256-GCM.
/// Wrapped format: ephemeral public key (x9.63, 65 bytes) ‖ AES-GCM combined box.
enum ECIES {
    static func wrap(_ key: Data, recipient: P256.KeyAgreement.PublicKey, context: Data) throws -> Data {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let wrappingKey = derive(shared, ephemeral: ephemeral.publicKey, context: context)
        let box = try AES.GCM.seal(key, using: wrappingKey, authenticating: context)
        return ephemeral.publicKey.x963Representation + Data(box.nonce) + box.ciphertext + box.tag
    }

    static func unwrap(_ wrapped: Data, agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret, context: Data) throws -> Data {
        guard wrapped.count > 65 else { throw SecureVaultError.invalidData(reason: "wrapped key too short") }
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: wrapped.prefix(65))
        let wrappingKey = derive(try agree(ephemeral), ephemeral: ephemeral, context: context)
        do {
            return try AES.GCM.open(AES.GCM.SealedBox(combined: wrapped.dropFirst(65)), using: wrappingKey, authenticating: context)
        } catch {
            throw SecureVaultError.keyUnavailable
        }
    }

    private static func derive(_ shared: SharedSecret, ephemeral: P256.KeyAgreement.PublicKey, context: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeral.x963Representation,
            sharedInfo: Data("SecureVault.KeyWrap.v1".utf8) + context,
            outputByteCount: 32
        )
    }
}

/// Wraps device-only data keys with a Secure Enclave key (PRD §15.2). The enclave key never leaves the chip;
/// the persisted blob is an opaque, device-bound handle.
public struct SecureEnclaveKeyProtector: KeyProtector {
    public init() {}

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    public var identifier: String { "se-p256-ecies-v1" }

    public func makeProtectionKey() throws -> Data {
        do {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey().dataRepresentation
        } catch {
            throw SecureVaultError.securityPolicyViolation(reason: "the Secure Enclave key could not be created")
        }
    }

    public func wrap(_ key: Data, protectionKey: Data, context: Data) throws -> Data {
        let enclaveKey = try load(protectionKey)
        return try ECIES.wrap(key, recipient: enclaveKey.publicKey, context: context)
    }

    public func unwrap(_ wrapped: Data, protectionKey: Data, context: Data) throws -> Data {
        let enclaveKey = try load(protectionKey)
        return try ECIES.unwrap(wrapped, agree: { try enclaveKey.sharedSecretFromKeyAgreement(with: $0) }, context: context)
    }

    private func load(_ data: Data) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        do {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
        } catch {
            throw SecureVaultError.keyUnavailable
        }
    }
}

/// The same ECIES construction with a software key. For tests and simulators only; it adds no hardware protection.
public struct SoftwareKeyProtector: KeyProtector {
    public init() {}

    public var identifier: String { "sw-p256-ecies-v1" }

    public func makeProtectionKey() throws -> Data {
        P256.KeyAgreement.PrivateKey().rawRepresentation
    }

    public func wrap(_ key: Data, protectionKey: Data, context: Data) throws -> Data {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: protectionKey)
        return try ECIES.wrap(key, recipient: privateKey.publicKey, context: context)
    }

    public func unwrap(_ wrapped: Data, protectionKey: Data, context: Data) throws -> Data {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: protectionKey)
        return try ECIES.unwrap(wrapped, agree: { try privateKey.sharedSecretFromKeyAgreement(with: $0) }, context: context)
    }
}
