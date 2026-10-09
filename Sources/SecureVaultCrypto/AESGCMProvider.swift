//
//  AESGCMProvider.swift
//  SecureVaultCrypto
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation
import SecureVaultCore

/// AES-256-GCM with a random 96-bit nonce (PRD §13).
public struct AESGCMProvider: CryptoProvider {
    public init() {}

    public var algorithm: String { "A256GCM" }

    public func seal(_ plaintext: Data, using key: SymmetricKey, authenticating aad: Data) throws -> Data {
        // Same bytes as `combined` (nonce ‖ ciphertext ‖ tag), without its optional, which is only nil for custom nonce sizes.
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        return Data(box.nonce) + box.ciphertext + box.tag
    }

    public func open(_ sealed: Data, using key: SymmetricKey, authenticating aad: Data) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key, authenticating: aad)
    }
}

/// Key derivation and blind indexes shared by the database and file stores.
public enum KeyDerivation {
    public static func derive(_ key: SymmetricKey, label: String, salt: Data = Data()) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, info: Data("SecureVault.\(label).v1".utf8), outputByteCount: 32)
    }

    public static func blindIndex(_ value: String, key: SymmetricKey) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: key))
    }

    public static func randomBytes(_ count: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: count * 8)).withUnsafeBytes { Data($0) }
    }
}
