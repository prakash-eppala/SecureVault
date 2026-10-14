//
//  Configuration.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import Foundation

extension SecureVault {
    /// Vault settings. The defaults implement the PRD; change them only with a reason.
    public struct Configuration: Sendable {
        /// Separates this vault's Keychain items and files from any other vault in the app.
        public var identifier: String
        /// Root for encrypted files and databases. Default: `Application Support/SecureVault/<identifier>`.
        public var directory: URL?
        /// Keychain access group for sharing with extensions (PRD §32).
        public var keychainAccessGroup: String?
        /// Secure Enclave wrapping of device-only keys (PRD §15.2).
        public var secureEnclave: SecureEnclaveUsage
        /// Delete Keychain items left over from a previous install (PRD §31). Ignored when `keychainAccessGroup` is set.
        public var resetKeychainOnReinstall: Bool
        /// Namespaces cleared by `logout()` (PRD §23).
        public var sessionNamespaces: Set<VaultNamespace>
        /// `os.Logger` output with hashed key names only. Off by default (PRD §26).
        public var loggingEnabled: Bool
        /// Overrides the Keychain, e.g. `InMemoryKeychain()` in tests.
        public var keychain: (any KeychainBackend)?
        /// Overrides device capability detection, e.g. `FixedDeviceCapabilities()` in tests.
        public var capabilities: (any DeviceCapabilities)?
        /// Overrides the key protector chosen from `secureEnclave`.
        public var keyProtector: (any KeyProtector)?
        /// Time source for expiry. Override in tests.
        public var clock: @Sendable () -> Date

        public init(
            identifier: String = Bundle.main.bundleIdentifier ?? "SecureVault",
            directory: URL? = nil,
            keychainAccessGroup: String? = nil,
            secureEnclave: SecureEnclaveUsage = .whenAvailable,
            resetKeychainOnReinstall: Bool = true,
            sessionNamespaces: Set<VaultNamespace> = [.auth, .session, .cache],
            loggingEnabled: Bool = false
        ) {
            precondition(!identifier.isEmpty, "identifier must not be empty")
            self.identifier = identifier
            self.directory = directory
            self.keychainAccessGroup = keychainAccessGroup
            self.secureEnclave = secureEnclave
            self.resetKeychainOnReinstall = resetKeychainOnReinstall
            self.sessionNamespaces = sessionNamespaces
            self.loggingEnabled = loggingEnabled
            self.keychain = nil
            self.capabilities = nil
            self.keyProtector = nil
            self.clock = { Date() }
        }

        /// An isolated vault for unit tests and previews: in-memory Keychain, fixed capabilities, its own directory.
        public static func testing(
            directory: URL = FileManager.default.temporaryDirectory.appendingPathComponent("SecureVault-\(UUID().uuidString)"),
            capabilities: FixedDeviceCapabilities = FixedDeviceCapabilities(),
            keychain: any KeychainBackend = InMemoryKeychain()
        ) -> Configuration {
            var configuration = Configuration(identifier: "test", directory: directory, secureEnclave: .never)
            configuration.keychain = keychain
            configuration.capabilities = capabilities
            return configuration
        }
    }

    /// What `logout(_:)` removes in addition to the configured session namespaces.
    public struct LogoutOptions: Sendable {
        public var additionalNamespaces: Set<VaultNamespace>
        public var databases: [String]
        public var includeFiles: Bool

        public init(additionalNamespaces: Set<VaultNamespace> = [], databases: [String] = [], includeFiles: Bool = true) {
            self.additionalNamespaces = additionalNamespaces
            self.databases = databases
            self.includeFiles = includeFiles
        }
    }

    /// The outcome of `rotateKeys()`.
    public struct KeyRotationReport: Sendable, Equatable {
        /// Key-value items re-encrypted under the new key.
        public var reencryptedItems = 0
        /// Items that need user authentication and were left on their old key, which is retained.
        public var skippedItems = 0
        public var reencryptedRecords = 0
        public var reencryptedFiles = 0
        public var retiredKeyVersions = 0
        public var isComplete: Bool { skippedItems == 0 }
    }
}
