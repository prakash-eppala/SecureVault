# SecureVault — Product Requirements Document v1.0

**Unified Secure Storage & Encrypted Data SDK for iOS (Swift, Objective-C and SwiftUI)**

## Document Control

| Field | Value |
|---|---|
| Version | 1.0 |
| Date | 9 October 2026 |
| Status | Draft for review. Engineering decisions are resolved; business decisions are open (see §51). |
| Scope | The V1 SDK for Swift, Objective-C and SwiftUI. Business decisions still open are listed in §51. |

## 1. Executive Summary

SecureVault is an iOS SDK that provides a single, secure, developer-friendly storage API for data ranging from ordinary application preferences to highly sensitive financial and medical information.

Today, iOS developers commonly use UserDefaults, Keychain, CryptoKit, Secure Enclave, Data Protection, SQLite/Core Data, LocalAuthentication, and custom migration/key-management code independently. This creates fragmented implementations and security mistakes.

SecureVault provides one abstraction for secure key-value storage, encrypted objects, structured encrypted records, and protected files. It uses Apple-backed security mechanisms underneath and selects protection based on data classification and policy. It is usable from Swift (async/await), Objective-C (completion blocks and NSError) and SwiftUI (property wrapper, environment injection and a biometric gate view).

## 2. Problem Statement

Developers frequently maintain separate storage systems for preferences, credentials, sessions, encrypted objects, databases, files, and biometrics. This leads to duplicated code, inconsistent security policies, accidental plaintext storage, weak key handling, difficult key rotation, and difficult migrations.

SecureVault addresses this by providing a unified, policy-driven persistence layer.

## 3. Product Vision

SecureVault should become the security-aware persistence layer for iOS applications.

The developer describes what needs to be stored and its security requirement; SecureVault determines the appropriate Apple-backed mechanism, such as Keychain, CryptoKit-backed encryption, Data Protection, Secure Enclave where appropriate, or encrypted record/file storage. The mapping is deterministic and documented (§10) so that every decision is auditable.

## 4. Goals

- Unified API for tokens, credentials, sessions, preferences, Codable objects, secrets, encrypted records, files, and databases.
- Secure-by-default behaviour with a published, deterministic policy mapping.
- Apple-native security primitives only.
- Strong key management and lifecycle handling.
- Structured encrypted local storage.
- Enterprise-ready architecture.
- Swift concurrency and type-safe APIs.
- First-class Objective-C and SwiftUI integration, with values readable across all three surfaces.

## 5. Non-Goals

SecureVault will not implement custom cryptographic algorithms, replace CryptoKit or Keychain at the OS level, implement a new SQL engine, provide server-side authentication, replace OAuth/OIDC, guarantee application security or regulatory compliance by itself, or act as a cloud backup service.

In addition, V1 will not:

- Synchronise secrets through iCloud Keychain. Requesting synchronisation is a policy error (§30).
- Bundle SQLCipher or any third-party database engine (§17).
- Share databases or files between an app and its extensions (§32).
- Detect jailbreaks or attest app integrity (V3).
- Provide relational queries, joins or secondary indexes (V2).
- Persist one-time passwords by default (§21).

## 6. Target Users and Supported Platforms

Primary users include iOS developers and teams building banking, fintech, healthcare, enterprise, and consumer applications that need secure local persistence.

| Dimension | V1 decision |
|---|---|
| Platforms | iOS 15+, iPadOS 15+, Mac Catalyst 15+, macOS 12+. macOS is supported so the package builds and tests with `swift test` and for Mac apps. watchOS, tvOS and visionOS are out of scope for V1. |
| Toolchain | Swift 6 language mode, swift-tools-version 6.0, Xcode 16 or later. |
| Product | One product, `SecureVault`, for every app. Swift and SwiftUI use `import SecureVault`; Objective-C uses `@import SecureVault;` and sees only the `SV…` classes. |
| Swift | Async/await API, Codable values, typed errors. |
| Objective-C | `SVVault`, `SVPolicy`, `SVDatabase`, `SVFileStore`, completion blocks delivered on the main queue, `NSError` in a stable domain (§37). |
| SwiftUI | `@SecureStorage`, `SecureValue` observable model, `.secureVault(_:)` environment, `BiometricGate` view (§38). |
| Distribution | Swift Package Manager in V1. A prebuilt XCFramework is V2. CocoaPods and Carthage are not planned. |
| Cross-platform frameworks | React Native and Flutter bridges are not in V1; they can wrap the Objective-C surface later. |

## 7. Product Principles

1. Secure by default.
1. Minimize stored data.
1. Never implement custom cryptography.
1. Protect keys independently from ciphertext.
1. Keep developer APIs simple.
1. Make security policies explicit.
1. Fail closed when required protection cannot be satisfied.
1. Never destroy data automatically to recover from an error. Recovery that deletes data is always an explicit API call.

## 8. High-Level Architecture

Application (Swift / Objective-C / SwiftUI) → SecureVault public API → Policy Engine → Storage Router → Keychain store / Encrypted object store / Secure Database / Protected File Store → Key Manager → Keychain (+ Secure Enclave key wrapping where appropriate) → CryptoKit / Data Protection.

The SDK hides implementation complexity while keeping security decisions explicit and auditable. Every stored value, wherever it lives, is sealed in the same authenticated envelope (§14).

## 9. Core Components

| Component | Responsibility | Module |
|---|---|---|
| SecureVault | Primary public API and orchestration (store, retrieve, logout, rotation, migration). | SecureVault |
| StoragePolicy / PolicyEngine | Classification, presets, validation and resolution to a concrete placement (§10). | SecureVaultCore |
| Keychain store | Keychain items in the data-protection keychain (§12). | SecureVaultKeychain |
| Encrypted object store | Envelope files for values not placed in the Keychain (§11). | SecureVaultCore |
| CryptoProvider | AES-256-GCM, HKDF, HMAC via CryptoKit (§13). | SecureVaultCrypto |
| KeyManager / KeyProtector | Key generation, versioning, rotation, Secure Enclave wrapping (§15–16). | SecureVaultCore / SecureVaultCrypto |
| SecureDatabase | Encrypted Codable record store on system SQLite (§17). | SecureVaultDatabase |
| ProtectedFileStore | Streaming-encrypted files (§19). | SecureVaultFiles |
| BiometricAuthenticator | LocalAuthentication integration and device capability detection (§20). | SecureVaultBiometrics |
| Diagnostics | Security posture report without secret values (§25). | SecureVaultDiagnostics |
| Objective-C facade | NSObject API over the Swift core (§37). | SecureVault |
| SwiftUI layer | Property wrapper, observable model, environment and biometric gate (§38). | SecureVault |

## 10. Data Classification and Policy Mapping

### 10.1 Classes

**Standard:** themes, language and non-sensitive preferences. **Sensitive:** user profiles and non-critical offline data. **Secret:** access tokens, refresh tokens, credentials and cryptographic metadata. **Highly Sensitive:** financial data, medical data and confidential enterprise records. **Biometric Protected:** information that requires user presence or biometric/passcode authorization on every read.

### 10.2 Default mapping

| Class | Default backend | Accessibility | Device-only | User auth | Passcode required | File protection |
|---|---|---|---|---|---|---|
| Standard | Encrypted object store | After first unlock | No (backed up) | — | No | Until first user auth |
| Sensitive | Encrypted object store | After first unlock | Yes | — | No | Until first user auth |
| Secret | Keychain if ≤ 4 KB, otherwise encrypted object store | After first unlock | Yes | — | No | Until first user auth |
| Highly Sensitive | Encrypted object store | When unlocked | Yes (mandatory) | — | Yes | Complete |
| Biometric Protected | Keychain only (≤ 64 KB) | When passcode set | Yes (mandatory) | Biometry, current set | Yes | n/a (Keychain) |

SecureVault never writes to UserDefaults. Even Standard data is encrypted. UserDefaults is only ever read, during migration (§24).

### 10.3 Presets

| Preset | Class | Differences from class default |
|---|---|---|
| `.standard`, `.preference` | Standard | — |
| `.sensitive` | Sensitive | — |
| `.secret`, `.accessToken`, `.refreshToken`, `.session` | Secret | After-first-unlock so background refresh works (§33). |
| `.credential` | Secret | When unlocked. |
| `.otp` | Secret | Expires after 5 minutes. |
| `.highlySensitive` | Highly Sensitive | — |
| `.biometric` | Biometric Protected | — |

Presets are values, so modifiers compose: `.accessToken.expiring(after: 3600)`, `.sensitive.allowingBackup()`, `.secret.stored(in: .encryptedFile)`, `.highlySensitive.requiringUserAuthentication(.userPresence)`.

### 10.4 Routing rules

- Backend `.automatic` resolves to the Keychain when the policy requires user authentication, or when the class is Secret or higher and the encoded value is 4 KB or less. Otherwise it resolves to the encrypted object store.
- An explicit backend (`.keychain` or `.encryptedFile`) is honoured if it passes validation.
- Storing a key again with a different placement moves it: the new copy is written first, then the old copy is deleted.

### 10.5 Validation rules (fail closed)

Resolution fails with `securityPolicyViolation` (or the specific error shown) instead of weakening protection:

| # | Rule | Error |
|---|---|---|
| R1 | Synchronisation requested. | securityPolicyViolation |
| R2 | Highly Sensitive or Biometric Protected data marked as allowed in backups. | securityPolicyViolation |
| R3 | Accessibility weaker than the class minimum (Highly Sensitive ≥ when unlocked; Biometric ≥ when passcode set). | securityPolicyViolation |
| R4 | User authentication requested with the encrypted object store backend (V1 supports it on Keychain items only). | securityPolicyViolation |
| R5 | User authentication or when-passcode-set requested with backup allowed. | securityPolicyViolation |
| R6 | Keychain placement for a value larger than 64 KB. | securityPolicyViolation |
| R7 | Biometric Protected class without a user-authentication requirement. | securityPolicyViolation |
| R8 | Policy requires a device passcode and none is set. | securityPolicyViolation |
| R9 | Biometry required and none is enrolled or available. | biometryNotAvailable |
| R10 | Secure Enclave set to `.required` and none is available. | securityPolicyViolation |

## 11. Secure Key-Value Storage

The SDK provides store, retrieve, value (optional), exists and delete operations for Codable values:

```
try await vault.store(token, forKey: "accessToken", namespace: .auth, policy: .accessToken)
let token: String = try await vault.retrieve(forKey: "accessToken", namespace: .auth)
let theme = try await vault.value(Theme.self, forKey: "theme")   // nil when absent or expired
```

| Aspect | Decision |
|---|---|
| Encoding | JSON (`JSONEncoder`) so Swift and Objective-C read each other's values. A type that does not decode raises `typeMismatch`. |
| Keychain location | Generic password, service `<vaultID>.kv.<namespace>`, account = key. |
| File location | `Application Support/SecureVault/<vaultID>/objects/<SHA-256(namespace)>/<SHA-256(vaultID\|namespace\|key)>`. Key names do not appear on disk. |
| Envelope | Every value, including Keychain-stored ones, is sealed in the §14 envelope. Expiry is authenticated and tampering is detected the same way in both backends. |
| Lookup | Retrieve checks the Keychain, then the object store. A key exists in at most one backend. |
| Writes | Atomic: file writes replace the file in one step; Keychain writes use update-in-place (§12). |

## 12. Keychain Layer

| SecureVault accessibility | Device-only | kSecAttrAccessible |
|---|---|---|
| When unlocked | Yes / No | WhenUnlockedThisDeviceOnly / WhenUnlocked |
| After first unlock | Yes / No | AfterFirstUnlockThisDeviceOnly / AfterFirstUnlock |
| When passcode set | Always yes | WhenPasscodeSetThisDeviceOnly |

- All items use the data-protection keychain (`kSecUseDataProtectionKeychain`) on every platform.
- User authentication uses `SecAccessControl` flags: `.userPresence`, `.biometryAny`, `.biometryCurrentSet` or `.devicePasscode`.
- Overwrites use `SecItemUpdate`, which is atomic. Items with access control are deleted and re-added, because updating them needs an authentication prompt. This is the one non-atomic write; it is documented in the API reference.
- Keychain calls block, so they run on a dedicated dispatch queue, never on the Swift cooperative thread pool.
- An optional `keychainAccessGroup` setting allows Keychain sharing with extensions (§32).
- The Keychain backend is a protocol, so tests and consumers can inject an in-memory implementation.

## 13. CryptoKit Layer

| Use | Primitive |
|---|---|
| Value, record and chunk encryption | AES-256-GCM, 96-bit random nonce, 128-bit tag |
| Sub-key derivation | HKDF-SHA256 |
| Blind indexes for record ids | HMAC-SHA256 |
| Key wrapping in the Secure Enclave | P-256 ECDH (Secure Enclave key) + HKDF-SHA256 + AES-256-GCM (ECIES) |
| Hashing of file and namespace names | SHA-256 |

CryptoKit is a building block inside SecureVault, not the storage system. Each envelope records an algorithm identifier, so future algorithms can be added behind the `CryptoProvider` protocol.

## 14. Encryption Flow and Envelope Format

Codable value → JSON → AES-256-GCM with associated data → envelope → Keychain item or file.

| Field | Size | Content |
|---|---|---|
| Magic | 3 bytes | `SVE` |
| Format version | 1 byte | 1 |
| Header length | 4 bytes, big-endian | n |
| Header | n bytes | JSON: algorithm, key purpose, key domain, key version, created-at, expires-at |
| Sealed box | remaining | nonce ‖ ciphertext ‖ tag |

The associated data is the magic, version, length and header bytes plus a location context: SHA-256 of `vaultID|namespace|key` (or the record or file equivalent). Changing the expiry, the key version, or moving a ciphertext to another key or record fails authentication with `decryptionFailed`.

## 15. Key Management

### 15.1 Key hierarchy

A data key is identified by **purpose**, **protection domain** and **version**. Purposes are `kv` (key-value), `files`, and `db.<name>` (one per database). The protection domain is the pair (accessibility, device-only), which gives five domains: when-unlocked local/portable, after-first-unlock local/portable, and when-passcode-set local.

- Each key is a random 256-bit `SymmetricKey`, stored as a Keychain item in service `<vaultID>.keys`, account `<purpose>|<domain>|v<N>`, with the domain's own accessibility. A key is never more available than the data it protects.
- Keys are created with add-only writes. Concurrent first-use requests are de-duplicated in the `KeyManager` actor, so two callers can never create two different version-1 keys.
- The current version is the highest version present, so no separate pointer item is needed.
- Unwrapped keys are cached in memory. The cache is cleared by `vault.lock()` and, for when-unlocked domains, when the device locks.

### 15.2 Secure Enclave

- Setting `secureEnclave`: `.whenAvailable` (default), `.required` or `.never`.
- The Secure Enclave holds only P-256 keys, so it wraps data keys rather than storing them. One Secure Enclave key-agreement key per vault is created and its opaque handle kept in the Keychain.
- Wrapping applies to device-only domains only. Portable keys are never Secure Enclave-wrapped, because a backup restored to another device could not unwrap them.
- `.required` on a device without a Secure Enclave fails with `securityPolicyViolation` (rule R10).

### 15.3 Revocation

Revocation means crypto-shredding: deleting a key version makes every value sealed with it permanently unreadable. `vault.reset()` destroys all keys and data. There is no remote revocation in V1.

## 16. Key Rotation

`try await vault.rotateKeys()` rotates every purpose and domain in use and returns a `KeyRotationReport`.

1. Create version N+1 of each key in use. New writes use it immediately.
1. Re-encrypt each item sealed with an older version: open with the old key, seal with the new key, replace atomically.
1. Rotate each database inside a single SQLite transaction (§17).
1. Delete an old key version only when no item still references it.

**Crash safety:** every envelope names its key version, and old versions are deleted last. An interrupted rotation leaves a mix of versions that are all still readable; calling `rotateKeys()` or `completePendingRotations()` again finishes the work. No journal is needed.

**Items requiring user authentication** cannot be re-encrypted without a prompt. They are reported as skipped and their old key version is retained until they are rewritten.

## 17. Secure Database

### 17.1 Engine

V1 uses the **system SQLite** library with **record-level AES-256-GCM** and **HMAC blind indexes**. It does not use SQLCipher.

**Why not whole-database encryption:** it requires SQLCipher, which adds a third-party C dependency, a licence review, and a known conflict with the system SQLite that other frameworks link. V1 instead encrypts every record and replaces type names and ids with keyed hashes.

What remains visible to someone who copies the file: the number of records per type, record sizes, and when records change. The engine sits behind a protocol so that a SQLCipher engine can be added in V2 for customers who need whole-file encryption.

### 17.2 Storage layout

```
CREATE TABLE records (type_tag BLOB, id_tag BLOB, payload BLOB NOT NULL,
                      PRIMARY KEY (type_tag, id_tag)) WITHOUT ROWID;
CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB);
PRAGMA journal_mode = WAL;  PRAGMA secure_delete = ON;
```

- One database file per name, in a directory with the policy's file protection, which new WAL and SHM files inherit.
- Encryption and index keys are derived from the database key version with HKDF. `type_tag` and `id_tag` are HMACs, so patient ids and type names never appear in the file.
- Each payload is an envelope whose associated data includes the type and id tags, so rows cannot be swapped.
- The policy is fixed when the database is created and recorded in `meta`. Reopening with a different policy uses the recorded one and logs a warning.

### 17.3 Data model and queries

The database is a typed document store. Records conform to `SecureRecord` (Codable, Sendable, Identifiable with a string-convertible id). V1 queries:

- `insert` (upsert), `insert(contentsOf:)` in one transaction
- `get(_:id:)` returning an optional
- `all(_:)` and `all(_:where:)` with in-memory filtering
- `count(_:)`, `delete(_:id:)`, `deleteAll(_:)`
- `rotateKey()` in one transaction; the old key is deleted after commit and orphaned keys are cleaned up on the next open

Indexed queries, sorting in SQL and joins are V2. Model evolution follows Codable rules: add new fields as optionals. A breaking change is handled by the app reading with the old type and writing with the new type.

### 17.4 Device lock

When file protection is Complete, the database is closed when protected data becomes unavailable and reopened on next use. This avoids the `0xdead10cc` termination that iOS applies to apps holding locked files.

## 18. Database API

```
let db = try await vault.database("medical", policy: .highlySensitive)
try await db.insert(patient)
let patient = try await db.get(Patient.self, id: patientID)   // Patient?
let adults = try await db.all(Patient.self) { $0.age >= 18 }
try await db.delete(Patient.self, id: patientID)
```

## 19. Secure Files

- Every file is encrypted and also gets Data Protection. Device-only files are excluded from backup.
- Streaming format: the STREAM construction (online authenticated encryption) with AES-256-GCM over 64 KiB chunks. Each file gets its own key, derived with HKDF from the data key and a random 32-byte salt.
- Each chunk nonce is a 7-byte random prefix, a 4-byte counter and a last-chunk flag. This detects truncation, reordering and splicing.
- The file name, size and creation date are stored encrypted in the file, so names do not appear on disk while `list(namespace:)` still works.
- API: write from `Data` or stream from a file URL; read to `Data` or stream to a URL; exists, delete, list, clear namespace, rotate.
- Files are rewritten through a temporary file in the same directory, then replace the original in one atomic step.

## 20. Biometric Protection

- Supported requirements: `.userPresence` (biometry or passcode), `.biometryAny`, `.biometryCurrentSet` (default for `.biometric`), `.devicePasscode`.
- With `.biometryCurrentSet`, adding or removing a fingerprint or face permanently invalidates the item. Reads then fail with `itemNotFound`. Apps must treat this as "sign in again". Use `.biometryAny` or `.userPresence` when lower friction matters more than detecting new enrollments.
- `BiometricAuthenticator.authenticate(reason:reuseDuration:)` returns an `AuthenticationContext` that can be passed to several reads, so the user is prompted once.
- In V1, biometric gating applies to Keychain items up to 64 KB. Biometric-gated databases and files are V2.
- The host app must declare `NSFaceIDUsageDescription`.
- Biometric authentication is a local protection layer and must not replace server-side authorization for sensitive banking or healthcare operations.

## 21. Expiration

- The expiry time is in the authenticated envelope header, so it cannot be changed without detection.
- On read, an expired item is deleted and `expired` is thrown; `value(...)` returns nil. `purgeExpired()` deletes all expired items.
- Expiry uses the device wall clock, which the user can change. It reduces exposure but is not a security boundary; the server must enforce token lifetimes.
- OTPs should not be persisted unless the product needs it. The `.otp` preset defaults to 5 minutes.

## 22. Namespaces

The type is `VaultNamespace` (not `Namespace`, which would clash with SwiftUI's `@Namespace`). Built-in namespaces: `default`, `auth`, `session`, `user`, `preferences`, `medical`, `financial`, `cache`. A namespace maps to a Keychain service and an object-store directory, and is also used by the file store, so clearing one is a bounded operation.

**Multiple accounts on one device:** use a namespace per user (for example `user.<accountID>`) and clear it on account removal. Logging out of one account does not affect another.

## 23. Logout

`vault.logout()` clears the configured session namespaces (default: `auth`, `session`, `cache`) in the Keychain, object store and file store. `LogoutOptions` can add namespaces, name databases to delete, and include persistent data. Logout deletes data but keeps keys, because keys are shared across namespaces. To crypto-shred everything, use `reset()`.

## 24. Migration

The developer lists what to migrate. SecureVault never scans UserDefaults or the Keychain on its own.

```
let report = await vault.migrate([
  .userDefaults("authToken", as: String.self, to: "accessToken", namespace: .auth, policy: .accessToken),
  .keychain(service: "com.acme.legacy", account: "refresh", to: "refreshToken", namespace: .auth, policy: .refreshToken),
])
```

1. Read the source. If it is absent, report it as skipped (this makes migration safe to run on every launch).
1. Store it in SecureVault with the target policy.
1. Read it back and compare bytes. Only on a match, delete the source.
1. Report each item as migrated, skipped or failed. A failure leaves the source intact.

Prior SecureVault formats are handled by the envelope format version. V1 reads format 1.

## 25. Security Diagnostics

`await vault.securityReport()` returns findings with a severity and a stable code. It never includes values or key names. V1 findings: no device passcode; biometry unavailable; Secure Enclave unavailable; in-memory Keychain in use; rotation pending (more than one key version); portable (backed-up) domains in use; after-first-unlock (background-readable) domains in use.

## 26. Logging

Logging uses `os.Logger` with subsystem `com.securevault.sdk` and is **off by default**. When enabled, it records operation names, namespaces and hashed key names only. It never logs values, tokens, keys, decrypted payloads, record contents or file contents.

## 27. Concurrency

- `KeyManager`, the object store, each `SecureDatabase` and the `ProtectedFileStore` are actors. `SecureVault` is an immutable `Sendable` class.
- Keychain and LocalAuthentication calls run on a dedicated queue and are bridged with continuations.
- Cancellation is checked between steps. A Keychain or file write that has started is allowed to finish, so cancellation never leaves a half-written value.
- The package compiles in Swift 6 language mode with complete concurrency checking.

## 28. Error Model

Swift: `SecureVaultError`. Objective-C: `NSError` in domain `com.securevault.error` with the codes below. Error reasons never contain secret values.

| Code | Case | Meaning |
|---|---|---|
| 1 | itemNotFound | No value for the key (also after a biometry set change) |
| 2 | invalidData | Envelope or payload is malformed |
| 3 | typeMismatch | Stored value does not decode as the requested type |
| 4 | encryptionFailed | Sealing failed |
| 5 | decryptionFailed | Authentication failed: tampered data, wrong key or moved ciphertext |
| 6 | keyUnavailable | The key version is missing (for example after restore to a new device) |
| 7 | keyRotationFailed | Rotation could not complete |
| 8 | authenticationRequired | The item needs user authentication and none was possible |
| 9 | authenticationFailed | Biometry or passcode did not match |
| 10 | userCancelled | The user dismissed the prompt |
| 11 | biometryNotAvailable | No biometry hardware or nothing enrolled |
| 12 | biometryLockout | Too many failed attempts |
| 13 | accessDenied | Keychain entitlement or access group problem |
| 14 | protectedDataUnavailable | The device is locked and the data is when-unlocked |
| 15 | expired | The value passed its expiry and was deleted |
| 16 | migrationFailed | A migration step failed; the source is intact |
| 17 | databaseFailure | SQLite error |
| 18 | fileFailure | File-system error |
| 19 | securityPolicyViolation | A rule in §10.5 failed |
| 20 | keychainFailure | Unmapped Keychain status |
| 21 | cancelled | The task was cancelled before work started |

## 29. Fail-Closed Behaviour

If a requested policy cannot be satisfied, SecureVault returns an error instead of falling back to weaker storage (§10.5).

**Simulator exception:** the iOS Simulator cannot report a passcode, so SecureVault treats it as passcode-set and logs a warning. This applies only in simulator builds (`targetEnvironment(simulator)`), never on a device. Simulator biometry follows the Simulator's Face ID / Touch ID enrollment menu.

## 30. Backup & Synchronization

- iCloud Keychain synchronisation is not supported in V1; requesting it is a policy error (R1).
- Device-only is the default for every class except Standard.
- Sensitive and Secret data can opt into backup with `.allowingBackup()`. Highly Sensitive and Biometric data cannot (R2).
- Portable data uses portable keys, so a restored backup can decrypt it. Device-only files are excluded from backup so backups do not carry undecryptable files.

## 31. Reinstall and Restore

- **Reinstall:** Keychain items survive app deletion. SecureVault writes an install marker in its Application Support directory. If the marker is missing at startup, all Keychain items for the vault are deleted before first use (`resetKeychainOnReinstall`, default on).
- **Restore to a new device:** portable data restores and works. Device-only data restores without its keys, so reads fail with `keyUnavailable`.
- Following principle 8, nothing is deleted automatically. The app calls `purgeUnreadableItems()` or `deleteDatabase(_:)` and then re-fetches from its server.

## 32. App Extensions

V1 supports Keychain sharing through `keychainAccessGroup`. Sharing databases and files through an App Group container is V2: it needs cross-process file coordination and must avoid the `0xdead10cc` termination when a suspended process holds a lock.

## 33. Device Lock and Background Access

| Accessibility | Readable while locked? | Use for |
|---|---|---|
| After first unlock | Yes, after the first unlock since boot | Tokens used by background refresh, push handling, sessions |
| When unlocked | No (`protectedDataUnavailable`) | Highly sensitive data and credentials |
| When passcode set | No; deleted if the passcode is removed | Biometric-protected items |

`.accessToken`, `.refreshToken` and `.session` default to after-first-unlock so background work keeps working. Databases with Complete protection close when the device locks (§17.4).

## 34. Threat Model

Threats include plaintext storage, key extraction, stolen databases/files, ciphertext tampering or relocation, backup leakage, debug/log leakage, key-rotation failures, memory exposure, and developer misconfiguration.

Mitigations include the Keychain, authenticated encryption with location-bound associated data, independent key protection with optional Secure Enclave wrapping, Data Protection, device-only defaults, logging off by default, versioned keys, crash-safe rotation and migration, and fail-closed validation.

**Known residual risk:** an attacker with file-system write access can roll an item back to an older valid ciphertext for the same key. V1 does not prevent this. Version counters are a V2 candidate.

## 35. Security Boundaries

SecureVault cannot protect against a compromised backend, malicious server, compromised operating system, kernel-level compromise, fully controlled jailbroken device, malicious application with equivalent privileges, or server-side authorization failures.

**Memory:** Swift does not guarantee that `Data` or `String` copies are zeroed. Decrypted values and cached keys exist in process memory while in use; `vault.lock()` drops cached keys. Documentation must clearly communicate these limitations.

## 36. Package Structure

| Module | Product? | Depends on |
|---|---|---|
| SecureVaultCore | internal | Foundation, Security, CryptoKit, LocalAuthentication |
| SecureVaultKeychain | internal | Core |
| SecureVaultCrypto | internal | Core |
| SecureVaultBiometrics | internal | Core |
| SecureVaultDatabase | internal | Core, Crypto, system sqlite3 |
| SecureVaultFiles | internal | Core, Crypto |
| SecureVaultDiagnostics | internal | Core |
| SecureVault | **The only product.** Re-exports the modules above and contains the Objective-C and SwiftUI layers. | all of the above, SwiftUI |

Every app needs only `import SecureVault` (Objective-C: `@import SecureVault;`). Linking SwiftUI costs nothing on the supported OS versions, where it is a system framework, so a separate SwiftUI product is not worth the extra choice. The package ships a `PrivacyInfo.xcprivacy` (§39).

## 37. Objective-C Support

```
@import SecureVault;

SVVault *vault = SVVault.sharedVault;
[vault setString:token forKey:@"accessToken" namespace:@"auth"
          policy:SVPolicy.accessToken completion:^(NSError *error) { ... }];
[vault stringForKey:@"accessToken" namespace:@"auth"
         completion:^(NSString *value, NSError *error) { ... }];
```

- Classes: `SVVault`, `SVPolicy` (presets as class properties, mutable copy for overrides), `SVDatabase` (JSON-dictionary records), `SVFileStore`, `SVBiometrics`, `SVSecurityReport`.
- Values: `NSData`, `NSString`, `NSNumber`, and any `NSSecureCoding` object (archived with secure coding).
- Strings, data and numbers use the same JSON encoding as Swift, so a value written in Objective-C can be read in Swift and the other way round.
- Completion blocks are always called on the main queue. Errors are `NSError` in domain `com.securevault.error` (`SVErrorCode`).

## 38. SwiftUI Support

```
@SecureStorage("accessToken", namespace: .auth, policy: .accessToken) var token: String?

ContentView()
  .secureVault(vault)                 // defaults to SecureVault.shared
  .biometricLock(reason: "Unlock your records")
```

- `@SecureStorage` loads asynchronously and publishes changes. Setting the value stores it; setting nil deletes it. `$token` exposes `isLoading`, `error` and a `Binding`.
- `SecureValue<Value>` is the underlying `ObservableObject` (main actor), usable directly in view models.
- `BiometricGate` / `.biometricLock(reason:)` hides content until the user authenticates and locks again when the app goes to the background.

## 39. App Store and Compliance Obligations

- The package ships `PrivacyInfo.xcprivacy` declaring UserDefaults access with reason CA92.1 (used only to read the app's own values during migration).
- Export compliance: SecureVault uses only Apple's encryption APIs. The host app still answers `ITSAppUsesNonExemptEncryption` and the App Store Connect export questions; SecureVault documents what it uses.
- The host app must add `NSFaceIDUsageDescription` when using biometric policies.
- FIPS: CryptoKit is backed by Apple corecrypto, which Apple submits for FIPS 140 validation. SecureVault makes no FIPS or regulatory claim of its own.

## 40. V1 Scope

- Swift Package Manager; Swift 6, async/await, actors
- Swift, Objective-C and SwiftUI surfaces
- Codable support
- Keychain storage
- AES-256-GCM authenticated encryption
- Secure key generation, protection and Secure Enclave wrapping
- Deterministic policy mapping and fail-closed validation
- Device-only defaults; Data Protection
- Biometric protection on Keychain items
- Expiration
- Namespaces and logout cleanup
- UserDefaults and Keychain migration
- Encrypted record database (system SQLite)
- Encrypted, streaming protected file storage
- Key versioning and manual crash-safe rotation
- Reinstall handling
- Basic security report
- Privacy manifest
- Unit, integration, security and concurrency tests

## 41. V2 Scope

- Optional SQLCipher whole-file database engine
- Indexed queries, SQL sorting and joins
- Biometric-gated databases and files
- Scheduled automatic key rotation
- App Group sharing of databases and files
- Rollback protection (version counters)
- Advanced file features: background re-encryption, file coordination
- Prebuilt XCFramework
- Security audit reporting, storage inspection and debug tooling
- Additional migration sources

## 42. V3 Scope

Enterprise security policies, compliance-oriented profiles, security posture reporting, centralized policy configuration, application-integrity integration and advanced organization-level key lifecycle management.

## 43. Banking and Healthcare Examples

**Banking:** access and refresh tokens use `.accessToken` / `.refreshToken` (Keychain, after-first-unlock, device-only). Offline transactions live in `vault.database("transactions", policy: .highlySensitive)`. Payment confirmation uses `.biometric` or a `BiometricGate`, while server-side authorization remains authoritative.

**Healthcare:** patient records live in a `.highlySensitive` database, and reports in the protected file store under `.highlySensitive`. Everything is device-only and readable only while the device is unlocked. Local persistence is limited to what the product experience requires.

## 44. Performance Requirements

| Operation | Target | Conditions |
|---|---|---|
| Keychain read | < 10 ms | Warm key cache, no user-authentication prompt |
| Encrypted key-value write | < 20 ms | Value ≤ 4 KB, warm key cache |
| Small object encryption | < 10 ms | ≤ 64 KB, in memory |
| Database open | < 100 ms | Raw 256-bit key from the Keychain (no passphrase KDF), existing file |
| File encryption throughput | Streaming, bounded memory | 64 KiB chunks; memory use does not grow with file size |

These are targets on representative devices (iPhone 12 or newer), not contractual SLAs. First use creates keys and may take longer.

## 45. Testing Strategy

- **Unit tests (`swift test` on macOS):** an injected in-memory Keychain and fixed device capabilities. They cover policy resolution and every validation rule, the envelope, expiry with a controllable clock, namespaces, logout, rotation, migration, reinstall, database, files and errors.
- **Security tests:** tampered ciphertext, tampered headers, moved ciphertext, wrong key, deleted key, truncated and reordered file chunks, interrupted rotation, and no plaintext on disk.
- **Concurrency tests:** hundreds of parallel reads and writes, concurrent first-key creation producing exactly one key, and cancellation.
- **Integration tests:** the real data-protection Keychain. A hostless SPM test bundle has no Keychain entitlement on macOS or the iOS Simulator, so these tests run from a small host app on the Simulator; elsewhere they skip themselves with a stated reason.
- **Objective-C tests:** an Objective-C test target using the `SVVault` API.
- **Manual device plan:** Secure Enclave wrapping, Face ID/Touch ID, enrollment change, device lock, reinstall and backup restore.

## 46. Acceptance Criteria

V1 is complete when developers can install the SDK through SPM and use it from Swift, Objective-C and SwiftUI to: store and retrieve Codable values under the published policy mapping; use Keychain-backed token policies; encrypt sensitive objects; protect keys independently; use biometric protection; expire values; isolate namespaces and log out; migrate existing values; use the encrypted database and file storage; rotate keys without data loss; detect tampering; and see every validation rule fail closed. The security and concurrency test suites must pass.

## 47. Competitive Positioning

SecureVault should not compete directly with CryptoKit. CryptoKit provides cryptographic primitives. SecureVault provides secure persistence, policy, key management and lifecycle orchestration. The positioning is not 'a better Keychain wrapper' but 'a policy-driven secure persistence layer for iOS.'

## 48. Core Differentiator

Policy-driven abstraction: the developer says 'store this data'; SecureVault determines how it should be protected based on its classification, size, lifecycle, access requirements and security policy, using the published mapping in §10.

## 49. Product Tagline

Primary: SecureVault — One API. Every level of data protection. Alternative: Store anything. Protect everything. Technical positioning: A policy-driven secure persistence layer for iOS.

## 50. Final Product Definition

SecureVault is a security abstraction layer, not another encryption library. Its long-term value is the combination of security policy, key management, secure storage, encryption, lifecycle management and developer experience. It should make secure storage easier without hiding important security decisions or making unrealistic claims about application-wide security or regulatory compliance.

## 51. Open Business Decisions

| Decision | Options | Why it matters |
|---|---|---|
| Licence model | Open source (MIT/Apache-2.0) / commercial / open-core | Sets the V2 SQLCipher licensing route and support obligations |
| Pricing and support | Free, per-app, enterprise tier | Enterprise buyers expect SLAs and security advisories |
| Owner and timeline | — | Not yet assigned |
| Success metrics | Adoption, integration time, zero plaintext incidents | Needed to judge V1 |
| Security review | External audit before 1.0 tag | Expected by banking and healthcare buyers |

## Appendix A — Recommended Architecture

```
Application (Swift | Objective-C | SwiftUI)
  ↓ SecureVault public API  (Swift, SV… Objective-C classes, SwiftUI layer)
  ↓ Policy Engine  →  validation rules R1–R10
  ↓ Storage Router
  ├── Keychain store        → data-protection Keychain
  ├── Encrypted object store → envelope files
  ├── Secure Database       → system SQLite, record-level AES-GCM
  └── Protected File Store  → chunked AES-GCM stream
  ↓ Key Manager (purpose × domain × version)
  ├── Keychain
  └── Secure Enclave key wrapping (device-only domains)
  ↓ CryptoKit / Data Protection
```

## Appendix B — V1 Definition of Done

- SPM installation and clean public API in Swift, Objective-C and SwiftUI
- Secure Codable key-value storage with the published policy mapping
- Keychain-backed token and secret policies
- AES-256-GCM authenticated encryption with location-bound envelopes
- Independent key protection with Secure Enclave wrapping
- Biometric/user-presence protection
- Expiration and namespaces
- Logout/session cleanup
- Migration from UserDefaults and existing Keychain
- Encrypted record database
- Encrypted streaming file storage
- Manual crash-safe key rotation
- Reinstall handling
- Tamper detection
- Swift 6 concurrency safety
- No secret leakage through SDK logs
- Privacy manifest
- Security, integration, concurrency and Objective-C test suites
- Security and threat-model documentation

