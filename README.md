# SecureVault

A policy-driven secure persistence layer for iOS. Describe how sensitive the data is; SecureVault picks the
Keychain, encrypted files or an encrypted database, binds keys to the right protection class, and fails closed
when the device cannot provide the protection you asked for.

Works from **Swift** (async/await), **Objective-C** (completion blocks, `NSError`) and **SwiftUI**
(`@SecureStorage`, `BiometricGate`). The spec is [docs/SecureVault_PRD.md](docs/SecureVault_PRD.md)
(also as [Word](docs/SecureVault_PRD_v1.0.docx)).

- Version 1.0.0 (build 1)
- iOS 15+, Mac Catalyst 15+, macOS 12+ · Swift 6 language mode · Xcode 16+
- No third-party dependencies: Keychain, CryptoKit, Secure Enclave, LocalAuthentication, system SQLite

## Install

```swift
.package(url: "<repository URL>", from: "1.0.0")
```

One product, `SecureVault`, serves every kind of app:

| Language | Import |
|---|---|
| Swift and SwiftUI | `import SecureVault` |
| Objective-C | `@import SecureVault;` (sees only the `SV…` classes) |

Add `NSFaceIDUsageDescription` to your Info.plist if you use biometric policies.

## Swift

```swift
let vault = SecureVault.shared

try await vault.store(token, forKey: "accessToken", namespace: .auth, policy: .accessToken)
let token: String = try await vault.retrieve(forKey: "accessToken", namespace: .auth)
let theme = try await vault.value(Theme.self, forKey: "theme")          // nil if absent or expired

try await vault.store(otp, forKey: "otp", namespace: .session, policy: .otp)   // expires in 5 minutes
try await vault.logout()                                                 // clears auth, session, cache

// Encrypted records
struct Patient: SecureRecord { let id: UUID; var name: String; var age: Int }
let db = try await vault.database("medical", policy: .highlySensitive)
try await db.insert(patient)
let found = try await db.get(Patient.self, id: patient.id)
let adults = try await db.all(Patient.self) { $0.age >= 18 }

// Encrypted files, streamed in 64 KiB chunks
try await vault.files.write(contentsOf: pdfURL, named: "report.pdf", namespace: .medical, policy: .highlySensitive)
let pdf = try await vault.files.read(named: "report.pdf", namespace: .medical)

// Biometric items: prompt once, read several
let auth = try await BiometricAuthenticator().authenticate(reason: "Show card details", reuseDuration: 10)
let pin: String = try await vault.retrieve(forKey: "cardPIN", namespace: .financial, authentication: auth)
```

### Policies

| Preset | Class | Stored in | Readable | Backed up |
|---|---|---|---|---|
| `.standard`, `.preference` | Standard | encrypted file | after first unlock | yes |
| `.sensitive` (default) | Sensitive | encrypted file | after first unlock | no |
| `.accessToken`, `.refreshToken`, `.session`, `.secret` | Secret | Keychain (≤ 4 KB) | after first unlock | no |
| `.credential` | Secret | Keychain | when unlocked | no |
| `.otp` | Secret | Keychain, expires in 5 min | after first unlock | no |
| `.highlySensitive` | Highly Sensitive | encrypted file, passcode required | when unlocked | never |
| `.biometric` | Biometric | Keychain, Face ID / Touch ID | when passcode set | never |

Modifiers compose: `.accessToken.expiring(after: 3600)`, `.sensitive.allowingBackup()`,
`.secret.stored(in: .encryptedFile)`, `.secret.requiringUserAuthentication(.userPresence)`.
A policy that cannot be met throws `securityPolicyViolation`. It never falls back to something weaker.

### Migration, rotation, recovery

```swift
let report = await vault.migrate([
    .userDefaults("authToken", as: String.self, to: "accessToken", namespace: .auth, policy: .accessToken),
    .keychain(service: "com.acme.legacy", account: "refresh", to: "refreshToken", namespace: .auth, policy: .refreshToken),
])                                                   // source deleted only after a verified read-back

try await vault.rotateKeys()                          // crash-safe; re-run completePendingRotations() after a crash
try await vault.purgeUnreadableItems()                // after a restore to a new device (keyUnavailable)
let posture = await vault.securityReport()            // never contains values or key names
```

## Objective-C

```objc
@import SecureVault;

SVVault *vault = SVVault.sharedVault;
[vault setString:token forKey:@"accessToken" namespace:@"auth" policy:SVPolicy.accessToken
      completion:^(NSError *error) { /* main queue */ }];
[vault stringForKey:@"accessToken" namespace:@"auth" completion:^(NSString *value, NSError *error) {
    if (error.code == SVErrorCodeItemNotFound) { /* … */ }
}];

SVPolicy *policy = [SVPolicy.accessToken copy];
policy.expiresAfter = 3600;

[vault databaseNamed:@"medical" policy:SVPolicy.highlySensitive completion:^(SVDatabase *db, NSError *error) {
    [db putRecord:@{@"name": @"Asha", @"age": @41} withID:@"p1" type:@"Patient" completion:nil];
}];
```

Strings, data and numbers use the same encoding as Swift, so values cross languages freely. A record put from
Objective-C with type `@"Patient"` reads in Swift as `Patient` (its `recordType`).

## SwiftUI

```swift
struct AccountView: View {
    @SecureStorage("accessToken", namespace: .auth, policy: .accessToken) var token: String?

    var body: some View {
        Text(token == nil ? "Signed out" : "Signed in")
            .overlay { if $token.isLoading { ProgressView() } }
    }
}

RecordsView()
    .biometricLock(reason: "Unlock your records")    // relocks when the app goes to the background
    .secureVault(vault)                              // defaults to SecureVault.shared
```

## Testing your app

```swift
let vault = SecureVault(configuration: .testing())    // in-memory Keychain, temp directory, fixed capabilities
```

`[SVVault inMemoryVaultForTesting]` does the same for Objective-C. Never ship either: the security report flags the
in-memory Keychain as critical.

## Developing SecureVault

```bash
swift test
```

Runs 69 Swift tests (on macOS, 67 run and the 2 real-Keychain tests skip) covering policy rules R1–R10, envelope tampering, expiry, namespaces, rotation and interrupted rotation,
database, streaming files, migration and concurrency, plus 7 Objective-C XCTests. The real-Keychain tests skip
themselves on macOS and in a hostless iOS Simulator bundle, because neither has a Keychain entitlement; run them
from a host app on the Simulator.

## Security notes

- AES-256-GCM everywhere; every value is bound to its location, so tampering or moving ciphertext fails.
- Device-only keys are wrapped by the Secure Enclave when available; portable keys never are.
- The database encrypts each record and replaces ids and type names with HMACs. The file still reveals record
  counts and sizes (PRD §17.1).
- Expiry uses the device clock, which users can change; servers must enforce token lifetimes.
- Logging is off by default and never records values.
- SecureVault does not protect against a compromised OS, a jailbroken device, or server-side failures (PRD §35).

## Specification

The PRD lives in [`docs/`](docs/) in two formats built from one source, so they never drift:

- [SecureVault_PRD.md](docs/SecureVault_PRD.md): read it on GitHub; changes show up in pull-request diffs.
- [SecureVault_PRD_v1.0.docx](docs/SecureVault_PRD_v1.0.docx): for sharing outside the repo.

To change the spec, edit `docs/tools/build-prd.js` and regenerate both files:

```bash
cd docs/tools && npm install && npm run build
```
