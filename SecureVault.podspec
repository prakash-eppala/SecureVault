Pod::Spec.new do |s|
  s.name             = 'SecureVault'
  s.version          = '1.0.2'
  s.summary          = 'Policy-driven secure storage for iOS: Keychain, encrypted files and records, biometrics.'
  s.description      = <<-DESC
    SecureVault stores anything from preferences to medical records behind one API. Describe how sensitive the
    data is and it picks the Keychain, encrypted files or an encrypted record database, binds keys to the right
    protection class, wraps device-only keys with the Secure Enclave, and fails closed when the device cannot
    provide the protection asked for. Works from Swift, Objective-C and SwiftUI.
  DESC
  s.homepage         = 'https://github.com/prakash-eppala/SecureVault'
  s.license          = { :type => 'Proprietary', :text => 'Copyright © 2026 Prakash Eppala. All rights reserved.' }
  s.author           = { 'Prakash Eppala' => 'prakash.eppala@gmail.com' }
  s.source           = { :git => 'https://github.com/prakash-eppala/SecureVault.git', :tag => s.version.to_s }

  s.ios.deployment_target = '15.0'
  s.osx.deployment_target = '12.0'
  s.swift_versions   = ['6.0']

  # One module named SecureVault, the same import as the Swift package: `import SecureVault` / `@import SecureVault;`.
  s.module_name      = 'SecureVault'
  s.source_files     = 'Sources/**/*.swift'
  s.resource_bundles = { 'SecureVault_Privacy' => ['Sources/SecureVault/PrivacyInfo.xcprivacy'] }
  s.frameworks       = 'Security', 'LocalAuthentication', 'CryptoKit', 'SwiftUI'
  s.libraries        = 'sqlite3'
  # The sources use Swift's `package` access level, which needs a package name when built as a pod.
  s.pod_target_xcconfig = { 'OTHER_SWIFT_FLAGS' => '$(inherited) -package-name SecureVault' }
end
