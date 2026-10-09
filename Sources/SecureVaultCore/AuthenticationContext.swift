//
//  AuthenticationContext.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import LocalAuthentication

/// An authentication session that can be reused across several reads so the user is prompted once.
/// Create one with `BiometricAuthenticator.authenticate(reason:reuseDuration:)`, or directly to set the prompt text.
public final class AuthenticationContext: @unchecked Sendable {
    // LAContext is thread-safe for the calls SecureVault makes (passing it to SecItem).
    public let laContext: LAContext

    public init(reason: String, reuseDuration: TimeInterval = 0) {
        let context = LAContext()
        context.localizedReason = reason
        #if os(iOS) || os(macOS)
        context.touchIDAuthenticationAllowableReuseDuration = min(reuseDuration, LATouchIDAuthenticationMaximumAllowableReuseDuration)
        #endif
        self.laContext = context
    }

    public init(context: LAContext) {
        self.laContext = context
    }

    /// Ends the session; later reads prompt again.
    public func invalidate() { laContext.invalidate() }
}
