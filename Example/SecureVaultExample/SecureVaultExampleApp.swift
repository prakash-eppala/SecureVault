//
//  SecureVaultExampleApp.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

@main
struct SecureVaultExampleApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .secureVault(.shared)
        }
    }
}
