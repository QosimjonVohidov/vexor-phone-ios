import SwiftUI
import UIKit

struct ContentView: View {
    @State private var log = "Ready."
    @State private var report = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("VEXOR Phone")
                    .font(.largeTitle)
                    .bold()
                Text("Secure Enclave test build")
                    .foregroundColor(.secondary)

                Button("1. Create biometric key") { createKey() }
                    .buttonStyle(.borderedProminent)

                Button("2. Sign a test message (Face ID / Touch ID)") { signTest() }
                    .buttonStyle(.borderedProminent)

                Button("3. Copy report") { UIPasteboard.general.string = report }
                    .buttonStyle(.bordered)
                    .disabled(report.isEmpty)

                Button("4. Delete key", role: .destructive) { deleteKey() }
                    .buttonStyle(.bordered)

                Text("Status")
                    .font(.headline)
                Text(log)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)

                if !report.isEmpty {
                    Text("Report")
                        .font(.headline)
                    Text(report)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            .padding()
        }
    }

    private func createKey() {
        do {
            if KeyManager.keyExists() {
                log = "A key already exists. Delete it first (button 4)."
                return
            }
            let key = try KeyManager.createKey()
            let pub = KeyManager.publicKeyBase64(of: key) ?? "(export failed)"
            log = "Key created inside the Secure Enclave.\nPublic key:\n\(pub)"
        } catch {
            log = "Error: \(error)"
        }
    }

    private func signTest() {
        let text = "VEXOR-TEST|\(UUID().uuidString)"
        let message = Data(text.utf8)
        log = "Waiting for Face ID / Touch ID..."

        DispatchQueue.global().async {
            do {
                let result = try KeyManager.sign(
                    message: message,
                    reason: "Confirm it's you to test VEXOR Phone")
                let text2 = "PUB=\(result.publicKey)\nMSG=\(text)\nSIG=\(result.signature.base64EncodedString())"
                DispatchQueue.main.async {
                    report = text2
                    log = "Signed OK (\(result.signature.count) bytes). Tap 'Copy report'."
                }
            } catch {
                DispatchQueue.main.async {
                    log = "Error: \(error)"
                }
            }
        }
    }

    private func deleteKey() {
        let ok = KeyManager.deleteKey()
        report = ""
        log = ok ? "Key deleted." : "Could not delete the key."
    }
}
