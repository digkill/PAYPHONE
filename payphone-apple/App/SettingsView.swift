import SwiftUI
import UniformTypeIdentifiers

// Minimal settings form: server address, PSK, subscription token import,
// optional pinned dev cert. Deliberately plain — this is v1 wiring, not
// a polished settings screen.
struct SettingsView: View {
    @Binding var settings: PayphoneSettings
    @Environment(\.dismiss) private var dismiss

    @State private var tokenImportError: String?
    @State private var certImportError: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("host:port, e.g. 201.51.24.102:443", text: $settings.server)
                        .plainTextEntry()

                    TextField("SNI override (optional)", text: $settings.serverName)
                        .plainTextEntry()
                }

                Section("Wire obfuscation") {
                    SecureField("PAYPHONE_OBFS_PSK", text: $settings.psk)
                }

                Section("Subscription token") {
                    if settings.tokenBytes != nil {
                        Label("Token loaded (\(settings.tokenBytes?.count ?? 0) bytes)", systemImage: "checkmark.circle")
                            .foregroundStyle(.green)
                    }

                    importButton(title: "Import subscription.token", error: $tokenImportError) { data in
                        settings.tokenBytes = [UInt8](data)
                    }
                }

                Section("Pinned certificate (self-signed dev servers only)") {
                    if settings.pinnedCertBytes != nil {
                        Label("Pin loaded", systemImage: "checkmark.circle")
                            .foregroundStyle(.green)
                    }

                    importButton(title: "Import payphone-cert.der", error: $certImportError) { data in
                        settings.pinnedCertBytes = [UInt8](data)
                    }

                    Text("Leave empty for servers with a real domain/Let's Encrypt cert — system trust is used automatically.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func importButton(
        title: String,
        error: Binding<String?>,
        onImport: @escaping (Data) -> Void
    ) -> some View {
        FileImportButton(title: title) { result in
            switch result {
            case .success(let data):
                onImport(data)
                error.wrappedValue = nil
            case .failure(let importError):
                error.wrappedValue = String(describing: importError)
            }
        }
    }
}

/// Thin wrapper around `.fileImporter` that reads the picked file's bytes
/// directly, since callers here just want raw `Data`.
private struct FileImportButton: View {
    let title: String
    let onResult: (Result<Data, Error>) -> Void

    @State private var isPresented = false

    var body: some View {
        Button(title) { isPresented = true }
            .fileImporter(isPresented: $isPresented, allowedContentTypes: [.data]) { result in
                switch result {
                case .success(let url):
                    let accessed = url.startAccessingSecurityScopedResource()
                    defer { if accessed { url.stopAccessingSecurityScopedResource() } }

                    do {
                        onResult(.success(try Data(contentsOf: url)))
                    } catch {
                        onResult(.failure(error))
                    }
                case .failure(let error):
                    onResult(.failure(error))
                }
            }
    }
}

#Preview {
    SettingsView(settings: .constant(PayphoneSettings()))
}

private extension View {
    /// No autocorrect, no autocapitalize — for host addresses and SNI
    /// names. `textInputAutocapitalization` doesn't exist on macOS
    /// (AppKit text fields don't autocapitalize in the first place), so
    /// that half only applies on iOS.
    @ViewBuilder
    func plainTextEntry() -> some View {
        #if os(iOS)
        self.textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        self.autocorrectionDisabled()
        #endif
    }
}
