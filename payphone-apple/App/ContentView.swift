import SwiftUI
import NetworkExtension

struct ContentView: View {
    @StateObject private var vpn = VpnManager()
    @State private var settings = PayphoneSettings()
    @State private var errorMessage: String?
    @State private var showingSettings = false

    private var isConnected: Bool { vpn.status == .connected }
    private var isBusy: Bool { vpn.status == .connecting || vpn.status == .disconnecting }

    var body: some View {
        NavigationStack {
            ZStack {
                RainView(intensity: isConnected ? 0.6 : 0.15)
                    .ignoresSafeArea()

                VStack(spacing: 24) {
                    Spacer()

                    Text("PAYPHONE")
                        .font(.system(size: 34, weight: .bold, design: .monospaced))
                        .foregroundStyle(.green)

                    Text(vpn.statusLine)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.green.opacity(0.85))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)

                    if !vpn.assignedIP.isEmpty {
                        Text(vpn.assignedIP)
                            .font(.system(.callout, design: .monospaced))
                            .foregroundStyle(.green.opacity(0.6))
                    }

                    Spacer()

                    Button(action: toggleConnection) {
                        Text(isConnected ? "Unplug" : "Jack in")
                            .font(.system(.headline, design: .monospaced))
                            .frame(maxWidth: .infinity)
                            .padding()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(isConnected ? .red : .green)
                    .disabled(isBusy || settings.server.isEmpty)
                    .padding(.horizontal, 32)

                    if let errorMessage {
                        Text(errorMessage)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .padding(.horizontal)
                    }

                    Spacer().frame(height: 24)
                }
            }
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .tint(.green)
                }
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView(settings: $settings)
            }
        }
        .task {
            _ = try? await vpn.loadOrCreateManager()
        }
    }

    private func toggleConnection() {
        errorMessage = nil

        if isConnected {
            vpn.disconnect()
            return
        }

        Task {
            do {
                try await vpn.connect(settings: settings)
            } catch {
                errorMessage = String(describing: error)
            }
        }
    }
}

#Preview {
    ContentView()
}
