package com.payphone.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.payphone.android.data.PayphoneSettings
import com.payphone.android.transport.TransportKind
import com.payphone.android.ui.components.MatrixRain
import com.payphone.android.ui.components.MatrixTagline
import com.payphone.android.ui.theme.MatrixBlack
import com.payphone.android.ui.theme.MatrixGreen
import com.payphone.android.ui.theme.MatrixGreenBright
import com.payphone.android.ui.theme.MatrixGreenDim
import com.payphone.android.vpn.VpnUiState
import java.util.Locale

@Composable
fun PayphoneScreen(
    settings: PayphoneSettings,
    vpnState: VpnUiState,
    onSettingsChange: (PayphoneSettings) -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onPrepareVpn: () -> Unit,
) {
    val connected = vpnState.connected
    Box(Modifier.fillMaxSize()) {
        MatrixRain(
            modifier = Modifier.fillMaxSize(),
            busy = connected,
        )
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Spacer(Modifier.height(24.dp))
            Text(
                text = "☎ PAYPHONE",
                style = androidx.compose.material3.MaterialTheme.typography.titleLarge,
                color = MatrixGreenBright,
                textAlign = TextAlign.Center,
            )
            MatrixTagline("Follow the white rabbit.")
            MatrixTagline("Wake up, Neo. The Matrix has you…")

            if (connected) {
                TunnelStatus(vpnState, onDisconnect)
            } else {
                ConnectForm(settings, onSettingsChange, onPrepareVpn, onConnect)
            }
        }
    }
}

@Composable
private fun TunnelStatus(state: VpnUiState, onDisconnect: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("▸ ${state.statusLine}", color = MatrixGreen)
        if (state.assignedIp.isNotBlank()) {
            Text("VPN ${state.assignedIp}", color = MatrixGreenBright)
        }
        Text(
            text = "↓ ${formatBytes(state.rxBytes)}  ↑ ${formatBytes(state.txBytes)}",
            color = MatrixGreenDim,
        )
        MatrixTagline("There is no spoon — only packets.")
        Button(
            onClick = onDisconnect,
            colors = ButtonDefaults.buttonColors(
                containerColor = MatrixBlack,
                contentColor = MatrixGreen,
            ),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Unplug")
        }
    }
}

@Composable
private fun ConnectForm(
    settings: PayphoneSettings,
    onChange: (PayphoneSettings) -> Unit,
    onPrepareVpn: () -> Unit,
    onConnect: () -> Unit,
) {
    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedTextColor = MatrixGreen,
        unfocusedTextColor = MatrixGreenDim,
        focusedBorderColor = MatrixGreen,
        unfocusedBorderColor = MatrixGreenDim,
        cursorColor = MatrixGreenBright,
        focusedLabelColor = MatrixGreen,
        unfocusedLabelColor = MatrixGreenDim,
    )

    OutlinedTextField(
        value = settings.server,
        onValueChange = { onChange(settings.copy(server = it)) },
        label = { Text("Server") },
        placeholder = { Text("vpn.example.com:443") },
        modifier = Modifier.fillMaxWidth(),
        colors = fieldColors,
        singleLine = true,
    )

    RowChips(
        selected = settings.transport,
        onSelect = { onChange(settings.copy(transport = it)) },
    )

    OutlinedTextField(
        value = settings.psk,
        onValueChange = { onChange(settings.copy(psk = it)) },
        label = { Text("Obfuscation PSK") },
        modifier = Modifier.fillMaxWidth(),
        colors = fieldColors,
        singleLine = true,
    )

    OutlinedTextField(
        value = settings.serverName,
        onValueChange = { onChange(settings.copy(serverName = it)) },
        label = { Text("TLS SNI (optional)") },
        modifier = Modifier.fillMaxWidth(),
        colors = fieldColors,
        singleLine = true,
    )

    OutlinedTextField(
        value = settings.tokenBase64,
        onValueChange = { onChange(settings.copy(tokenBase64 = it)) },
        label = { Text("Token (Base64, 135 bytes)") },
        modifier = Modifier.fillMaxWidth(),
        colors = fieldColors,
        minLines = 2,
    )

    OutlinedTextField(
        value = settings.pinnedCertBase64,
        onValueChange = { onChange(settings.copy(pinnedCertBase64 = it)) },
        label = { Text("Pinned cert DER (Base64, optional)") },
        modifier = Modifier.fillMaxWidth(),
        colors = fieldColors,
        minLines = 2,
    )

    MatrixTagline("What's up, dude? — handshake uses your subscription token.")

    Button(
        onClick = {
            onPrepareVpn()
            onConnect()
        },
        colors = ButtonDefaults.buttonColors(
            containerColor = Color(0xFF001A00),
            contentColor = MatrixGreenBright,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("☎ Jack in")
    }
}

@Composable
private fun RowChips(selected: TransportKind, onSelect: (TransportKind) -> Unit) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        MatrixTagline("Transport")
        androidx.compose.foundation.layout.Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = selected == TransportKind.Tls,
                onClick = { onSelect(TransportKind.Tls) },
                label = { Text("TLS :40443") },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = Color(0xFF002200),
                    selectedLabelColor = MatrixGreenBright,
                    containerColor = MatrixBlack,
                    labelColor = MatrixGreenDim,
                ),
            )
            FilterChip(
                selected = selected == TransportKind.Quic,
                onClick = { onSelect(TransportKind.Quic) },
                label = { Text("QUIC :40404") },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = Color(0xFF002200),
                    selectedLabelColor = MatrixGreenBright,
                    containerColor = MatrixBlack,
                    labelColor = MatrixGreenDim,
                ),
            )
        }
        if (selected == TransportKind.Quic) {
            MatrixTagline("QUIC needs native/ (Rust). Use TLS until built.")
        }
    }
}

private fun formatBytes(value: Long): String {
    if (value < 1024) return "$value B"
    val kb = value / 1024.0
    if (kb < 1024) return String.format(Locale.US, "%.1f KiB", kb)
    return String.format(Locale.US, "%.1f MiB", kb / 1024.0)
}
