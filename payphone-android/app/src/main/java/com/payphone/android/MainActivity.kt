package com.payphone.android

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import com.payphone.android.data.PayphoneSettings
import com.payphone.android.ui.screens.PayphoneScreen
import com.payphone.android.ui.theme.MatrixTheme
import com.payphone.android.vpn.PayphoneVpnConfig
import com.payphone.android.vpn.PayphoneVpnService
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class MainActivity : ComponentActivity() {
    private val app by lazy { application as PayphoneApp }

    private var pendingConnect = false

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        if (it.resultCode == RESULT_OK && pendingConnect) {
            pendingConnect = false
            startVpn()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MatrixTheme {
                val settings by app.settingsRepository.settings.collectAsState(
                    initial = PayphoneSettings(),
                )
                val vpnState by PayphoneVpnService.state.collectAsState()
                var draft by remember(settings) { mutableStateOf(settings) }

                PayphoneScreen(
                    settings = draft,
                    vpnState = vpnState,
                    onSettingsChange = { draft = it },
                    onConnect = {
                        lifecycleScope.launch {
                            app.settingsRepository.update { draft }
                            pendingConnect = true
                            val intent = VpnService.prepare(this@MainActivity)
                            if (intent != null) {
                                vpnPermission.launch(intent)
                            } else {
                                pendingConnect = false
                                startVpn()
                            }
                        }
                    },
                    onDisconnect = {
                        PayphoneVpnService.disconnectFromUi(this)
                    },
                    onPrepareVpn = {},
                )
            }
        }
    }

    private fun startVpn() {
        val settings = runBlocking { app.settingsRepository.settings.first() }
        val config = PayphoneVpnConfig.from(settings)
        startForegroundService(
            Intent(this, PayphoneVpnService::class.java).apply {
                action = PayphoneVpnService.ACTION_CONNECT
                putExtra(PayphoneVpnService.EXTRA_SETTINGS, config)
            },
        )
    }
}
