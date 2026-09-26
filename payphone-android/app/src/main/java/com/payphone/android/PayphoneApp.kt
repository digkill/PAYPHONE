package com.payphone.android

import android.app.Application
import com.payphone.android.data.SettingsRepository

class PayphoneApp : Application() {
    lateinit var settingsRepository: SettingsRepository
        private set

    override fun onCreate() {
        super.onCreate()
        settingsRepository = SettingsRepository(this)
    }
}
