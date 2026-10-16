package com.fraudshield.companion

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import kotlin.concurrent.thread

/** One-screen setup: server URL + device token from the FraudShield console, permissions, and a connection test. */
class MainActivity : Activity() {

    private lateinit var server: EditText
    private lateinit var token: EditText
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        server = findViewById(R.id.server)
        token = findViewById(R.id.token)
        status = findViewById(R.id.status)

        server.setText(Api.serverUrl(this))
        token.setText(Api.token(this))

        findViewById<Button>(R.id.save).setOnClickListener {
            if (!Api.isAllowedServer(server.text.toString().trim())) {
                refreshStatus("✗ Use the https:// server URL (http:// is only allowed in debug builds)")
                return@setOnClickListener
            }
            Api.save(this, server.text.toString(), token.text.toString())
            requestPermissionsIfNeeded()
            testConnection()
        }
        findViewById<Button>(R.id.test_sms).setOnClickListener { sendSample() }
        refreshStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    private fun requestPermissionsIfNeeded() {
        val wanted = buildList {
            add(Manifest.permission.RECEIVE_SMS)
            if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.POST_NOTIFICATIONS)
        }.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (wanted.isNotEmpty()) requestPermissions(wanted.toTypedArray(), 1)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        refreshStatus()
    }

    private fun refreshStatus(extra: String? = null) {
        val sms = checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
        val lines = mutableListOf(
            if (Api.isConfigured(this)) "✓ Paired with ${Api.serverUrl(this)}" else "✗ Not paired — enter server URL and device token",
            if (sms) "✓ SMS permission granted — incoming SMS are scanned in real time" else "✗ SMS permission missing",
        )
        if (extra != null) lines += extra
        status.text = lines.joinToString("\n")
    }

    private fun testConnection() {
        refreshStatus("… testing connection")
        thread {
            val msg = runCatching { Api.ping(this) }
                .fold({ "✓ Server reachable — device \"${it.optString("device")}\" is live in the console" }, { "✗ ${it.message}" })
            runOnUiThread { refreshStatus(msg) }
        }
    }

    private fun sendSample() {
        if (!Api.isConfigured(this)) return refreshStatus("✗ Save the pairing first")
        refreshStatus("… sending a test message")
        thread {
            val msg = runCatching {
                Api.submitSms(this, "FS-TEST", "TEST: Your account will be blocked today. Verify KYC at http://example.com/verify", System.currentTimeMillis())
            }.fold({ "✓ Test analysed: ${it.optString("verdict")} (${it.optInt("risk")}/100) — check the console feed" }, { "✗ ${it.message}" })
            runOnUiThread { refreshStatus(msg) }
        }
    }
}
