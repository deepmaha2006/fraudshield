package com.fraudshield.companion

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Stored pairing settings plus the two HTTP calls the app makes. */
object Api {
    private const val PREFS = "fraudshield"

    fun serverUrl(ctx: Context): String =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("server", "")!!.trimEnd('/')

    fun token(ctx: Context): String =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("token", "")!!

    /** Release builds only talk HTTPS (also enforced by network_security_config). */
    fun isAllowedServer(server: String): Boolean =
        server.startsWith("https://") || (BuildConfig.DEBUG && server.startsWith("http://"))

    fun save(ctx: Context, server: String, token: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("server", server.trim().trimEnd('/'))
            .putString("token", token.trim())
            .apply()
    }

    fun isConfigured(ctx: Context) = serverUrl(ctx).isNotEmpty() && token(ctx).isNotEmpty()

    /** Sends one SMS for analysis. Returns the server's JSON verdict. Blocking — call off the main thread. */
    fun submitSms(ctx: Context, sender: String, body: String, receivedAt: Long): JSONObject {
        val payload = JSONObject()
            .put("sender", sender)
            .put("body", body)
            .put("receivedAt", java.time.Instant.ofEpochMilli(receivedAt).toString())
        return request(ctx, "POST", "/api/ingest/sms", payload.toString())
    }

    fun ping(ctx: Context): JSONObject = request(ctx, "GET", "/api/ingest/ping", null)

    private fun request(ctx: Context, method: String, path: String, body: String?): JSONObject {
        val conn = URL(serverUrl(ctx) + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 10_000
            conn.readTimeout = 60_000 // the server probes every link live before answering
            conn.setRequestProperty("Authorization", "Device ${token(ctx)}")
            conn.setRequestProperty("Accept", "application/json")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() } ?: "{}"
            val json = runCatching { JSONObject(text) }.getOrElse { JSONObject() }
            if (code !in 200..299) throw ApiException(code, json.optString("message", "HTTP $code"))
            return json
        } finally {
            conn.disconnect()
        }
    }

    class ApiException(val code: Int, message: String) : Exception(message)
}
