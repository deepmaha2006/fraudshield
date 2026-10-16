package com.fraudshield.companion

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/** Uploads one SMS to the FraudShield server and warns the user if it is a scam. */
class ForwardWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result {
        val sender = inputData.getString(KEY_SENDER) ?: return Result.failure()
        val body = inputData.getString(KEY_BODY) ?: return Result.failure()
        val time = inputData.getLong(KEY_TIME, System.currentTimeMillis())

        return try {
            val verdict = Api.submitSms(applicationContext, sender, body, time)
            val label = verdict.optString("verdict", "legit")
            if (label != "legit") notifyThreat(sender, label, verdict.optInt("risk"), verdict.optString("summary"), verdict.optString("advice"))
            Result.success()
        } catch (e: Api.ApiException) {
            // 4xx = bad token / revoked device: retrying will not help.
            if (e.code in 400..499 && e.code != 429) Result.failure() else Result.retry()
        } catch (e: Exception) {
            if (runAttemptCount < 5) Result.retry() else Result.failure()
        }
    }

    private fun notifyThreat(sender: String, verdict: String, risk: Int, summary: String, advice: String) {
        val ctx = applicationContext
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return

        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Scam warnings", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Warnings for SMS that FraudShield judged suspicious or malicious"
        })
        val title = if (verdict == "malicious") "⚠ Scam SMS from $sender" else "Suspicious SMS from $sender"
        val text = "Risk $risk/100 — $summary"
        val notification = NotificationCompat.Builder(ctx, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(if (advice.isNotEmpty()) "$text\n\n$advice" else text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(ctx).notify((sender + time()).hashCode(), notification)
    }

    private fun time() = System.currentTimeMillis().toString()

    companion object {
        const val KEY_SENDER = "sender"
        const val KEY_BODY = "body"
        const val KEY_TIME = "time"
        const val CHANNEL = "scam_warnings"
    }
}
