package com.fraudshield.companion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import androidx.work.Constraints
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf

/**
 * Fires for every incoming SMS. Multipart messages arrive as several PDUs and are
 * joined per sender, then handed to WorkManager so the upload survives the
 * receiver's short execution window and waits for connectivity if needed.
 */
class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        if (!Api.isConfigured(context)) return

        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        parts.groupBy { it.displayOriginatingAddress ?: "unknown" }.forEach { (sender, messages) ->
            val body = messages.joinToString("") { it.displayMessageBody ?: "" }
            if (body.isBlank()) return@forEach

            val work = OneTimeWorkRequestBuilder<ForwardWorker>()
                .setInputData(workDataOf(
                    ForwardWorker.KEY_SENDER to sender,
                    ForwardWorker.KEY_BODY to body,
                    ForwardWorker.KEY_TIME to (messages.first().timestampMillis),
                ))
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueue(work)
        }
    }
}
