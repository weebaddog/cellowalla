package com.cellowalla.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/** Every 15 minutes: asks the box for new Pings and shows them as notifications. */
class PingsWorker(context: Context, params: WorkerParameters) : Worker(context, params) {
    override fun doWork(): Result {
        val box = Box(applicationContext)
        if (box.url.isEmpty()) return Result.success()
        runCatching { check(applicationContext, box) }
        return Result.success()
    }

    companion object {
        private const val CHANNEL = "pings"
        private val TITLES = mapOf("newDevice" to "New device", "malware" to "Malware blocked", "tunnel" to "Tunnel", "bedtime" to "Bedtime", "system" to "Cellowalla")

        fun schedule(context: Context) {
            val req = PeriodicWorkRequestBuilder<PingsWorker>(15, TimeUnit.MINUTES).build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork("pings", ExistingPeriodicWorkPolicy.KEEP, req)
        }

        /** Shows Pings the phone hasn't shown yet. Also used when the app opens. */
        fun check(context: Context, box: Box) {
            val pings = box.call("GET", "/api/pings").getJSONArray("pings")
            val seen = box.seen
            val ids = mutableSetOf<String>()
            val fresh = mutableListOf<Triple<String, String, String>>()
            for (i in 0 until pings.length()) {
                val p = pings.getJSONObject(i)
                val id = p.getString("id")
                ids += id
                if (!p.optBoolean("read") && id !in seen) fresh += Triple(id, p.optString("kind"), p.optString("text"))
            }
            box.seen = ids
            if (seen.isEmpty()) return // first look: don't replay old ones
            if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "Pings", NotificationManager.IMPORTANCE_DEFAULT).apply { description = "Alerts from your Cellowalla box" })
            val open = PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java).putExtra("tab", "pings"), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            for ((id, kind, text) in fresh.take(5)) {
                val n = android.app.Notification.Builder(context, CHANNEL)
                    .setSmallIcon(R.drawable.ic_notify)
                    .setColor(0xFF0F7A5A.toInt())
                    .setContentTitle(TITLES[kind] ?: "Cellowalla")
                    .setContentText(text)
                    .setStyle(android.app.Notification.BigTextStyle().bigText(text))
                    .setContentIntent(open)
                    .setAutoCancel(true)
                    .build()
                nm.notify(id.hashCode(), n)
            }
        }
    }
}
