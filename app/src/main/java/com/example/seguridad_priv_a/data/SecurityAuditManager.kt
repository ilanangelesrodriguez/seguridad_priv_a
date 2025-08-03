package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.collections.HashMap

class SecurityAuditManager(private val context: Context) {

    private lateinit var auditPrefs: SharedPreferences
    private val accessAttempts = HashMap<String, MutableList<Long>>()
    private val suspiciousActivities = mutableListOf<SuspiciousActivity>()

    companion object {
        private const val MAX_ATTEMPTS_PER_MINUTE = 10
        private const val RATE_LIMIT_WINDOW = 60 * 1000L
        private const val SUSPICIOUS_THRESHOLD = 5
        private const val HMAC_ALGORITHM = "HmacSHA256"
    }

    data class SuspiciousActivity(
        val timestamp: Long,
        val type: String,
        val description: String,
        val severity: String,
        val metadata: Map<String, String>
    )

    data class SecurityAlert(
        val id: String,
        val timestamp: Long,
        val type: String,
        val message: String,
        val severity: AlertSeverity,
        val actionRequired: Boolean
    )

    enum class AlertSeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    fun initialize() {
        auditPrefs = context.getSharedPreferences("security_audit", Context.MODE_PRIVATE)
        loadSuspiciousActivities()
    }

    /**
     * Detecta intentos de acceso sospechosos
     */
    fun detectSuspiciousAccess(operation: String, userId: String = "anonymous"): Boolean {
        val currentTime = System.currentTimeMillis()
        val key = "$operation:$userId"

        // Obtener intentos previos
        val attempts = accessAttempts.getOrPut(key) { mutableListOf() }

        // Limpiar intentos antiguos (fuera de la ventana de tiempo)
        attempts.removeAll { currentTime - it > RATE_LIMIT_WINDOW }

        // Agregar intento actual
        attempts.add(currentTime)

        // Verificar si excede el límite
        if (attempts.size > MAX_ATTEMPTS_PER_MINUTE) {
            recordSuspiciousActivity(
                type = "RATE_LIMIT_EXCEEDED",
                description = "Demasiados intentos de $operation en corto tiempo",
                severity = "HIGH",
                metadata = mapOf(
                    "operation" to operation,
                    "user_id" to userId,
                    "attempts_count" to attempts.size.toString(),
                    "time_window" to "${RATE_LIMIT_WINDOW / 1000}s"
                )
            )

            generateAlert(
                type = "RATE_LIMITING",
                message = "Actividad sospechosa detectada: múltiples intentos de $operation",
                severity = AlertSeverity.HIGH,
                actionRequired = true
            )

            return true
        }

        return false
    }

    /**
     * Implementa rate limiting para operaciones sensibles
     */
    fun isRateLimited(operation: String, userId: String = "anonymous"): Boolean {
        return detectSuspiciousAccess(operation, userId)
    }

    /**
     * Genera alertas cuando se detecten patrones anómalos
     */
    fun analyzePatterns() {
        val recentActivities = suspiciousActivities.filter {
            System.currentTimeMillis() - it.timestamp < 24 * 60 * 60 * 1000 // Últimas 24 horas
        }

        // Patrón 1: Múltiples tipos de actividades sospechosas
        val uniqueTypes = recentActivities.map { it.type }.distinct()
        if (uniqueTypes.size >= 3) {
            generateAlert(
                type = "PATTERN_MULTIPLE_THREATS",
                message = "Detectados múltiples tipos de amenazas en las últimas 24 horas",
                severity = AlertSeverity.CRITICAL,
                actionRequired = true
            )
        }

        // Patrón 2: Actividad fuera de horario normal
        val nightActivities = recentActivities.filter { activity ->
            val hour = Calendar.getInstance().apply { timeInMillis = activity.timestamp }.get(Calendar.HOUR_OF_DAY)
            hour < 6 || hour > 22 // Entre 22:00 y 06:00
        }

        if (nightActivities.size > 5) {
            generateAlert(
                type = "PATTERN_UNUSUAL_HOURS",
                message = "Actividad inusual detectada fuera del horario normal",
                severity = AlertSeverity.MEDIUM,
                actionRequired = false
            )
        }

        // Patrón 3: Escalada de severidad
        val highSeverityCount = recentActivities.count { it.severity == "HIGH" }
        if (highSeverityCount > 3) {
            generateAlert(
                type = "PATTERN_ESCALATION",
                message = "Escalada de amenazas de alta severidad detectada",
                severity = AlertSeverity.CRITICAL,
                actionRequired = true
            )
        }
    }

    /**
     * Exporta logs en formato JSON firmado digitalmente
     */
    fun exportSignedLogs(): String {
        val exportData = JSONObject()
        val timestamp = System.currentTimeMillis()

        // Metadatos del export
        exportData.put("export_timestamp", timestamp)
        exportData.put("export_id", UUID.randomUUID().toString())
        exportData.put("device_id", getDeviceId())
        exportData.put("app_version", getAppVersion())

        // Actividades sospechosas
        val activitiesArray = JSONArray()
        suspiciousActivities.forEach { activity ->
            val activityJson = JSONObject().apply {
                put("timestamp", activity.timestamp)
                put("type", activity.type)
                put("description", activity.description)
                put("severity", activity.severity)
                put("metadata", JSONObject(activity.metadata))
            }
            activitiesArray.put(activityJson)
        }
        exportData.put("suspicious_activities", activitiesArray)

        // Estadísticas de acceso
        val statsJson = JSONObject()
        accessAttempts.forEach { (key, attempts) ->
            statsJson.put(key, attempts.size)
        }
        exportData.put("access_statistics", statsJson)

        // Generar firma digital
        val dataString = exportData.toString()
        val signature = generateDigitalSignature(dataString)

        // Crear objeto final con firma
        val signedExport = JSONObject()
        signedExport.put("data", exportData)
        signedExport.put("signature", signature)
        signedExport.put("signature_algorithm", "HMAC-SHA256")

        return signedExport.toString(2) // Pretty print con indentación
    }

    fun verifySignedLogs(signedLogsJson: String): Boolean {
        return try {
            val signedExport = JSONObject(signedLogsJson)
            val data = signedExport.getJSONObject("data")
            val signature = signedExport.getString("signature")

            val expectedSignature = generateDigitalSignature(data.toString())
            MessageDigest.isEqual(signature.toByteArray(), expectedSignature.toByteArray())

        } catch (e: Exception) {
            false
        }
    }

    private fun recordSuspiciousActivity(
        type: String,
        description: String,
        severity: String,
        metadata: Map<String, String>
    ) {
        val activity = SuspiciousActivity(
            timestamp = System.currentTimeMillis(),
            type = type,
            description = description,
            severity = severity,
            metadata = metadata
        )

        suspiciousActivities.add(activity)
        saveSuspiciousActivities()

        // Auto-análisis de patrones
        analyzePatterns()
    }

    private fun generateAlert(
        type: String,
        message: String,
        severity: AlertSeverity,
        actionRequired: Boolean
    ) {
        val alert = SecurityAlert(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            type = type,
            message = message,
            severity = severity,
            actionRequired = actionRequired
        )

        saveAlert(alert)

        // Log del alert
        logSecurityEvent("ALERT_GENERATED", "Tipo: $type, Severidad: $severity, Mensaje: $message")
    }

    private fun generateDigitalSignature(data: String): String {
        val secretKey = getOrCreateSigningKey()
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        val keySpec = SecretKeySpec(secretKey.toByteArray(), HMAC_ALGORITHM)
        mac.init(keySpec)
        val signature = mac.doFinal(data.toByteArray())
        return Base64.encodeToString(signature, Base64.NO_WRAP)
    }

    private fun getOrCreateSigningKey(): String {
        val existingKey = auditPrefs.getString("signing_key", null)
        if (existingKey != null) {
            return existingKey
        }

        // Generar nueva clave de firma
        val keyBytes = ByteArray(32)
        SecureRandom().nextBytes(keyBytes)
        val newKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP)

        auditPrefs.edit().putString("signing_key", newKey).apply()
        return newKey
    }

    private fun saveSuspiciousActivities() {
        val activitiesJson = JSONArray()
        suspiciousActivities.takeLast(100).forEach { activity -> // Mantener solo las últimas 100
            val activityJson = JSONObject().apply {
                put("timestamp", activity.timestamp)
                put("type", activity.type)
                put("description", activity.description)
                put("severity", activity.severity)
                put("metadata", JSONObject(activity.metadata))
            }
            activitiesJson.put(activityJson)
        }

        auditPrefs.edit().putString("suspicious_activities", activitiesJson.toString()).apply()
    }

    private fun loadSuspiciousActivities() {
        val activitiesString = auditPrefs.getString("suspicious_activities", null) ?: return

        try {
            val activitiesJson = JSONArray(activitiesString)
            suspiciousActivities.clear()

            for (i in 0 until activitiesJson.length()) {
                val activityJson = activitiesJson.getJSONObject(i)
                val metadataJson = activityJson.getJSONObject("metadata")
                val metadata = HashMap<String, String>()

                metadataJson.keys().forEach { key ->
                    metadata[key] = metadataJson.getString(key)
                }

                val activity = SuspiciousActivity(
                    timestamp = activityJson.getLong("timestamp"),
                    type = activityJson.getString("type"),
                    description = activityJson.getString("description"),
                    severity = activityJson.getString("severity"),
                    metadata = metadata
                )

                suspiciousActivities.add(activity)
            }
        } catch (e: Exception) {
            logSecurityEvent("LOAD_ERROR", "Error cargando actividades sospechosas: ${e.message}")
        }
    }

    private fun saveAlert(alert: SecurityAlert) {
        val alertsString = auditPrefs.getString("security_alerts", "[]")
        val alertsArray = JSONArray(alertsString)

        val alertJson = JSONObject().apply {
            put("id", alert.id)
            put("timestamp", alert.timestamp)
            put("type", alert.type)
            put("message", alert.message)
            put("severity", alert.severity.name)
            put("action_required", alert.actionRequired)
        }

        alertsArray.put(alertJson)

        // Mantener solo las últimas 50 alertas
        if (alertsArray.length() > 50) {
            val trimmedArray = JSONArray()
            for (i in (alertsArray.length() - 50) until alertsArray.length()) {
                trimmedArray.put(alertsArray.get(i))
            }
            auditPrefs.edit().putString("security_alerts", trimmedArray.toString()).apply()
        } else {
            auditPrefs.edit().putString("security_alerts", alertsArray.toString()).apply()
        }
    }

    private fun getDeviceId(): String {
        return android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        ) ?: "unknown_device"
    }

    private fun getAppVersion(): String {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            packageInfo.versionName ?: "unknown"
        } catch (e: Exception) {
            "unknown"
        }
    }

    private fun logSecurityEvent(category: String, action: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(Date())
        val logEntry = "$timestamp - AUDIT_$category: $action"

        val existingLogs = auditPrefs.getString("audit_logs", "") ?: ""
        val newLogs = if (existingLogs.isEmpty()) {
            logEntry
        } else {
            "$existingLogs\n$logEntry"
        }

        auditPrefs.edit().putString("audit_logs", newLogs).apply()
    }

    // Métodos públicos para obtener información
    fun getSuspiciousActivitiesCount(): Int = suspiciousActivities.size

    fun getRecentAlerts(): List<SecurityAlert> {
        val alertsString = auditPrefs.getString("security_alerts", "[]")
        val alerts = mutableListOf<SecurityAlert>()

        try {
            val alertsArray = JSONArray(alertsString)
            for (i in 0 until alertsArray.length()) {
                val alertJson = alertsArray.getJSONObject(i)
                val alert = SecurityAlert(
                    id = alertJson.getString("id"),
                    timestamp = alertJson.getLong("timestamp"),
                    type = alertJson.getString("type"),
                    message = alertJson.getString("message"),
                    severity = AlertSeverity.valueOf(alertJson.getString("severity")),
                    actionRequired = alertJson.getBoolean("action_required")
                )
                alerts.add(alert)
            }
        } catch (e: Exception) {
            logSecurityEvent("ALERT_LOAD_ERROR", "Error cargando alertas: ${e.message}")
        }

        return alerts.sortedByDescending { it.timestamp }
    }
}
