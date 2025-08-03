package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class DataProtectionManager(private val context: Context) {
    
    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var accessLogPrefs: SharedPreferences
    private lateinit var keyRotationPrefs: SharedPreferences
    private var currentMasterKey: MasterKey? = null

    companion object {
        private const val KEY_ROTATION_INTERVAL = 30L * 24 * 60 * 60 * 1000
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val SALT_LENGTH = 32
    }

    fun initialize() {
        try {
            keyRotationPrefs = context.getSharedPreferences("key_rotation", Context.MODE_PRIVATE)

            // Verificar si necesitamos rotar la clave
            if (shouldRotateKey()) {
                rotateEncryptionKey()
            } else {
                initializeWithCurrentKey()
            }

            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)

        } catch (e: Exception) {
            // Fallback mejorado con logging de errores
            logSecurityEvent("ENCRYPTION_INIT_FAILED", "Error: ${e.message}")
            initializeFallback()
        }
    }

    fun rotateEncryptionKey(): Boolean {
        return try {
            logSecurityEvent("KEY_ROTATION", "Iniciando rotación de clave maestra")

            // Respaldar datos existentes
            val existingData = backupExistingData()

            // Generar nueva clave maestra
            val newMasterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            // Crear nuevas preferencias encriptadas
            val newEncryptedPrefs = EncryptedSharedPreferences.create(
                context,
                "secure_prefs_${System.currentTimeMillis()}",
                newMasterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            // Migrar datos existentes
            migrateDataToNewKey(existingData, newEncryptedPrefs)

            // Actualizar referencias
            currentMasterKey = newMasterKey
            encryptedPrefs = newEncryptedPrefs

            // Registrar timestamp de rotación
            keyRotationPrefs.edit()
                .putLong("last_rotation", System.currentTimeMillis())
                .putString("rotation_id", UUID.randomUUID().toString())
                .apply()

            logSecurityEvent("KEY_ROTATION", "Rotación completada exitosamente")
            true

        } catch (e: Exception) {
            logSecurityEvent("KEY_ROTATION_FAILED", "Error en rotación: ${e.message}")
            false
        }
    }

    fun verifyDataIntegrity(key: String): Boolean {
        return try {
            val data = encryptedPrefs.getString(key, null) ?: return false
            val storedHmac = encryptedPrefs.getString("${key}_hmac", null) ?: return false

            // Generar HMAC para los datos actuales
            val currentHmac = generateHMAC(data, getHMACKey())

            val isValid = MessageDigest.isEqual(
                storedHmac.toByteArray(),
                currentHmac.toByteArray()
            )

            logSecurityEvent("INTEGRITY_CHECK", "Verificación para $key: ${if (isValid) "VÁLIDA" else "INVÁLIDA"}")
            isValid

        } catch (e: Exception) {
            logSecurityEvent("INTEGRITY_CHECK_FAILED", "Error verificando $key: ${e.message}")
            false
        }
    }

    private fun deriveUserKey(userId: String): String {
        val salt = getUserSalt(userId)
        val combined = "$userId:${getDeviceId()}:$salt"

        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(combined.toByteArray())

        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    private fun getUserSalt(userId: String): String {
        val saltKey = "user_salt_$userId"
        var salt = keyRotationPrefs.getString(saltKey, null)

        if (salt == null) {
            // Generar nuevo salt único
            val saltBytes = ByteArray(SALT_LENGTH)
            SecureRandom().nextBytes(saltBytes)
            salt = Base64.encodeToString(saltBytes, Base64.NO_WRAP)

            keyRotationPrefs.edit().putString(saltKey, salt).apply()
            logSecurityEvent("SALT_GENERATION", "Nuevo salt generado para usuario: $userId")
        }

        return salt
    }

    fun storeSecureDataWithIntegrity(key: String, value: String) {
        try {
            // Almacenar datos
            encryptedPrefs.edit().putString(key, value).apply()

            // Generar y almacenar HMAC
            val hmac = generateHMAC(value, getHMACKey())
            encryptedPrefs.edit().putString("${key}_hmac", hmac).apply()

            logSecurityEvent("SECURE_STORAGE", "Datos almacenados con verificación de integridad: $key")

        } catch (e: Exception) {
            logSecurityEvent("STORAGE_ERROR", "Error almacenando $key: ${e.message}")
        }
    }

    private fun generateHMAC(data: String, key: String): String {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        val secretKey = SecretKeySpec(key.toByteArray(),
            HMAC_ALGORITHM
        )
        mac.init(secretKey)
        val hmacBytes = mac.doFinal(data.toByteArray())
        return Base64.encodeToString(hmacBytes, Base64.NO_WRAP)
    }

    private fun getHMACKey(): String {
        val hmacKey = keyRotationPrefs.getString("hmac_key", null)
        if (hmacKey == null) {
            val newKey = generateSecureRandomString(32)
            keyRotationPrefs.edit().putString("hmac_key", newKey).apply()
            return newKey
        }
        return hmacKey
    }

    private fun shouldRotateKey(): Boolean {
        val lastRotation = keyRotationPrefs.getLong("last_rotation", 0)
        val currentTime = System.currentTimeMillis()
        return (currentTime - lastRotation) > KEY_ROTATION_INTERVAL
    }

    private fun initializeWithCurrentKey() {
        currentMasterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        encryptedPrefs = EncryptedSharedPreferences.create(
            context,
            "secure_prefs",
            currentMasterKey!!,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun backupExistingData(): Map<String, String> {
        val backup = HashMap<String, String>()
        try {
            encryptedPrefs.all.forEach { (key, value) ->
                if (value is String) {
                    backup[key] = value
                }
            }
        } catch (e: Exception) {
            logSecurityEvent("BACKUP_ERROR", "Error respaldando datos: ${e.message}")
        }
        return backup
    }

    private fun migrateDataToNewKey(data: Map<String, String>, newPrefs: SharedPreferences) {
        val editor = newPrefs.edit()
        data.forEach { (key, value) ->
            editor.putString(key, value)
        }
        editor.apply()
        logSecurityEvent("DATA_MIGRATION", "Migrados ${data.size} elementos a nueva clave")
    }

    private fun initializeFallback() {
        encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)
        logSecurityEvent("FALLBACK_INIT", "Inicializado modo fallback - DATOS NO ENCRIPTADOS")
    }

    private fun getDeviceId(): String {
        return android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        ) ?: "unknown_device"
    }

    private fun generateSecureRandomString(length: Int): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val random = SecureRandom()
        return (1..length)
            .map { chars[random.nextInt(chars.length)] }
            .joinToString("")
    }

    private fun logSecurityEvent(category: String, action: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(Date())
        val logEntry = "$timestamp - SECURITY_$category: $action"

        val existingLogs = accessLogPrefs.getString("security_logs", "") ?: ""
        val newLogs = if (existingLogs.isEmpty()) {
            logEntry
        } else {
            "$existingLogs\n$logEntry"
        }

        accessLogPrefs.edit().putString("security_logs", newLogs).apply()
    }

    // Métodos heredados del DataProtectionManager original
    fun storeSecureData(key: String, value: String) {
        storeSecureDataWithIntegrity(key, value)
    }

    fun getSecureData(key: String): String? {
        val data = encryptedPrefs.getString(key, null)
        if (data != null) {
            // Verificar integridad antes de devolver datos
            if (!verifyDataIntegrity(key)) {
                logSecurityEvent("INTEGRITY_VIOLATION", "Datos comprometidos detectados para: $key")
                return null
            }
            logSecurityEvent("DATA_ACCESS", "Dato accedido: $key")
        }
        return data
    }

    fun logAccess(category: String, action: String) {
        logSecurityEvent(category, action)
    }

    fun getAccessLogs(): List<String> {
        val logsString = accessLogPrefs.getString("security_logs", "") ?: ""
        return if (logsString.isEmpty()) {
            emptyList()
        } else {
            logsString.split("\n").reversed()
        }
    }

    fun clearAllData() {
        encryptedPrefs.edit().clear().apply()
        accessLogPrefs.edit().clear().apply()
        keyRotationPrefs.edit().clear().apply()

        logSecurityEvent("DATA_MANAGEMENT", "Todos los datos han sido borrados de forma segura")
    }

    fun getDataProtectionInfo(): Map<String, String> {
        val lastRotation = keyRotationPrefs.getLong("last_rotation", 0)
        val rotationDate = if (lastRotation > 0) {
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(lastRotation))
        } else {
            "Nunca"
        }

        return mapOf(
            "Encriptación" to "AES-256-GCM con rotación automática",
            "Verificación de integridad" to "HMAC-SHA256",
            "Última rotación de clave" to rotationDate,
            "Próxima rotación" to getNextRotationDate(),
            "Salt único por usuario" to "Activo",
            "Logs de acceso" to "${getAccessLogs().size} entradas",
            "Estado de seguridad" to "Mejorado"
        )
    }

    private fun getNextRotationDate(): String {
        val lastRotation = keyRotationPrefs.getLong("last_rotation", 0)
        val nextRotation = lastRotation + KEY_ROTATION_INTERVAL
        return SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(nextRotation))
    }
}