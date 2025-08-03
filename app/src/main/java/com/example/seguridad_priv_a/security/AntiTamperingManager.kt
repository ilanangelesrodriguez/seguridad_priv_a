package com.example.seguridad_priv_a.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Debug
import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

class AntiTamperingManager(private val context: Context) {

    private val obfuscatedStrings = mutableMapOf<String, String>()
    private val certificatePins = mutableMapOf<String, Set<String>>()

    companion object {
        // Strings ofuscados - en producción usar herramientas de ofuscación más avanzadas
        private const val OBFUSCATED_API_KEY = "encrypted_api_key_here"
        private const val OBFUSCATED_SECRET = "encrypted_secret_here"

        // Detectores de debugging
        private val DEBUG_INDICATORS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/data/local/xbin/su",
            "/data/local/bin/su"
        )

        private val EMULATOR_INDICATORS = listOf(
            "generic",
            "unknown",
            "emulator",
            "sdk_gphone",
            "google_sdk"
        )
    }

    fun initializeAntiTampering(): Boolean {
        try {
            // Verificar si la aplicación está siendo debuggeada
            if (isBeingDebugged()) {
                handleTamperingDetected("Active debugging detected")
                return false
            }

            // Verificar si está ejecutándose en un emulador
            if (isRunningOnEmulator()) {
                handleTamperingDetected("Emulator environment detected")
                return false
            }

            // Verificar integridad de la aplicación
            if (!verifyApplicationIntegrity()) {
                handleTamperingDetected("Application integrity compromised")
                return false
            }

            // Inicializar certificate pinning
            initializeCertificatePinning()

            // Ofuscar strings sensibles
            initializeStringObfuscation()

            return true

        } catch (e: Exception) {
            handleTamperingDetected("Anti-tampering initialization failed: ${e.message}")
            return false
        }
    }

    private fun isBeingDebugged(): Boolean {
        // Verificar múltiples indicadores de debugging

        // 1. Verificar flag de debugging de Android
        if (Debug.isDebuggerConnected()) {
            return true
        }

        // 2. Verificar si la aplicación fue compilada en modo debug
        val isDebuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (isDebuggable) {
            return true
        }

        // 3. Verificar presencia de debugger usando timing
        val startTime = System.nanoTime()
        Debug.waitForDebugger()
        val endTime = System.nanoTime()

        // Si el tiempo es muy largo, probablemente hay un debugger
        if ((endTime - startTime) > 10000000) { // 10ms
            return true
        }

        // 4. Verificar archivos de root/debugging tools
        for (path in DEBUG_INDICATORS) {
            if (File(path).exists()) {
                return true
            }
        }

        return false
    }

    private fun isRunningOnEmulator(): Boolean {
        // Verificar múltiples indicadores de emulador

        // 1. Verificar modelo del dispositivo
        val model = Build.MODEL.lowercase()
        for (indicator in EMULATOR_INDICATORS) {
            if (model.contains(indicator)) {
                return true
            }
        }

        // 2. Verificar manufacturer
        val manufacturer = Build.MANUFACTURER.lowercase()
        if (manufacturer.contains("genymotion") || manufacturer.contains("google")) {
            return true
        }

        // 3. Verificar hardware
        val hardware = Build.HARDWARE.lowercase()
        if (hardware.contains("goldfish") || hardware.contains("ranchu")) {
            return true
        }

        // 4. Verificar fingerprint
        val fingerprint = Build.FINGERPRINT.lowercase()
        if (fingerprint.contains("generic") || fingerprint.contains("emulator")) {
            return true
        }

        // 5. Verificar archivos específicos del emulador
        val emulatorFiles = listOf(
            "/dev/socket/qemud",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        )

        for (file in emulatorFiles) {
            if (File(file).exists()) {
                return true
            }
        }

        return false
    }

    private fun verifyApplicationIntegrity(): Boolean {
        try {
            // Verificar checksum del APK
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName, 0
            )

            val apkPath = packageInfo.applicationInfo?.sourceDir
            val apkFile = File(apkPath)

            if (!apkFile.exists()) {
                return false
            }

            // Calcular hash del APK
            val apkHash = calculateFileHash(apkFile)
            val expectedHash = getExpectedApkHash()

            return apkHash.contentEquals(expectedHash)

        } catch (e: Exception) {
            return false
        }
    }

    private fun initializeCertificatePinning() {
        // Configurar certificate pinning para APIs futuras
        certificatePins["api.example.com"] = setOf(
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
        )

        certificatePins["secure.example.com"] = setOf(
            "sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
            "sha256/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
        )
    }

    private fun initializeStringObfuscation() {
        // Desofuscar strings críticos en runtime
        obfuscatedStrings["API_KEY"] = deobfuscateString(OBFUSCATED_API_KEY)
        obfuscatedStrings["SECRET"] = deobfuscateString(OBFUSCATED_SECRET)
    }

    fun getObfuscatedString(key: String): String? {
        return obfuscatedStrings[key]
    }

    fun verifyCertificatePin(hostname: String, certificateHash: String): Boolean {
        val pins = certificatePins[hostname] ?: return false
        return pins.contains(certificateHash)
    }

    private fun deobfuscateString(obfuscatedString: String): String {
        try {
            // Implementación simple de deofuscación
            // En producción, usar algoritmos más complejos
            val key = SecretKeySpec("MySecretKey1234".toByteArray(), "AES")
            val cipher = Cipher.getInstance("AES")
            cipher.init(Cipher.DECRYPT_MODE, key)

            val encryptedBytes = android.util.Base64.decode(obfuscatedString, android.util.Base64.DEFAULT)
            val decryptedBytes = cipher.doFinal(encryptedBytes)

            return String(decryptedBytes)
        } catch (e: Exception) {
            return ""
        }
    }

    private fun calculateFileHash(file: File): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest()
    }

    private fun getExpectedApkHash(): ByteArray {
        // En producción, esto debería estar ofuscado y verificado contra un servidor
        return "EXPECTED_APK_HASH_HERE".toByteArray()
    }

    private fun handleTamperingDetected(reason: String) {
        // Registrar el intento de tampering
        logSecurityEvent("TAMPERING_DETECTED", reason)

        // Implementar contramedidas
        implementCountermeasures(reason)
    }

    private fun implementCountermeasures(reason: String) {
        // Contramedidas progresivas
        when {
            reason.contains("debugging") -> {
                // Limpiar datos sensibles de memoria
                clearSensitiveData()
                // Cerrar la aplicación
                System.exit(0)
            }
            reason.contains("emulator") -> {
                // Modo de funcionalidad limitada
                enableRestrictedMode()
            }
            reason.contains("integrity") -> {
                // Bloquear funcionalidades críticas
                disableCriticalFeatures()
            }
        }
    }

    private fun clearSensitiveData() {
        // Limpiar strings ofuscados
        obfuscatedStrings.clear()

        // Limpiar certificados
        certificatePins.clear()

        // Forzar garbage collection
        System.gc()
    }

    private fun enableRestrictedMode() {
        // Implementar modo restringido
        // Deshabilitar funcionalidades sensibles
    }

    private fun disableCriticalFeatures() {
        // Deshabilitar funcionalidades críticas
        // Mostrar mensaje de error al usuario
    }

    private fun logSecurityEvent(eventType: String, details: String) {
        // Registrar evento de seguridad
        val timestamp = System.currentTimeMillis()
        println("SECURITY_EVENT: $timestamp - $eventType: $details")
    }

    // Función para verificar integridad en runtime
    fun performRuntimeIntegrityCheck(): Boolean {
        return try {
            !isBeingDebugged() &&
                    !isRunningOnEmulator() &&
                    verifyApplicationIntegrity()
        } catch (e: Exception) {
            false
        }
    }
}
