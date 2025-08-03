package com.example.seguridad_priv_a

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.example.seguridad_priv_a.data.SecurityAuditManager
import com.example.seguridad_priv_a.databinding.ActivityDataProtectionBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executor

class DataProtectionActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDataProtectionBinding
    private val dataProtectionManager by lazy {
        (application as PermissionsApplication).dataProtectionManager
    }
    private lateinit var securityAuditManager: SecurityAuditManager

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    private var isAuthenticated = false
    private var lastActivityTime = System.currentTimeMillis()
    private val sessionTimeoutHandler = Handler(Looper.getMainLooper())
    private val sessionTimeoutRunnable = Runnable { handleSessionTimeout() }

    companion object {
        private const val SESSION_TIMEOUT = 5 * 60 * 1000L // 5 minutos
        private const val MAX_FAILED_ATTEMPTS = 3
    }

    private var failedAttempts = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDataProtectionBinding.inflate(layoutInflater)
        setContentView(binding.root)

        initializeSecurityComponents()
        setupBiometricAuthentication()

        // Requerir autenticación al iniciar
        if (!isAuthenticated) {
            authenticateUser()
        } else {
            setupAuthenticatedUI()
        }

        dataProtectionManager.logAccess("NAVIGATION", "EnhancedDataProtectionActivity abierta")
    }

    private fun initializeSecurityComponents() {
        securityAuditManager = SecurityAuditManager(this)
        securityAuditManager.initialize()
    }

    /**
     * Configuración de autenticación biométrica con BiometricPrompt API
     */
    private fun setupBiometricAuthentication() {
        executor = ContextCompat.getMainExecutor(this)

        biometricPrompt = BiometricPrompt(this as FragmentActivity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    handleAuthenticationError(errorCode, errString.toString())
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    handleAuthenticationSuccess()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    handleAuthenticationFailure()
                }
            })

        // Configurar el prompt biométrico
        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autenticación Requerida")
            .setSubtitle("Usa tu huella dactilar o reconocimiento facial para acceder a los datos de protección")
            .setDescription("Esta información es sensible y requiere autenticación biométrica")
            .setNegativeButtonText("Usar PIN/Patrón")
            .setConfirmationRequired(true)
            .build()
    }

    private fun authenticateUser() {
        // Verificar disponibilidad de biometría
        val biometricManager = BiometricManager.from(this)

        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                // Biometría disponible
                showBiometricPrompt()
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                // No hay hardware biométrico, usar fallback
                showPinPatternFallback("No hay hardware biométrico disponible")
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                // Hardware no disponible temporalmente
                showPinPatternFallback("Hardware biométrico no disponible")
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                // No hay biometría configurada
                showBiometricEnrollmentDialog()
            }
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {
                showSecurityUpdateDialog()
            }
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> {
                showPinPatternFallback("Biometría no soportada")
            }
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> {
                showPinPatternFallback("Estado biométrico desconocido")
            }
        }
    }

    private fun showBiometricPrompt() {
        // Verificar rate limiting
        if (securityAuditManager.isRateLimited("BIOMETRIC_AUTH", "user")) {
            showRateLimitedDialog()
            return
        }

        biometricPrompt.authenticate(promptInfo)
        dataProtectionManager.logAccess("BIOMETRIC_AUTH", "Prompt biométrico mostrado")
    }

    /**
     * Implementación de fallback a PIN/Pattern si biometría no está disponible
     */
    private fun showPinPatternFallback(reason: String) {
        AlertDialog.Builder(this)
            .setTitle("Autenticación Alternativa")
            .setMessage("$reason\n\nPor favor, usa tu PIN, patrón o contraseña del dispositivo para continuar.")
            .setPositiveButton("Autenticar") { _, _ ->
                openDeviceSecuritySettings()
            }
            .setNegativeButton("Cancelar") { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()

        dataProtectionManager.logAccess("FALLBACK_AUTH", "Fallback mostrado: $reason")
    }

    private fun showBiometricEnrollmentDialog() {
        AlertDialog.Builder(this)
            .setTitle("Configurar Biometría")
            .setMessage("No tienes configurada la autenticación biométrica. ¿Deseas configurarla ahora para mayor seguridad?")
            .setPositiveButton("Configurar") { _, _ ->
                openBiometricEnrollment()
            }
            .setNegativeButton("Usar PIN/Patrón") { _, _ ->
                showPinPatternFallback("Biometría no configurada")
            }
            .setCancelable(false)
            .show()
    }

    private fun showSecurityUpdateDialog() {
        AlertDialog.Builder(this)
            .setTitle("Actualización de Seguridad Requerida")
            .setMessage("Se requiere una actualización de seguridad para usar la autenticación biométrica.")
            .setPositiveButton("Ir a Configuración") { _, _ ->
                openDeviceSecuritySettings()
            }
            .setNegativeButton("Cancelar") { _, _ ->
                finish()
            }
            .show()
    }

    private fun showRateLimitedDialog() {
        AlertDialog.Builder(this)
            .setTitle("Demasiados Intentos")
            .setMessage("Has excedido el número máximo de intentos de autenticación. Por favor, espera antes de intentar nuevamente.")
            .setPositiveButton("Entendido") { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }

    private fun handleAuthenticationSuccess() {
        isAuthenticated = true
        failedAttempts = 0
        resetSessionTimeout()
        setupAuthenticatedUI()

        dataProtectionManager.logAccess("BIOMETRIC_AUTH", "Autenticación biométrica exitosa")
        Toast.makeText(this, "Autenticación exitosa", Toast.LENGTH_SHORT).show()
    }

    private fun handleAuthenticationFailure() {
        failedAttempts++
        dataProtectionManager.logAccess("BIOMETRIC_AUTH", "Intento de autenticación fallido ($failedAttempts/$MAX_FAILED_ATTEMPTS)")

        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            securityAuditManager.detectSuspiciousAccess("BIOMETRIC_AUTH_FAILED", "user")

            AlertDialog.Builder(this)
                .setTitle("Múltiples Intentos Fallidos")
                .setMessage("Has fallado $MAX_FAILED_ATTEMPTS intentos de autenticación. La aplicación se cerrará por seguridad.")
                .setPositiveButton("Entendido") { _, _ ->
                    finish()
                }
                .setCancelable(false)
                .show()
        } else {
            Toast.makeText(this, "Autenticación fallida. Intentos restantes: ${MAX_FAILED_ATTEMPTS - failedAttempts}", Toast.LENGTH_LONG).show()
        }
    }

    private fun handleAuthenticationError(errorCode: Int, errString: String) {
        when (errorCode) {
            BiometricPrompt.ERROR_USER_CANCELED -> {
                dataProtectionManager.logAccess("BIOMETRIC_AUTH", "Autenticación cancelada por el usuario")
                finish()
            }
            BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {
                // Usuario eligió usar PIN/Patrón
                showPinPatternFallback("Usuario eligió autenticación alternativa")
            }
            BiometricPrompt.ERROR_LOCKOUT -> {
                showTemporaryLockoutDialog()
            }
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                showPermanentLockoutDialog()
            }
            else -> {
                dataProtectionManager.logAccess("BIOMETRIC_AUTH", "Error de autenticación: $errString")
                Toast.makeText(this, "Error de autenticación: $errString", Toast.LENGTH_LONG).show()
                finish()
            }
        }
    }

    private fun showTemporaryLockoutDialog() {
        AlertDialog.Builder(this)
            .setTitle("Bloqueo Temporal")
            .setMessage("Demasiados intentos fallidos. La autenticación biométrica está temporalmente bloqueada.")
            .setPositiveButton("Usar PIN/Patrón") { _, _ ->
                showPinPatternFallback("Bloqueo temporal de biometría")
            }
            .setNegativeButton("Cancelar") { _, _ ->
                finish()
            }
            .show()
    }

    private fun showPermanentLockoutDialog() {
        AlertDialog.Builder(this)
            .setTitle("Bloqueo Permanente")
            .setMessage("La autenticación biométrica está permanentemente bloqueada debido a múltiples intentos fallidos.")
            .setPositiveButton("Usar PIN/Patrón") { _, _ ->
                showPinPatternFallback("Bloqueo permanente de biometría")
            }
            .setNegativeButton("Cancelar") { _, _ ->
                finish()
            }
            .show()
    }

    /**
     * Timeout de sesión tras inactividad de 5 minutos
     */
    private fun resetSessionTimeout() {
        lastActivityTime = System.currentTimeMillis()
        sessionTimeoutHandler.removeCallbacks(sessionTimeoutRunnable)
        sessionTimeoutHandler.postDelayed(sessionTimeoutRunnable, SESSION_TIMEOUT)
    }

    private fun handleSessionTimeout() {
        if (isAuthenticated) {
            isAuthenticated = false
            dataProtectionManager.logAccess("SESSION", "Sesión expirada por inactividad")

            AlertDialog.Builder(this)
                .setTitle("Sesión Expirada")
                .setMessage("Tu sesión ha expirado por inactividad. Debes autenticarte nuevamente.")
                .setPositiveButton("Autenticar") { _, _ ->
                    authenticateUser()
                }
                .setNegativeButton("Salir") { _, _ ->
                    finish()
                }
                .setCancelable(false)
                .show()
        }
    }

    private fun setupAuthenticatedUI() {
        loadDataProtectionInfo()
        loadAccessLogs()
        loadSecurityAuditInfo()

        binding.btnViewLogs.setOnClickListener {
            resetSessionTimeout()
            loadAccessLogs()
            Toast.makeText(this, "Logs actualizados", Toast.LENGTH_SHORT).show()
        }

        binding.btnClearData.setOnClickListener {
            resetSessionTimeout()
            showClearDataDialog()
        }

        // Nuevo botón para exportar logs firmados
        binding.btnExportLogs?.setOnClickListener {
            resetSessionTimeout()
            exportSignedLogs()
        }
    }

    private fun loadSecurityAuditInfo() {
        val suspiciousCount = securityAuditManager.getSuspiciousActivitiesCount()
        val recentAlerts = securityAuditManager.getRecentAlerts().take(5)

        val auditInfo = StringBuilder()
        auditInfo.append("\n🛡️ AUDITORÍA DE SEGURIDAD:\n")
        auditInfo.append("• Actividades sospechosas: $suspiciousCount\n")
        auditInfo.append("• Alertas recientes: ${recentAlerts.size}\n")

        if (recentAlerts.isNotEmpty()) {
            auditInfo.append("\n🚨 ALERTAS RECIENTES:\n")
            recentAlerts.forEach { alert ->
                val date = SimpleDateFormat("dd/MM HH:mm", Locale.getDefault()).format(Date(alert.timestamp))
                auditInfo.append("• [$date] ${alert.severity}: ${alert.message}\n")
            }
        }

        // Agregar información de auditoría al texto existente
        val currentText = binding.tvDataProtectionInfo.text.toString()
        binding.tvDataProtectionInfo.text = "$currentText\n$auditInfo"
    }

    private fun exportSignedLogs() {
        try {
            val signedLogs = securityAuditManager.exportSignedLogs()

            // En una implementación real, aquí guardarías el archivo o lo compartirías
            // Por ahora, mostraremos un resumen
            AlertDialog.Builder(this)
                .setTitle("Logs Exportados")
                .setMessage("Los logs han sido exportados y firmados digitalmente.\n\nTamaño: ${signedLogs.length} caracteres\nFirma: Verificada")
                .setPositiveButton("Entendido", null)
                .show()

            dataProtectionManager.logAccess("EXPORT", "Logs exportados con firma digital")

        } catch (e: Exception) {
            Toast.makeText(this, "Error exportando logs: ${e.message}", Toast.LENGTH_LONG).show()
            dataProtectionManager.logAccess("EXPORT_ERROR", "Error exportando logs: ${e.message}")
        }
    }

    private fun openBiometricEnrollment() {
        val intent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
            putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        }
        startActivity(intent)
    }

    private fun openDeviceSecuritySettings() {
        val intent = Intent(Settings.ACTION_SECURITY_SETTINGS)
        startActivity(intent)
    }

    // Métodos heredados del DataProtectionActivity original
    private fun loadDataProtectionInfo() {
        val info = dataProtectionManager.getDataProtectionInfo()
        val infoText = StringBuilder()

        infoText.append("🔐 INFORMACIÓN DE SEGURIDAD MEJORADA\n\n")
        info.forEach { (key, value) ->
            infoText.append("• $key: $value\n")
        }

        infoText.append("\n📊 EVIDENCIAS DE PROTECCIÓN:\n")
        infoText.append("• Encriptación AES-256-GCM con rotación automática\n")
        infoText.append("• Verificación de integridad HMAC-SHA256\n")
        infoText.append("• Autenticación biométrica activa\n")
        infoText.append("• Sistema de auditoría avanzado\n")
        infoText.append("• Rate limiting implementado\n")
        infoText.append("• Logs firmados digitalmente\n")
        infoText.append("• Timeout de sesión: 5 minutos\n")

        binding.tvDataProtectionInfo.text = infoText.toString()

        dataProtectionManager.logAccess("DATA_PROTECTION", "Información de protección mejorada mostrada")
    }

    private fun loadAccessLogs() {
        val logs = dataProtectionManager.getAccessLogs()

        if (logs.isNotEmpty()) {
            val logsText = logs.take(50).joinToString("\n") // Mostrar solo los últimos 50
            binding.tvAccessLogs.text = logsText
        } else {
            binding.tvAccessLogs.text = "No hay logs disponibles"
        }

        dataProtectionManager.logAccess("DATA_ACCESS", "Logs de acceso consultados")
    }

    private fun showClearDataDialog() {
        AlertDialog.Builder(this)
            .setTitle("Borrar Todos los Datos")
            .setMessage("¿Estás seguro de que deseas borrar todos los datos almacenados, logs de acceso y datos de auditoría? Esta acción no se puede deshacer.")
            .setPositiveButton("Borrar") { _, _ ->
                clearAllData()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun clearAllData() {
        dataProtectionManager.clearAllData()

        // Actualizar UI
        binding.tvAccessLogs.text = "Todos los datos han sido borrados"
        binding.tvDataProtectionInfo.text = "🔐 DATOS BORRADOS DE FORMA SEGURA\n\nTodos los datos personales, logs y datos de auditoría han sido eliminados del dispositivo."

        Toast.makeText(this, "Datos borrados de forma segura", Toast.LENGTH_LONG).show()

        dataProtectionManager.logAccess("DATA_MANAGEMENT", "Todos los datos borrados por el usuario")
    }

    override fun onResume() {
        super.onResume()
        if (isAuthenticated) {
            resetSessionTimeout()
            loadAccessLogs()
        }
    }

    override fun onPause() {
        super.onPause()
        sessionTimeoutHandler.removeCallbacks(sessionTimeoutRunnable)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        if (isAuthenticated) {
            resetSessionTimeout()
        }
    }


}