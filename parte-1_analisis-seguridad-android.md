# 📱 Análisis de Seguridad - Aplicación Android

<div align="center">

**Análisis de Vulnerabilidades y Protección de Datos**

---

**👨‍🎓 Estudiante:** Ilan Angeles Rodriguez  
**🏛️ Universidad:** Universidad Nacional del Santa (UNS)  
**💼 LinkedIn:** [ilanangelesrodriguez](https://www.linkedin.com/in/ilanangelesrodriguez/)  
**📚 Curso:** Aplicaciones Móviles  
**📧 Email:** 202014026@uns.edu.pe

---

</div>

## 📋 Tabla de Contenidos

- [🔍 Parte 1: Análisis de Seguridad Básico](#-parte-1-análisis-de-seguridad-básico)
  - [🛡️ 1.1 Identificación de Vulnerabilidades](#️-11-identificación-de-vulnerabilidades)
  - [🔐 1.2 Permisos y Manifiesto](#-12-permisos-y-manifiesto)
  - [📁 1.3 Gestión de Archivos](#-13-gestión-de-archivos)

---

## 🔍 Parte 1: Análisis de Seguridad Básico

### 🛡️ 1.1 Identificación de Vulnerabilidades

#### 🔒 ¿Qué método de encriptación se utiliza para proteger datos sensibles?

En el archivo `DataProtectionManager.kt`, se implementa un sistema de encriptación robusto utilizando **AES-256-GCM**:

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
```

| Componente | Algoritmo de Encriptación |
|------------|---------------------------|
| 🔑 **Clave Maestra** | AES-256-GCM |
| 🗝️ **Claves de Preferencias** | AES256_SIV |
| 💾 **Valores de Preferencias** | AES256_GCM |

#### ⚠️ Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging

##### 🚨 **Vulnerabilidad #1: Logs almacenados sin encriptación**

```kotlin
// SharedPreferences normal para logs de acceso (no son datos sensibles críticos)
accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
```

> **⚠️ Riesgo:** Los logs se almacenan en SharedPreferences normales, **sin encriptación**, lo que puede exponer información sensible sobre patrones de comportamiento del usuario y metadatos de acceso.

##### 🚨 **Vulnerabilidad #2: Filtración de información sensible en logs**

```kotlin
dataProtectionManager.logAccess("DATA_STORAGE", "Dato almacenado de forma segura: \$key")
dataProtectionManager.logAccess("DATA_ACCESS", "Dato accedido: \$key")
```

> **⚠️ Riesgo:** Los logs incluyen las **claves de los datos accedidos**, revelando qué tipo de información sensible maneja la aplicación y creando un mapa de actividad del usuario.

#### 💥 ¿Qué sucede si falla la inicialización del sistema de encriptación?

```kotlin
} catch (e: Exception) {
    // Fallback a SharedPreferences normales si falla la encriptación
    encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)
    accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
}
```

> **🔴 CRÍTICO:** Si falla la inicialización del sistema de encriptación, la aplicación realiza un **fallback silencioso a SharedPreferences normales**, almacenando datos sensibles **completamente sin protección**. Esto compromete totalmente la seguridad de los datos sin notificar al usuario del fallo de seguridad.

---

### 🔐 1.2 Permisos y Manifiesto

#### 📋 Lista todos los permisos peligrosos declarados en el manifiesto

Los siguientes permisos peligrosos están declarados en `AndroidManifest.xml`:

| # | Permiso | Descripción | Nivel de Riesgo |
|---|---------|-------------|-----------------|
| 1 | `CAMERA` | 📷 Acceso a la cámara | 🟡 Medio |
| 2 | `READ_EXTERNAL_STORAGE` | 📂 Lectura de almacenamiento externo | 🟠 Alto |
| 3 | `READ_MEDIA_IMAGES` | 🖼️ Lectura de imágenes multimedia | 🟡 Medio |
| 4 | `RECORD_AUDIO` | 🎤 Grabación de audio | 🔴 Alto |
| 5 | `READ_CONTACTS` | 👥 Lectura de contactos | 🔴 Alto |
| 6 | `CALL_PHONE` | 📞 Realizar llamadas telefónicas | 🔴 Crítico |
| 7 | `SEND_SMS` | 💬 Envío de SMS | 🔴 Crítico |
| 8 | `ACCESS_COARSE_LOCATION` | 📍 Acceso a ubicación aproximada | 🟠 Alto |

#### 🔄 ¿Qué patrón se utiliza para solicitar permisos en runtime?

Se implementa el patrón moderno **ActivityResultContracts** con `RequestPermission()`:

```kotlin
private val requestPermissionLauncher = registerForActivityResult(
    ActivityResultContracts.RequestPermission()
) { isGranted ->
    val permission = currentRequestedPermission
    if (permission != null) {
        permission.status = if (isGranted) PermissionStatus.GRANTED else PermissionStatus.DENIED
        permissionsAdapter.updatePermissionStatus(permission)
        
        val status = if (isGranted) "OTORGADO" else "DENEGADO"
        dataProtectionManager.logAccess("PERMISSION", "\${permission.name}: \$status")
        
        if (isGranted) {
            openActivity(permission)
        }
        currentRequestedPermission = null
    }
}
```

**🔄 Flujo de Solicitud de Permisos:**

1. **✅ Verificación** del estado actual del permiso
2. **📤 Solicitud** del permiso usando el launcher
3. **📥 Manejo** del resultado en el callback
4. **📝 Logging** de la acción realizada
5. **🚀 Navegación** condicional basada en el resultado

#### 🛡️ Identifica qué configuración de seguridad previene backups automáticos

```xml
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules"
    ...>
```

> **🔒 Configuración de Seguridad:** `android:allowBackup="false"` **previene los backups automáticos**, protegiendo los datos sensibles de la aplicación de ser incluidos en copias de seguridad del sistema Android.

---

### 📁 1.3 Gestión de Archivos

#### 🔐 ¿Cómo se implementa la compartición segura de archivos de imágenes?

La compartición segura se implementa utilizando **FileProvider** de AndroidX:

```kotlin
currentPhotoUri = FileProvider.getUriForFile(
    this,
    "com.example.seguridad_priv_a.fileprovider",
    photoFile
)
```

**Configuración en `file_paths.xml`:**
```xml
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <external-files-path name="my_images" path="Pictures" />
    <external-files-path name="my_audio" path="Audio" />
</paths>
```

#### 🏷️ ¿Qué autoridad se utiliza para el FileProvider?

**Autoridad:** `com.example.seguridad_priv_a.fileprovider`

**Declaración en el manifiesto:**
```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.seguridad_priv_a.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths" />
</provider>
```

#### 🚫 Explica por qué no se debe usar file:// URIs directamente

| Problema | Descripción | Impacto |
|----------|-------------|---------|
| **🔓 Exposición de Rutas** | Los `file://` URIs exponen rutas completas del sistema de archivos | Revelación de estructura interna de la app |
| **⛔ Restricciones de Android N+** | A partir de Android 7.0 (API 24), compartir `file://` URIs lanza `FileUriExposedException` | Crash de la aplicación |
| **🚨 Falta de Control de Permisos** | No permiten control granular sobre el acceso a archivos | Acceso no autorizado a archivos |
| **📱 Incompatibilidad con Políticas Modernas** | No cumple con las políticas de seguridad actuales de Android | Rechazo en Play Store |

#### ✅ **Ventajas del FileProvider:**

- **🔒 URIs Seguros:** Genera URIs `content://` temporales y seguros
- **⏰ Permisos Temporales:** Otorga permisos específicos y limitados en tiempo
- **🎯 Control Granular:** Permite control preciso sobre qué aplicaciones acceden a qué archivos
- **✅ Cumplimiento de Estándares:** Compatible con las mejores prácticas de seguridad de Android

---

<div align="center">

## 📊 Resumen de Hallazgos

| Categoría | Estado | Observaciones |
|-----------|--------|---------------|
| **🔐 Encriptación** | ✅ **Bueno** | AES-256-GCM implementado correctamente |
| **📝 Logging** | ⚠️ **Mejorable** | 2 vulnerabilidades identificadas |
| **🔒 Fallback de Seguridad** | 🔴 **Crítico** | Falla silenciosa a almacenamiento sin encriptar |
| **📋 Permisos** | ✅ **Bueno** | Patrón moderno ActivityResultContracts |
| **💾 Backups** | ✅ **Seguro** | Backups automáticos deshabilitados |
| **📁 Compartición de Archivos** | ✅ **Seguro** | FileProvider implementado correctamente |

---

**📅 Fecha de Análisis:** $(new Date().toLocaleDateString('es-ES'))  
**🔍 Versión del Análisis:** 1.0  
**👨‍💻 Analista:** Ilan Angeles Rodriguez

</div>
