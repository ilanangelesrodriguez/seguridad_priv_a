package com.example.seguridad_priv_a.privacy

import kotlin.math.*
import kotlin.random.Random

data class PersonalData(
    val id: String,
    val age: Int,
    val zipCode: String,
    val salary: Double,
    val medicalCondition: String,
    val sensitiveAttributes: Map<String, Any>
)

data class AnonymizedData(
    val id: String,
    val ageRange: String,
    val zipCodePrefix: String,
    val salaryRange: String,
    val medicalCategory: String,
    val generalizedAttributes: Map<String, Any>
)

data class NumericData(
    val values: List<Double>,
    val metadata: Map<String, Any> = emptyMap()
)

data class MaskingPolicy(
    val dataType: String,
    val maskingLevel: MaskingLevel,
    val preserveFormat: Boolean = true,
    val customRules: Map<String, Any> = emptyMap()
)

enum class MaskingLevel {
    LOW,    // Enmascarar parcialmente
    MEDIUM, // Enmascarar significativamente
    HIGH    // Enmascarar completamente
}

class AdvancedAnonymizer {

    private val random = Random.Default

    /**
     * Implementa k-anonimity: cada registro es indistinguible de al menos k-1 otros registros
     */
    fun anonymizeWithKAnonymity(data: List<PersonalData>, k: Int): List<AnonymizedData> {
        if (data.size < k) {
            throw IllegalArgumentException("Dataset too small for k=$k anonymity")
        }

        // Agrupar datos por atributos quasi-identificadores
        val groups = groupByQuasiIdentifiers(data, k)

        return groups.flatMap { group ->
            generalizeGroup(group)
        }
    }

    /**
     * Implementa l-diversity: cada grupo k-anónimo tiene al menos l valores diferentes
     * para cada atributo sensible
     */
    fun anonymizeWithLDiversity(data: List<PersonalData>, k: Int, l: Int): List<AnonymizedData> {
        val kAnonymousGroups = groupByQuasiIdentifiers(data, k)

        // Verificar y ajustar para l-diversity
        val lDiverseGroups = ensureLDiversity(kAnonymousGroups, l)

        return lDiverseGroups.flatMap { group ->
            generalizeGroup(group)
        }
    }

    /**
     * Aplica differential privacy añadiendo ruido calibrado a datos numéricos
     */
    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData {
        if (epsilon <= 0) {
            throw IllegalArgumentException("Epsilon must be positive")
        }

        // Calcular sensibilidad de la función (para suma/promedio = 1)
        val sensitivity = 1.0

        // Generar ruido Laplaciano
        val scale = sensitivity / epsilon
        val noisyValues = data.values.map { value ->
            value + generateLaplaceNoise(scale)
        }

        return NumericData(
            values = noisyValues,
            metadata = data.metadata + mapOf(
                "epsilon" to epsilon,
                "noise_applied" to true,
                "privacy_budget_used" to epsilon
            )
        )
    }

    /**
     * Aplica enmascaramiento específico por tipo de dato
     */
    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any {
        return when (maskingPolicy.dataType.uppercase()) {
            "EMAIL" -> maskEmail(data as String, maskingPolicy)
            "PHONE" -> maskPhoneNumber(data as String, maskingPolicy)
            "SSN" -> maskSSN(data as String, maskingPolicy)
            "CREDIT_CARD" -> maskCreditCard(data as String, maskingPolicy)
            "NAME" -> maskName(data as String, maskingPolicy)
            "ADDRESS" -> maskAddress(data as String, maskingPolicy)
            "DATE" -> maskDate(data as String, maskingPolicy)
            "NUMERIC" -> maskNumeric(data as Double, maskingPolicy)
            else -> maskGeneric(data.toString(), maskingPolicy)
        }
    }

    private fun groupByQuasiIdentifiers(data: List<PersonalData>, k: Int): List<List<PersonalData>> {
        // Agrupar por edad, código postal (primeros 3 dígitos)
        val grouped = data.groupBy { person ->
            val ageGroup = (person.age / 10) * 10 // Grupos de 10 años
            val zipPrefix = person.zipCode.take(3)
            "$ageGroup-$zipPrefix"
        }

        val validGroups = mutableListOf<List<PersonalData>>()
        val remainingData = mutableListOf<PersonalData>()

        // Separar grupos que cumplen k-anonimity
        grouped.values.forEach { group ->
            if (group.size >= k) {
                validGroups.add(group)
            } else {
                remainingData.addAll(group)
            }
        }

        // Reagrupar datos restantes con generalización más agresiva
        if (remainingData.isNotEmpty()) {
            val regrouped = regroupWithHigherGeneralization(remainingData, k)
            validGroups.addAll(regrouped)
        }

        return validGroups
    }

    private fun ensureLDiversity(groups: List<List<PersonalData>>, l: Int): List<List<PersonalData>> {
        return groups.mapNotNull { group ->
            val sensitiveValues = group.map { it.medicalCondition }.distinct()
            if (sensitiveValues.size >= l) {
                group
            } else {
                // Intentar combinar con otros grupos o suprimir
                null
            }
        }.filterNotNull()
    }

    private fun generalizeGroup(group: List<PersonalData>): List<AnonymizedData> {
        val ageRange = "${group.minOf { it.age }}-${group.maxOf { it.age }}"
        val zipPrefix = group.first().zipCode.take(3) + "**"
        val salaryMin = group.minOf { it.salary }
        val salaryMax = group.maxOf { it.salary }
        val salaryRange = "${(salaryMin/1000).toInt()}K-${(salaryMax/1000).toInt()}K"

        return group.map { person ->
            AnonymizedData(
                id = generateAnonymousId(),
                ageRange = ageRange,
                zipCodePrefix = zipPrefix,
                salaryRange = salaryRange,
                medicalCategory = generalizeMedicalCondition(person.medicalCondition),
                generalizedAttributes = generalizeAttributes(person.sensitiveAttributes)
            )
        }
    }

    private fun regroupWithHigherGeneralization(data: List<PersonalData>, k: Int): List<List<PersonalData>> {
        // Generalización más agresiva: grupos de 20 años, primeros 2 dígitos del código postal
        val regrouped = data.groupBy { person ->
            val ageGroup = (person.age / 20) * 20
            val zipPrefix = person.zipCode.take(2)
            "$ageGroup-$zipPrefix"
        }

        return regrouped.values.filter { it.size >= k }
    }

    private fun generateLaplaceNoise(scale: Double): Double {
        val u = random.nextDouble() - 0.5
        return -scale * sign(u) * ln(1 - 2 * abs(u))
    }

    private fun maskEmail(email: String, policy: MaskingPolicy): String {
        val parts = email.split("@")
        if (parts.size != 2) return "***@***.***"

        val localPart = parts[0]
        val domain = parts[1]

        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> {
                val maskedLocal = if (localPart.length > 2) {
                    localPart.take(2) + "*".repeat(localPart.length - 2)
                } else {
                    "*".repeat(localPart.length)
                }
                "$maskedLocal@$domain"
            }
            MaskingLevel.MEDIUM -> {
                val maskedLocal = localPart.take(1) + "*".repeat(localPart.length - 1)
                val maskedDomain = domain.split(".").joinToString(".") { part ->
                    if (part.length > 1) part.take(1) + "*".repeat(part.length - 1) else part
                }
                "$maskedLocal@$maskedDomain"
            }
            MaskingLevel.HIGH -> "***@***.***"
        }
    }

    private fun maskPhoneNumber(phone: String, policy: MaskingPolicy): String {
        val digits = phone.filter { it.isDigit() }

        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> {
                if (digits.length >= 4) {
                    "*".repeat(digits.length - 4) + digits.takeLast(4)
                } else {
                    "*".repeat(digits.length)
                }
            }
            MaskingLevel.MEDIUM -> {
                if (digits.length >= 2) {
                    "*".repeat(digits.length - 2) + digits.takeLast(2)
                } else {
                    "*".repeat(digits.length)
                }
            }
            MaskingLevel.HIGH -> "*".repeat(digits.length)
        }
    }

    private fun maskSSN(ssn: String, policy: MaskingPolicy): String {
        val digits = ssn.filter { it.isDigit() }

        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> "***-**-${digits.takeLast(4)}"
            MaskingLevel.MEDIUM -> "***-**-**${digits.takeLast(2)}"
            MaskingLevel.HIGH -> "***-**-****"
        }
    }

    private fun maskCreditCard(cardNumber: String, policy: MaskingPolicy): String {
        val digits = cardNumber.filter { it.isDigit() }

        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> "**** **** **** ${digits.takeLast(4)}"
            MaskingLevel.MEDIUM -> "**** **** **** **${digits.takeLast(2)}"
            MaskingLevel.HIGH -> "**** **** **** ****"
        }
    }

    private fun maskName(name: String, policy: MaskingPolicy): String {
        val parts = name.split(" ")

        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> {
                parts.mapIndexed { index, part ->
                    if (index == 0) part.take(1) + "*".repeat(part.length - 1)
                    else part
                }.joinToString(" ")
            }
            MaskingLevel.MEDIUM -> {
                parts.map { part ->
                    part.take(1) + "*".repeat(part.length - 1)
                }.joinToString(" ")
            }
            MaskingLevel.HIGH -> "*".repeat(name.length)
        }
    }

    private fun maskAddress(address: String, policy: MaskingPolicy): String {
        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> {
                // Mantener ciudad y estado, enmascarar dirección específica
                val parts = address.split(",")
                if (parts.size >= 2) {
                    "*** ${parts.takeLast(2).joinToString(",")}"
                } else {
                    "*** " + address.takeLast(10)
                }
            }
            MaskingLevel.MEDIUM -> {
                // Mantener solo estado/país
                val parts = address.split(",")
                if (parts.isNotEmpty()) {
                    "*** ${parts.last().trim()}"
                } else {
                    "***"
                }
            }
            MaskingLevel.HIGH -> "***"
        }
    }

    private fun maskDate(date: String, policy: MaskingPolicy): String {
        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> {
                // Mantener año, enmascarar mes y día
                if (date.contains("-")) {
                    val parts = date.split("-")
                    if (parts.size == 3) "**-**-${parts[2]}" else "**-**-****"
                } else {
                    "**/**/****"
                }
            }
            MaskingLevel.MEDIUM -> "**/**/****"
            MaskingLevel.HIGH -> "**/**/****"
        }
    }

    private fun maskNumeric(number: Double, policy: MaskingPolicy): Double {
        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> {
                // Redondear a decenas
                (number / 10).roundToInt() * 10.0
            }
            MaskingLevel.MEDIUM -> {
                // Redondear a centenas
                (number / 100).roundToInt() * 100.0
            }
            MaskingLevel.HIGH -> {
                // Redondear a miles
                (number / 1000).roundToInt() * 1000.0
            }
        }
    }

    private fun maskGeneric(data: String, policy: MaskingPolicy): String {
        return when (policy.maskingLevel) {
            MaskingLevel.LOW -> {
                if (data.length > 2) {
                    data.take(2) + "*".repeat(data.length - 2)
                } else {
                    "*".repeat(data.length)
                }
            }
            MaskingLevel.MEDIUM -> {
                if (data.length > 1) {
                    data.take(1) + "*".repeat(data.length - 1)
                } else {
                    "*"
                }
            }
            MaskingLevel.HIGH -> "*".repeat(data.length)
        }
    }

    private fun generateAnonymousId(): String {
        return "ANON_${random.nextInt(100000, 999999)}"
    }

    private fun generalizeMedicalCondition(condition: String): String {
        // Generalizar condiciones médicas a categorías más amplias
        return when {
            condition.contains("diabetes", ignoreCase = true) -> "Metabolic Disorder"
            condition.contains("hypertension", ignoreCase = true) -> "Cardiovascular Condition"
            condition.contains("depression", ignoreCase = true) -> "Mental Health Condition"
            condition.contains("cancer", ignoreCase = true) -> "Oncological Condition"
            else -> "General Medical Condition"
        }
    }

    private fun generalizeAttributes(attributes: Map<String, Any>): Map<String, Any> {
        return attributes.mapValues { (key, value) ->
            when (key.lowercase()) {
                "income" -> {
                    val income = value as? Double ?: 0.0
                    when {
                        income < 30000 -> "Low Income"
                        income < 70000 -> "Medium Income"
                        else -> "High Income"
                    }
                }
                "education" -> {
                    when (value.toString().lowercase()) {
                        "high school", "hs" -> "Secondary Education"
                        "bachelor", "bs", "ba" -> "Undergraduate"
                        "master", "ms", "ma" -> "Graduate"
                        "phd", "doctorate" -> "Advanced Degree"
                        else -> "Education Completed"
                    }
                }
                else -> "***"
            }
        }
    }
}

/**
 * Sistema de políticas de retención configurables
 */
class RetentionPolicyManager {

    data class RetentionPolicy(
        val dataType: String,
        val retentionPeriodDays: Int,
        val anonymizeAfterDays: Int,
        val deleteAfterDays: Int,
        val exceptions: List<String> = emptyList()
    )

    private val policies = mutableMapOf<String, RetentionPolicy>()

    fun addPolicy(policy: RetentionPolicy) {
        policies[policy.dataType] = policy
    }

    fun getPolicy(dataType: String): RetentionPolicy? {
        return policies[dataType]
    }

    fun shouldAnonymize(dataType: String, dataAge: Long): Boolean {
        val policy = policies[dataType] ?: return false
        val ageDays = dataAge / (24 * 60 * 60 * 1000)
        return ageDays >= policy.anonymizeAfterDays
    }

    fun shouldDelete(dataType: String, dataAge: Long): Boolean {
        val policy = policies[dataType] ?: return false
        val ageDays = dataAge / (24 * 60 * 60 * 1000)
        return ageDays >= policy.deleteAfterDays
    }

    fun initializeDefaultPolicies() {
        // Políticas por defecto según GDPR/CCPA
        addPolicy(RetentionPolicy("PERSONAL_DATA", 365, 180, 2555)) // 7 años máximo
        addPolicy(RetentionPolicy("BIOMETRIC_DATA", 90, 30, 365))   // Datos biométricos más restrictivos
        addPolicy(RetentionPolicy("LOCATION_DATA", 180, 90, 730))   // Datos de ubicación
        addPolicy(RetentionPolicy("USAGE_LOGS", 730, 365, 2555))    // Logs de uso
        addPolicy(RetentionPolicy("SECURITY_LOGS", 2555, 1095, -1)) // Logs de seguridad (no eliminar)
    }
}
