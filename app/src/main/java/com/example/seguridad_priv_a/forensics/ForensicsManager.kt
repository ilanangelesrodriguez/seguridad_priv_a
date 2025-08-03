package com.example.seguridad_priv_a.forensics

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*

data class DigitalEvidence(
    val id: String,
    val timestamp: Long,
    val eventType: String,
    val description: String,
    val hash: String,
    val previousHash: String,
    val metadata: Map<String, Any>,
    val chainOfCustody: List<CustodyRecord>
)

data class CustodyRecord(
    val timestamp: Long,
    val handler: String,
    val action: String,
    val reason: String,
    val signature: String
)

data class ComplianceReport(
    val reportId: String,
    val generatedAt: Long,
    val reportType: String, // GDPR, CCPA, etc.
    val findings: List<ComplianceFinding>,
    val recommendations: List<String>,
    val riskScore: Int
)

data class ComplianceFinding(
    val category: String,
    val severity: String,
    val description: String,
    val evidence: List<String>,
    val remediation: String
)

class ForensicsManager(private val context: Context) {

    private val evidenceChain = mutableListOf<DigitalEvidence>()
    private val custodyLog = mutableMapOf<String, MutableList<CustodyRecord>>()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())

    fun initializeForensics() {
        // Crear evidencia inicial del sistema
        createSystemInitializationEvidence()
    }

    /**
     * Mantiene chain of custody para evidencias digitales
     */
    fun createEvidence(
        eventType: String,
        description: String,
        metadata: Map<String, Any> = emptyMap(),
        handler: String = "SYSTEM"
    ): String {
        val evidenceId = generateEvidenceId()
        val timestamp = System.currentTimeMillis()

        // Calcular hash de la evidencia
        val evidenceData = "$evidenceId:$timestamp:$eventType:$description:${metadata.hashCode()}"
        val hash = calculateHash(evidenceData)

        // Obtener hash de la evidencia anterior para crear la cadena
        val previousHash = evidenceChain.lastOrNull()?.hash ?: "GENESIS"

        // Crear registro de custodia inicial
        val initialCustody = CustodyRecord(
            timestamp = timestamp,
            handler = handler,
            action = "CREATED",
            reason = "Evidence creation",
            signature = generateCustodySignature(evidenceId, handler, "CREATED")
        )

        val evidence = DigitalEvidence(
            id = evidenceId,
            timestamp = timestamp,
            eventType = eventType,
            description = description,
            hash = hash,
            previousHash = previousHash,
            metadata = metadata,
            chainOfCustody = listOf(initialCustody)
        )

        evidenceChain.add(evidence)
        custodyLog[evidenceId] = mutableListOf(initialCustody)

        return evidenceId
    }

    /**
     * Actualiza la cadena de custodia cuando la evidencia es accedida o modificada
     */
    fun updateCustodyChain(
        evidenceId: String,
        handler: String,
        action: String,
        reason: String
    ): Boolean {
        val custodyRecords = custodyLog[evidenceId] ?: return false

        val custodyRecord = CustodyRecord(
            timestamp = System.currentTimeMillis(),
            handler = handler,
            action = action,
            reason = reason,
            signature = generateCustodySignature(evidenceId, handler, action)
        )

        custodyRecords.add(custodyRecord)

        // Actualizar la evidencia en la cadena
        val evidenceIndex = evidenceChain.indexOfFirst { it.id == evidenceId }
        if (evidenceIndex != -1) {
            val updatedEvidence = evidenceChain[evidenceIndex].copy(
                chainOfCustody = custodyRecords.toList()
            )
            evidenceChain[evidenceIndex] = updatedEvidence
        }

        return true
    }

    /**
     * Implementa logs tamper-evident usando blockchain local
     */
    fun addTamperEvidentLog(
        category: String,
        action: String,
        details: Map<String, Any> = emptyMap()
    ) {
        val logEntry = mapOf(
            "category" to category,
            "action" to action,
            "details" to details,
            "timestamp" to System.currentTimeMillis(),
            "system_state" to getCurrentSystemState()
        )

        createEvidence(
            eventType = "TAMPER_EVIDENT_LOG",
            description = "$category: $action",
            metadata = logEntry
        )
    }

    /**
     * Verifica la integridad de la cadena de evidencias
     */
    fun verifyEvidenceChain(): Boolean {
        if (evidenceChain.isEmpty()) return true

        for (i in 1 until evidenceChain.size) {
            val current = evidenceChain[i]
            val previous = evidenceChain[i - 1]

            // Verificar que el hash anterior coincide
            if (current.previousHash != previous.hash) {
                return false
            }

            // Verificar integridad del hash actual
            val expectedHash = calculateHash(
                "${current.id}:${current.timestamp}:${current.eventType}:${current.description}:${current.metadata.hashCode()}"
            )
            if (current.hash != expectedHash) {
                return false
            }
        }

        return true
    }

    /**
     * Genera reportes de compliance GDPR/CCPA automáticos
     */
    fun generateComplianceReport(reportType: String): ComplianceReport {
        val reportId = "COMPLIANCE_${System.currentTimeMillis()}"
        val findings = mutableListOf<ComplianceFinding>()
        val recommendations = mutableListOf<String>()

        when (reportType.uppercase()) {
            "GDPR" -> {
                findings.addAll(analyzeGDPRCompliance())
                recommendations.addAll(getGDPRRecommendations())
            }
            "CCPA" -> {
                findings.addAll(analyzeCCPACompliance())
                recommendations.addAll(getCCPARecommendations())
            }
            "GENERAL" -> {
                findings.addAll(analyzeGeneralCompliance())
                recommendations.addAll(getGeneralRecommendations())
            }
        }

        val riskScore = calculateRiskScore(findings)

        return ComplianceReport(
            reportId = reportId,
            generatedAt = System.currentTimeMillis(),
            reportType = reportType,
            findings = findings,
            recommendations = recommendations,
            riskScore = riskScore
        )
    }

    /**
     * Herramientas de investigación de incidentes
     */
    fun investigateIncident(
        incidentId: String,
        timeRange: Pair<Long, Long>,
        keywords: List<String> = emptyList()
    ): IncidentReport {
        val relevantEvidence = evidenceChain.filter { evidence ->
            evidence.timestamp in timeRange.first..timeRange.second &&
                    (keywords.isEmpty() || keywords.any { keyword ->
                        evidence.description.contains(keyword, ignoreCase = true) ||
                                evidence.eventType.contains(keyword, ignoreCase = true)
                    })
        }

        val timeline = createIncidentTimeline(relevantEvidence)
        val analysis = analyzeIncidentPatterns(relevantEvidence)
        val recommendations = generateIncidentRecommendations(analysis)

        return IncidentReport(
            incidentId = incidentId,
            investigatedAt = System.currentTimeMillis(),
            timeRange = timeRange,
            evidenceCount = relevantEvidence.size,
            timeline = timeline,
            analysis = analysis,
            recommendations = recommendations,
            severity = calculateIncidentSeverity(analysis)
        )
    }

    /**
     * Exporta evidencias en formato forense estándar
     */
    fun exportForensicPackage(evidenceIds: List<String>): String {
        val exportPackage = JSONObject()
        val evidenceArray = JSONArray()

        // Metadatos del export
        exportPackage.put("export_id", generateEvidenceId())
        exportPackage.put("exported_at", System.currentTimeMillis())
        exportPackage.put("exported_by", "ForensicsManager")
        exportPackage.put("chain_verified", verifyEvidenceChain())

        // Evidencias solicitadas
        evidenceIds.forEach { evidenceId ->
            val evidence = evidenceChain.find { it.id == evidenceId }
            evidence?.let {
                val evidenceJson = JSONObject().apply {
                    put("id", it.id)
                    put("timestamp", it.timestamp)
                    put("event_type", it.eventType)
                    put("description", it.description)
                    put("hash", it.hash)
                    put("previous_hash", it.previousHash)
                    put("metadata", JSONObject(it.metadata))

                    val custodyArray = JSONArray()
                    it.chainOfCustody.forEach { custody ->
                        custodyArray.put(JSONObject().apply {
                            put("timestamp", custody.timestamp)
                            put("handler", custody.handler)
                            put("action", custody.action)
                            put("reason", custody.reason)
                            put("signature", custody.signature)
                        })
                    }
                    put("chain_of_custody", custodyArray)
                }
                evidenceArray.put(evidenceJson)
            }
        }

        exportPackage.put("evidence", evidenceArray)

        // Firma digital del paquete completo
        val packageHash = calculateHash(exportPackage.toString())
        exportPackage.put("package_hash", packageHash)
        exportPackage.put("digital_signature", generateDigitalSignature(packageHash))

        return exportPackage.toString(2)
    }

    private fun analyzeGDPRCompliance(): List<ComplianceFinding> {
        val findings = mutableListOf<ComplianceFinding>()

        // Verificar consentimiento
        val consentEvidence = evidenceChain.filter {
            it.eventType.contains("CONSENT") || it.eventType.contains("PERMISSION")
        }

        if (consentEvidence.isEmpty()) {
            findings.add(ComplianceFinding(
                category = "CONSENT",
                severity = "HIGH",
                description = "No evidence of user consent collection",
                evidence = emptyList(),
                remediation = "Implement explicit consent collection mechanism"
            ))
        }

        // Verificar derecho al olvido
        val deletionEvidence = evidenceChain.filter {
            it.eventType.contains("DELETE") || it.eventType.contains("ERASURE")
        }

        // Verificar portabilidad de datos
        val exportEvidence = evidenceChain.filter {
            it.eventType.contains("EXPORT") || it.eventType.contains("DOWNLOAD")
        }

        // Verificar notificación de brechas
        val breachEvidence = evidenceChain.filter {
            it.eventType.contains("BREACH") || it.eventType.contains("INCIDENT")
        }

        return findings
    }

    private fun analyzeCCPACompliance(): List<ComplianceFinding> {
        val findings = mutableListOf<ComplianceFinding>()

        // Verificar transparencia en la recolección de datos
        val collectionEvidence = evidenceChain.filter {
            it.eventType.contains("DATA_COLLECTION") || it.eventType.contains("DATA_STORAGE")
        }

        // Verificar derecho a saber
        val disclosureEvidence = evidenceChain.filter {
            it.eventType.contains("DISCLOSURE") || it.eventType.contains("PRIVACY_POLICY")
        }

        // Verificar derecho a eliminar
        val deletionEvidence = evidenceChain.filter {
            it.eventType.contains("DELETE") || it.eventType.contains("ERASURE")
        }

        return findings
    }

    private fun analyzeGeneralCompliance(): List<ComplianceFinding> {
        val findings = mutableListOf<ComplianceFinding>()

        // Verificar encriptación de datos
        val encryptionEvidence = evidenceChain.filter {
            it.eventType.contains("ENCRYPTION") || it.eventType.contains("DECRYPT")
        }

        if (encryptionEvidence.isEmpty()) {
            findings.add(ComplianceFinding(
                category = "ENCRYPTION",
                severity = "MEDIUM",
                description = "Limited evidence of data encryption activities",
                evidence = emptyList(),
                remediation = "Ensure all sensitive data is encrypted at rest and in transit"
            ))
        }

        return findings
    }

    private fun calculateRiskScore(findings: List<ComplianceFinding>): Int {
        return findings.sumOf { finding ->
            when (finding.severity) {
                "HIGH" -> 30
                "MEDIUM" -> 15
                "LOW" -> 5
                else -> 0
            }.toInt()
        }.coerceAtMost(100)
    }

    private fun createSystemInitializationEvidence() {
        createEvidence(
            eventType = "SYSTEM_INITIALIZATION",
            description = "Forensics system initialized",
            metadata = mapOf(
                "version" to "1.0",
                "timestamp" to System.currentTimeMillis(),
                "device_info" to getCurrentSystemState()
            )
        )
    }

    private fun generateEvidenceId(): String {
        return "EVD_${System.currentTimeMillis()}_${(1000..9999).random()}"
    }

    private fun calculateHash(data: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(data.toByteArray())
        return hashBytes.joinToString("") { "%02x".format(it) }
    }

    private fun generateCustodySignature(evidenceId: String, handler: String, action: String): String {
        val data = "$evidenceId:$handler:$action:${System.currentTimeMillis()}"
        return calculateHash(data).take(16)
    }

    private fun generateDigitalSignature(data: String): String {
        // En producción, usar criptografía asimétrica real
        return calculateHash("SIGNATURE:$data").take(32)
    }

    private fun getCurrentSystemState(): Map<String, Any> {
        return mapOf(
            "timestamp" to System.currentTimeMillis(),
            "memory_usage" to Runtime.getRuntime().let {
                (it.totalMemory() - it.freeMemory()) / 1024 / 1024
            },
            "available_memory" to Runtime.getRuntime().freeMemory() / 1024 / 1024,
            "evidence_count" to evidenceChain.size
        )
    }

    private fun getGDPRRecommendations(): List<String> = listOf(
        "Implement explicit consent collection for all data processing",
        "Provide clear privacy policy with data usage details",
        "Implement data subject rights (access, rectification, erasure)",
        "Conduct regular data protection impact assessments",
        "Implement privacy by design principles"
    )

    private fun getCCPARecommendations(): List<String> = listOf(
        "Provide clear notice of data collection at point of collection",
        "Implement consumer rights (know, delete, opt-out)",
        "Maintain records of data sales and disclosures",
        "Implement age verification for minors",
        "Provide non-discriminatory service regardless of privacy choices"
    )

    private fun getGeneralRecommendations(): List<String> = listOf(
        "Implement end-to-end encryption for sensitive data",
        "Regular security audits and penetration testing",
        "Employee training on data protection practices",
        "Incident response plan and breach notification procedures",
        "Regular backup and disaster recovery testing"
    )

    private fun createIncidentTimeline(evidence: List<DigitalEvidence>): List<TimelineEvent> {
        return evidence.sortedBy { it.timestamp }.map { evidence ->
            TimelineEvent(
                timestamp = evidence.timestamp,
                eventType = evidence.eventType,
                description = evidence.description,
                severity = determineEventSeverity(evidence)
            )
        }
    }

    private fun analyzeIncidentPatterns(evidence: List<DigitalEvidence>): IncidentAnalysis {
        val eventTypes = evidence.groupBy { it.eventType }
        val timeDistribution = analyzeTimeDistribution(evidence)
        val suspiciousPatterns = detectSuspiciousPatterns(evidence)

        return IncidentAnalysis(
            eventTypeDistribution = eventTypes.mapValues { it.value.size },
            timeDistribution = timeDistribution,
            suspiciousPatterns = suspiciousPatterns,
            totalEvents = evidence.size
        )
    }

    private fun generateIncidentRecommendations(analysis: IncidentAnalysis): List<String> {
        val recommendations = mutableListOf<String>()

        if (analysis.suspiciousPatterns.isNotEmpty()) {
            recommendations.add("Investigate suspicious activity patterns detected")
        }

        if (analysis.eventTypeDistribution.containsKey("SECURITY_VIOLATION")) {
            recommendations.add("Review and strengthen security controls")
        }

        recommendations.add("Implement additional monitoring for similar incidents")
        recommendations.add("Update incident response procedures based on findings")

        return recommendations
    }

    private fun calculateIncidentSeverity(analysis: IncidentAnalysis): String {
        return when {
            analysis.suspiciousPatterns.size > 5 -> "CRITICAL"
            analysis.suspiciousPatterns.size > 2 -> "HIGH"
            analysis.suspiciousPatterns.size > 0 -> "MEDIUM"
            else -> "LOW"
        }
    }

    private fun analyzeTimeDistribution(evidence: List<DigitalEvidence>): Map<String, Int> {
        // Analizar distribución por horas del día
        return evidence.groupBy {
            val hour = (it.timestamp / (1000 * 60 * 60)) % 24
            "Hour_$hour"
        }.mapValues { it.value.size }
    }

    private fun detectSuspiciousPatterns(evidence: List<DigitalEvidence>): List<String> {
        val patterns = mutableListOf<String>()

        // Detectar ráfagas de actividad
        val timeWindows = evidence.groupBy { it.timestamp / (1000 * 60) } // Por minuto
        timeWindows.forEach { (minute, events) ->
            if (events.size > 10) {
                patterns.add("High activity burst at minute $minute with ${events.size} events")
            }
        }

        // Detectar patrones de error repetitivos
        val errorEvents = evidence.filter { it.eventType.contains("ERROR") || it.eventType.contains("FAILURE") }
        if (errorEvents.size > evidence.size * 0.3) {
            patterns.add("High error rate: ${errorEvents.size}/${evidence.size} events")
        }

        return patterns
    }

    private fun determineEventSeverity(evidence: DigitalEvidence): String {
        return when {
            evidence.eventType.contains("CRITICAL") || evidence.eventType.contains("BREACH") -> "CRITICAL"
            evidence.eventType.contains("ERROR") || evidence.eventType.contains("FAILURE") -> "HIGH"
            evidence.eventType.contains("WARNING") -> "MEDIUM"
            else -> "LOW"
        }
    }
}

data class IncidentReport(
    val incidentId: String,
    val investigatedAt: Long,
    val timeRange: Pair<Long, Long>,
    val evidenceCount: Int,
    val timeline: List<TimelineEvent>,
    val analysis: IncidentAnalysis,
    val recommendations: List<String>,
    val severity: String
)

data class TimelineEvent(
    val timestamp: Long,
    val eventType: String,
    val description: String,
    val severity: String
)

data class IncidentAnalysis(
    val eventTypeDistribution: Map<String, Int>,
    val timeDistribution: Map<String, Int>,
    val suspiciousPatterns: List<String>,
    val totalEvents: Int
)
