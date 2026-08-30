// Stack 6 — Kotlin/OkHttp DPIA test helpers
// Mirrors dpia_test_helpers.mjs: four plain functions, no class wrappers.
// Each test file defines its own req() inline; only shared utilities live here.

package dpia

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.security.MessageDigest

// ── Environment ───────────────────────────────────────────────────────────────

fun env(key: String, fallback: String = ""): String = System.getenv(key) ?: fallback

// ── SHA-256 ───────────────────────────────────────────────────────────────────

fun sha256Hex(input: String): String =
    MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
        .joinToString("") { "%02x".format(it) }

// ── Cognito ───────────────────────────────────────────────────────────────────

class CognitoTokenFetcher(
    private val region: String,
    private val clientId: String,
    private val password: String
) {
    private val client = OkHttpClient()

    fun fetchToken(username: String): String {
        val body = """{"AuthFlow":"USER_PASSWORD_AUTH","ClientId":"$clientId","AuthParameters":{"USERNAME":"$username","PASSWORD":"$password"}}"""
        val req = Request.Builder()
            .url("https://cognito-idp.$region.amazonaws.com/")
            .post(body.toRequestBody("application/x-amz-json-1.1".toMediaType()))
            .addHeader("X-Amz-Target", "AWSCognitoIdentityProviderService.InitiateAuth")
            .build()
        val resp = client.newCall(req).execute()
        val json = Json.parseToJsonElement(resp.body!!.string()).jsonObject
        val auth = json["AuthenticationResult"]?.jsonObject
            ?: error("Cognito failed: ${resp.body}")
        return ((auth["IdToken"] ?: auth["AccessToken"]) as JsonPrimitive).content
    }
}

// ── HTTP response ─────────────────────────────────────────────────────────────
// Plain data class — mirrors Stack 4's { status, body } object.

data class Res(val status: Int, val body: Map<String, Any?>)

// ── HTTP execution (shared by each test's inline req()) ───────────────────────

fun makeRequest(
    client: OkHttpClient,
    method: String,
    url: String,
    body: Map<String, Any?>?,
    headers: Map<String, String>
): Res {
    val rb = Request.Builder().url(url).addHeader("Content-Type", "application/json")
    headers.forEach { (k, v) -> rb.addHeader(k, v) }
    val okBody = body?.let { jsonOf(it).toRequestBody("application/json".toMediaType()) }
    val req = when (method.uppercase()) {
        "GET"    -> rb.get()
        "DELETE" -> if (okBody != null) rb.delete(okBody) else rb.delete()
        "POST"   -> rb.post(okBody ?: "{}".toRequestBody("application/json".toMediaType()))
        "PUT"    -> rb.put(okBody ?: "{}".toRequestBody("application/json".toMediaType()))
        else     -> rb.method(method, okBody)
    }.build()
    val resp = client.newCall(req).execute()
    return Res(resp.code, parseBody(resp.body?.string() ?: "{}"))
}

// ── JSON utilities ────────────────────────────────────────────────────────────

fun jsonOf(v: Any?): String = when (v) {
    null         -> "null"
    is String    -> "\"${v.replace("\\", "\\\\").replace("\"", "\\\"")}\""
    is Number, is Boolean -> v.toString()
    is Map<*, *> -> "{${v.entries.joinToString(",") { (k, w) -> "\"$k\":${jsonOf(w)}" }}}"
    is List<*>   -> "[${v.joinToString(",") { jsonOf(it) }}]"
    else         -> "\"$v\""
}

fun parseBody(json: String): Map<String, Any?> = try {
    (Json { ignoreUnknownKeys = true }.parseToJsonElement(json) as? JsonObject)
        ?.let { it.entries.associate { (k, v) -> k to v.toPlain() } } ?: emptyMap()
} catch (_: Exception) { emptyMap() }

fun JsonElement.toPlain(): Any? = when (this) {
    is JsonNull      -> null
    is JsonPrimitive -> when {
        isString              -> content
        booleanOrNull != null -> booleanOrNull
        intOrNull != null     -> intOrNull
        longOrNull != null    -> longOrNull
        doubleOrNull != null  -> doubleOrNull
        else                  -> content
    }
    is JsonObject -> entries.associate { (k, v) -> k to v.toPlain() }
    is JsonArray  -> map { it.toPlain() }
}

fun Map<String, Any?>.str(key: String): String? = when (val v = this[key]) {
    null      -> null
    is String -> v
    else      -> v.toString()
}

fun Map<String, Any?>.ledger(): Map<*, *> =
    this["ledger"] as? Map<*, *> ?: this

fun Map<String, Any?>.ledgerInt(key: String): Int =
    when (val v = ledger()[key]) {
        is Number -> v.toInt()
        is String -> v.toIntOrNull() ?: 0
        else      -> 0
    }

fun Map<String, Any?>.ledgerBool(key: String): Boolean? =
    when (val v = ledger()[key]) {
        is Boolean -> v
        is String  -> v.toBooleanStrictOrNull()
        else       -> null
    }

// ── Results ───────────────────────────────────────────────────────────────────
// Mirrors Stack 4's { stack, run, sections: [{ name, assertions: [] }] }

@Serializable
data class DPIAAssertion(
    val label: String,
    val claim: String,
    var result: String = "pending",
    var ms: Long = 0
)

@Serializable
data class DPIASection(
    val name: String,
    val assertions: MutableList<DPIAAssertion> = mutableListOf()
)

@Serializable
data class DPIAResults(
    val stack: String,
    val run: String,
    val githubRunId: String? = null,
    val timestamp: String,
    val auth: String,
    val ledger: String,
    val sections: MutableList<DPIASection> = mutableListOf()
)

private object DPIAResultStore {
    val sections: MutableList<DPIASection> = mutableListOf()

    fun section(name: String): DPIASection =
        sections.find { it.name == name }
            ?: DPIASection(name = name).also { sections.add(it) }
}

fun record(
    results: DPIAResults,
    section: String,
    label: String,
    claim: String,
    startMs: Long,
    passed: Boolean
) {
    val sec = results.sections.find { it.name == section }
        ?: DPIASection(name = section).also { results.sections.add(it) }
    val assertion = DPIAAssertion(
        label  = label,
        claim  = claim,
        result = if (passed) "pass" else "fail",
        ms     = System.currentTimeMillis() - startMs
    )
    sec.assertions.add(assertion)
    DPIAResultStore.section(section).assertions.add(assertion)
}

fun writeResults(results: DPIAResults, outDir: String, stackNum: String) {
    val output = if (results.sections.all { it.assertions.isEmpty() } && DPIAResultStore.sections.isNotEmpty()) {
        results.copy(sections = DPIAResultStore.sections)
    } else {
        results
    }
    val dir = File(outDir); dir.mkdirs()
    val outFile = File(dir, "unit-results-stack$stackNum.json")
    outFile.writeText(Json { prettyPrint = true }.encodeToString(output))
    val total  = output.sections.sumOf { it.assertions.size }
    val passed = output.sections.sumOf { s -> s.assertions.count { it.result == "pass" } }
    println("\n  Unit results: $passed/$total assertions passed")
    println("  Written: ${outFile.absolutePath}")
    for (sec in output.sections) for (a in sec.assertions) {
        println("    ${if (a.result == "pass") "✓" else "✗"} [${sec.name}] ${a.label}")
    }
}
