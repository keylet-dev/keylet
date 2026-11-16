package me.keylet.app.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import me.keylet.app.crypto.KdfConfig
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.URI
import java.util.concurrent.TimeUnit

class TwoFactorRequiredException(val providers: List<Int>) :
    Exception("Two-factor authentication required")

class ApiException(message: String, val statusCode: Int) : Exception(message)

object BitwardenApi {
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }
    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    fun normalizeServerUrl(raw: String): String {
        val trimmed = raw.trim().trimEnd('/')
        require(trimmed.isNotEmpty()) { "Server URL is required" }
        val withScheme = if (Regex("^[a-zA-Z][a-zA-Z\\d+\\-.]*://").containsMatchIn(trimmed)) {
            trimmed
        } else if (trimmed.startsWith("localhost") || trimmed.startsWith("127.0.0.1")) {
            "http://$trimmed"
        } else {
            "https://$trimmed"
        }
        val uri = URI(withScheme)
        val isLocal = uri.host == "localhost" || uri.host == "127.0.0.1"
        require(uri.scheme == "https" || (uri.scheme == "http" && isLocal)) {
            "Server URL must use https:// (except localhost)"
        }
        val portPart = if (uri.port > 0) ":${uri.port}" else ""
        val pathPart = uri.path?.trimEnd('/') ?: ""
        return "${uri.scheme}://${uri.host}$portPart$pathPart"
    }

    private fun parseError(body: String, status: Int): String {
        return try {
            val obj = json.parseToJsonElement(body).jsonObject
            obj["error_description"]?.jsonPrimitive?.content
                ?: obj["message"]?.jsonPrimitive?.content
                ?: obj["Message"]?.jsonPrimitive?.content
                ?: obj["ErrorModel"]?.jsonObject?.get("Message")?.jsonPrimitive?.content
                ?: "Request failed ($status)"
        } catch (_: Exception) {
            if (body.isNotBlank() && !body.trimStart().startsWith("<")) {
                body.trim().take(200)
            } else {
                "Request failed ($status)"
            }
        }
    }

    suspend fun prelogin(serverUrl: String, email: String): KdfConfig = withContext(Dispatchers.IO) {
        val base = normalizeServerUrl(serverUrl)
        val payload = """{"email":"${email.trim().lowercase()}"}"""
        val req = Request.Builder()
            .url("$base/identity/accounts/prelogin")
            .post(payload.toRequestBody(jsonMedia))
            .header("Accept", "application/json")
            .build()

        client.newCall(req).execute().use { res ->
            val body = res.body?.string().orEmpty()
            if (!res.isSuccessful) throw ApiException(parseError(body, res.code), res.code)
            val obj = json.parseToJsonElement(body).jsonObject
            KdfConfig(
                kdf = (obj["kdf"] ?: obj["Kdf"])?.jsonPrimitive?.intOrNull ?: 0,
                kdfIterations = (obj["kdfIterations"] ?: obj["KdfIterations"])?.jsonPrimitive?.intOrNull ?: 600_000,
                kdfMemory = (obj["kdfMemory"] ?: obj["KdfMemory"])?.jsonPrimitive?.intOrNull,
                kdfParallelism = (obj["kdfParallelism"] ?: obj["KdfParallelism"])?.jsonPrimitive?.intOrNull
            )
        }
    }

    suspend fun loginWithPassword(
        serverUrl: String,
        email: String,
        masterPasswordHash: String,
        deviceId: String,
        twoFactorProvider: Int? = null,
        twoFactorToken: String? = null
    ): TokenResponse = withContext(Dispatchers.IO) {
        val base = normalizeServerUrl(serverUrl)
        val form = FormBody.Builder()
            .add("grant_type", "password")
            .add("username", email.trim().lowercase())
            .add("password", masterPasswordHash)
            .add("scope", "api offline_access")
            .add("client_id", "mobile")
            .add("deviceType", "0")
            .add("deviceIdentifier", deviceId)
            .add("deviceName", "Keylet Android")

        if (twoFactorProvider != null && !twoFactorToken.isNullOrBlank()) {
            form.add("twoFactorProvider", twoFactorProvider.toString())
            form.add("twoFactorToken", twoFactorToken.trim())
            form.add("twoFactorRemember", "1")
        }

        val req = Request.Builder()
            .url("$base/identity/connect/token")
            .post(form.build())
            .header("Accept", "application/json")
            .build()

        client.newCall(req).execute().use { res ->
            val body = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                try {
                    val obj = json.parseToJsonElement(body).jsonObject
                    val providers = obj["TwoFactorProviders"]?.jsonArray?.mapNotNull { it.jsonPrimitive.intOrNull }
                    if (!providers.isNullOrEmpty()) throw TwoFactorRequiredException(providers)
                    val providers2 = obj["TwoFactorProviders2"]?.jsonObject?.keys?.mapNotNull { it.toIntOrNull() }
                    if (!providers2.isNullOrEmpty()) throw TwoFactorRequiredException(providers2)
                } catch (e: TwoFactorRequiredException) {
                    throw e
                } catch (_: Exception) {
                }
                throw ApiException(parseError(body, res.code), res.code)
            }
            json.decodeFromString<TokenResponse>(body)
        }
    }

    suspend fun refreshToken(serverUrl: String, refreshToken: String): TokenResponse =
        withContext(Dispatchers.IO) {
            val base = normalizeServerUrl(serverUrl)
            val form = FormBody.Builder()
                .add("grant_type", "refresh_token")
                .add("refresh_token", refreshToken)
                .add("client_id", "mobile")
                .build()
            val req = Request.Builder()
                .url("$base/identity/connect/token")
                .post(form)
                .header("Accept", "application/json")
                .build()
            client.newCall(req).execute().use { res ->
                val body = res.body?.string().orEmpty()
                if (!res.isSuccessful) throw ApiException(parseError(body, res.code), res.code)
                json.decodeFromString<TokenResponse>(body)
            }
        }

    suspend fun syncVault(serverUrl: String, accessToken: String): EncryptedSyncResponse =
        withContext(Dispatchers.IO) {
            val base = normalizeServerUrl(serverUrl)
            val req = Request.Builder()
                .url("$base/api/sync?excludeDomains=true")
                .get()
                .header("Authorization", "Bearer $accessToken")
                .header("Accept", "application/json")
                .build()
            client.newCall(req).execute().use { res ->
                val body = res.body?.string().orEmpty()
                if (!res.isSuccessful) throw ApiException(parseError(body, res.code), res.code)
                json.decodeFromString<EncryptedSyncResponse>(body)
            }
        }

    private fun extractJwtSub(token: String): String? = runCatching {
        val parts = token.split('.')
        if (parts.size < 2) return null
        val decoded = android.util.Base64.decode(
            parts[1],
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
        )
        val obj = json.parseToJsonElement(String(decoded, Charsets.UTF_8)).jsonObject
        obj["sub"]?.jsonPrimitive?.content?.takeIf { it.isNotBlank() }
    }.getOrNull()

    suspend fun createCipher(
        serverUrl: String,
        accessToken: String,
        payload: CreateCipherRequest
    ): EncryptedCipher = withContext(Dispatchers.IO) {
        val base = normalizeServerUrl(serverUrl)
        val finalPayload = if (payload.encryptedFor == null) {
            payload.copy(encryptedFor = extractJwtSub(accessToken))
        } else {
            payload
        }
        val bodyStr = json.encodeToString(CreateCipherRequest.serializer(), finalPayload)
        val req = Request.Builder()
            .url("$base/api/ciphers")
            .post(bodyStr.toRequestBody(jsonMedia))
            .header("Authorization", "Bearer $accessToken")
            .header("Accept", "application/json")
            .build()
        client.newCall(req).execute().use { res ->
            val body = res.body?.string().orEmpty()
            if (!res.isSuccessful) throw ApiException(parseError(body, res.code), res.code)
            json.decodeFromString<EncryptedCipher>(body)
        }
    }

    suspend fun updateCipher(
        serverUrl: String,
        accessToken: String,
        cipherId: String,
        payload: CreateCipherRequest
    ): EncryptedCipher = withContext(Dispatchers.IO) {
        val base = normalizeServerUrl(serverUrl)
        val finalPayload = if (payload.encryptedFor == null) {
            payload.copy(encryptedFor = extractJwtSub(accessToken))
        } else {
            payload
        }
        val bodyStr = json.encodeToString(CreateCipherRequest.serializer(), finalPayload)
        val req = Request.Builder()
            .url("$base/api/ciphers/$cipherId")
            .put(bodyStr.toRequestBody(jsonMedia))
            .header("Authorization", "Bearer $accessToken")
            .header("Accept", "application/json")
            .build()
        client.newCall(req).execute().use { res ->
            val body = res.body?.string().orEmpty()
            if (!res.isSuccessful) throw ApiException(parseError(body, res.code), res.code)
            json.decodeFromString<EncryptedCipher>(body)
        }
    }

    suspend fun deleteCipher(serverUrl: String, accessToken: String, cipherId: String) =
        withContext(Dispatchers.IO) {
            val base = normalizeServerUrl(serverUrl)
            val req = Request.Builder()
                .url("$base/api/ciphers/$cipherId")
                .delete()
                .header("Authorization", "Bearer $accessToken")
                .build()
            client.newCall(req).execute().use { res ->
                val body = res.body?.string().orEmpty()
                if (!res.isSuccessful) throw ApiException(parseError(body, res.code), res.code)
            }
        }
}
