package me.keylet.app.data

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import me.keylet.app.crypto.KdfConfig
import me.keylet.app.crypto.KeyletCrypto
import me.keylet.app.crypto.SymmetricKey
import java.net.URI
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher

enum class VaultAuthState {
    LOGGED_OUT,
    LOCKED,
    UNLOCKED
}

@Serializable
data class StoredAccount(
    val serverUrl: String,
    val email: String,
    val deviceId: String,
    val kdf: Int,
    val kdfIterations: Int,
    val kdfMemory: Int? = null,
    val kdfParallelism: Int? = null,
    val protectedKey: String,
    val lastSyncAt: Long? = null,
    val biometricEnabled: Boolean = false,
    val biometricWrappedKeyB64: String? = null,
    val biometricIvB64: String? = null
)

data class VaultUiState(
    val authState: VaultAuthState = VaultAuthState.LOGGED_OUT,
    val serverUrl: String? = null,
    val email: String? = null,
    val lastSyncAt: Long? = null,
    val biometricEnabled: Boolean = false,
    val ciphers: List<DecryptedCipher> = emptyList(),
    val folders: List<DecryptedFolder> = emptyList()
)

class VaultRepository private constructor(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("keylet_vault", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

    private var memSymKey: SymmetricKey? = null
    private var memAccessToken: String? = null
    private var memRefreshToken: String? = null

    private val _state = MutableStateFlow(VaultUiState())
    val state: StateFlow<VaultUiState> = _state.asStateFlow()

    init {
        refreshStateFromDisk()
    }

    private fun readAccount(): StoredAccount? {
        val raw = prefs.getString("account", null) ?: return null
        return runCatching { json.decodeFromString<StoredAccount>(raw) }.getOrNull()
    }

    private fun saveAccount(account: StoredAccount) {
        prefs.edit().putString("account", json.encodeToString(StoredAccount.serializer(), account)).apply()
    }

    private fun readSnapshot(): EncryptedSyncResponse? {
        val raw = prefs.getString("snapshot", null) ?: return null
        return runCatching { json.decodeFromString<EncryptedSyncResponse>(raw) }.getOrNull()
    }

    private fun saveSnapshot(snapshot: EncryptedSyncResponse) {
        prefs.edit().putString("snapshot", json.encodeToString(EncryptedSyncResponse.serializer(), snapshot)).apply()
    }

    private fun refreshStateFromDisk(
        ciphers: List<DecryptedCipher> = emptyList(),
        folders: List<DecryptedFolder> = emptyList()
    ) {
        val account = readAccount()
        _state.value = if (account == null) {
            VaultUiState(authState = VaultAuthState.LOGGED_OUT)
        } else {
            VaultUiState(
                authState = if (memSymKey != null) VaultAuthState.UNLOCKED else VaultAuthState.LOCKED,
                serverUrl = account.serverUrl,
                email = account.email,
                lastSyncAt = account.lastSyncAt,
                biometricEnabled = account.biometricEnabled && account.biometricWrappedKeyB64 != null,
                ciphers = if (memSymKey != null) ciphers else emptyList(),
                folders = if (memSymKey != null) folders else emptyList()
            )
        }
    }

    suspend fun login(
        serverUrl: String,
        email: String,
        masterPassword: String,
        twoFactorProvider: Int? = null,
        twoFactorToken: String? = null
    ) = withContext(Dispatchers.Default) {
        val normalizedUrl = BitwardenApi.normalizeServerUrl(serverUrl)
        val normalizedEmail = email.trim().lowercase()
        val existing = readAccount()
        val deviceId = existing?.deviceId ?: UUID.randomUUID().toString()

        val kdfConfig = BitwardenApi.prelogin(normalizedUrl, normalizedEmail)
        val masterKey = KeyletCrypto.deriveMasterKey(masterPassword, normalizedEmail, kdfConfig)
        val pwHash = KeyletCrypto.deriveMasterPasswordHash(masterKey, masterPassword)

        val tokenRes = BitwardenApi.loginWithPassword(
            normalizedUrl,
            normalizedEmail,
            pwHash,
            deviceId,
            twoFactorProvider,
            twoFactorToken
        )

        val stretched = KeyletCrypto.stretchKey(masterKey)
        val symKey = KeyletCrypto.decryptProtectedSymmetricKey(tokenRes.key, stretched)

        memSymKey = symKey
        memAccessToken = tokenRes.accessToken
        memRefreshToken = tokenRes.refreshToken

        val account = StoredAccount(
            serverUrl = normalizedUrl,
            email = normalizedEmail,
            deviceId = deviceId,
            kdf = kdfConfig.kdf,
            kdfIterations = kdfConfig.kdfIterations,
            kdfMemory = kdfConfig.kdfMemory,
            kdfParallelism = kdfConfig.kdfParallelism,
            protectedKey = tokenRes.key,
            lastSyncAt = null
        )
        saveAccount(account)
        performSync(account, symKey)
    }

    suspend fun unlock(masterPassword: String) = withContext(Dispatchers.Default) {
        val account = readAccount() ?: error("No logged-in account")
        val kdf = KdfConfig(account.kdf, account.kdfIterations, account.kdfMemory, account.kdfParallelism)
        val masterKey = KeyletCrypto.deriveMasterKey(masterPassword, account.email, kdf)
        val stretched = KeyletCrypto.stretchKey(masterKey)
        val symKey = KeyletCrypto.decryptProtectedSymmetricKey(account.protectedKey, stretched)

        memSymKey = symKey

        if (memAccessToken == null) {
            runCatching {
                val pwHash = KeyletCrypto.deriveMasterPasswordHash(masterKey, masterPassword)
                val tok = BitwardenApi.loginWithPassword(account.serverUrl, account.email, pwHash, account.deviceId)
                memAccessToken = tok.accessToken
                memRefreshToken = tok.refreshToken
            }
        }

        val snapshot = readSnapshot()
        if (snapshot != null) {
            val (ciphers, folders) = decryptSnapshot(snapshot, symKey)
            refreshStateFromDisk(ciphers, folders)
        } else {
            refreshStateFromDisk()
        }
    }

    fun getBiometricDecryptCipher(): Cipher? {
        val account = readAccount() ?: return null
        val iv = account.biometricIvB64 ?: return null
        return runCatching { BiometricKeyStore.getDecryptCipher(iv) }.getOrNull()
    }

    suspend fun unlockWithBiometricCipher(cipher: Cipher) = withContext(Dispatchers.Default) {
        val account = readAccount() ?: error("No logged-in account")
        val wrappedB64 = account.biometricWrappedKeyB64 ?: error("Biometric unlock not enabled")
        val rawSym = cipher.doFinal(Base64.getDecoder().decode(wrappedB64))
        val symKey = SymmetricKey(rawSym)
        memSymKey = symKey
        val snapshot = readSnapshot()
        if (snapshot != null) {
            val (ciphers, folders) = decryptSnapshot(snapshot, symKey)
            refreshStateFromDisk(ciphers, folders)
        } else {
            refreshStateFromDisk()
        }
    }

    fun enableBiometric(cipher: Cipher) {
        val symKey = memSymKey ?: error("Vault is locked")
        val account = readAccount() ?: error("No account")
        val encrypted = cipher.doFinal(symKey.raw)
        val enc = Base64.getEncoder()
        saveAccount(
            account.copy(
                biometricEnabled = true,
                biometricWrappedKeyB64 = enc.encodeToString(encrypted),
                biometricIvB64 = enc.encodeToString(cipher.iv)
            )
        )
        refreshStateFromDisk(_state.value.ciphers, _state.value.folders)
    }

    fun disableBiometric() {
        val account = readAccount() ?: return
        BiometricKeyStore.deleteKey()
        saveAccount(
            account.copy(
                biometricEnabled = false,
                biometricWrappedKeyB64 = null,
                biometricIvB64 = null
            )
        )
        refreshStateFromDisk(_state.value.ciphers, _state.value.folders)
    }

    suspend fun sync() = withContext(Dispatchers.Default) {
        val account = readAccount() ?: error("Not logged in")
        val symKey = memSymKey ?: error("Vault is locked")
        performSync(account, symKey)
    }

    private suspend fun performSync(account: StoredAccount, symKey: SymmetricKey) {
        val token = memAccessToken ?: error("No active session token; re-unlock with Master Password")
        val syncRes = try {
            BitwardenApi.syncVault(account.serverUrl, token)
        } catch (e: ApiException) {
            val refresh = memRefreshToken ?: throw e
            val refreshed = BitwardenApi.refreshToken(account.serverUrl, refresh)
            memAccessToken = refreshed.accessToken
            if (refreshed.refreshToken != null) memRefreshToken = refreshed.refreshToken
            BitwardenApi.syncVault(account.serverUrl, refreshed.accessToken)
        }
        saveSnapshot(syncRes)
        val updated = account.copy(lastSyncAt = System.currentTimeMillis())
        saveAccount(updated)
        val (ciphers, folders) = decryptSnapshot(syncRes, symKey)
        refreshStateFromDisk(ciphers, folders)
    }

    suspend fun saveCipher(request: CreateCipherRequest, cipherId: String? = null) =
        withContext(Dispatchers.Default) {
            val account = readAccount() ?: error("Not logged in")
            val symKey = memSymKey ?: error("Vault is locked")
            val token = memAccessToken ?: error("Session token unavailable; unlock with Master Password")
            if (cipherId == null) {
                BitwardenApi.createCipher(account.serverUrl, token, request)
            } else {
                BitwardenApi.updateCipher(account.serverUrl, token, cipherId, request)
            }
            performSync(account, symKey)
        }

    suspend fun deleteCipher(cipherId: String) = withContext(Dispatchers.Default) {
        val account = readAccount() ?: error("Not logged in")
        val symKey = memSymKey ?: error("Vault is locked")
        val token = memAccessToken ?: error("Session token unavailable; unlock with Master Password")
        BitwardenApi.deleteCipher(account.serverUrl, token, cipherId)
        performSync(account, symKey)
    }

    fun getSymmetricKeyOrThrow(): SymmetricKey = memSymKey ?: error("Vault is locked")

    fun lock() {
        memSymKey?.wipe()
        memSymKey = null
        memAccessToken = null
        memRefreshToken = null
        refreshStateFromDisk()
    }

    fun logout() {
        lock()
        BiometricKeyStore.deleteKey()
        prefs.edit().clear().apply()
        refreshStateFromDisk()
    }

    fun findMatchesForAutofill(packageName: String?, webDomain: String?): List<DecryptedCipher> {
        val logins = _state.value.ciphers.filter { it.type == CipherType.LOGIN }
        if (logins.isEmpty()) return emptyList()

        return logins.filter { cipher ->
            cipher.uris.any { u ->
                val uriLower = u.uri.lowercase()
                val pkgMatch = !packageName.isNullOrBlank() &&
                    uriLower == "androidapp://${packageName.lowercase()}"
                val domainMatch = !webDomain.isNullOrBlank() && runCatching {
                    val host = URI(if (uriLower.contains("://")) uriLower else "https://$uriLower").host
                    host != null && (host.equals(webDomain, true) || host.endsWith(".${webDomain.lowercase()}") || webDomain.lowercase().endsWith(".$host"))
                }.getOrDefault(false)
                pkgMatch || domainMatch
            }
        }
    }

    private fun decryptSnapshot(
        sync: EncryptedSyncResponse,
        key: SymmetricKey
    ): Pair<List<DecryptedCipher>, List<DecryptedFolder>> {
        val folders = sync.folders.map {
            DecryptedFolder(
                id = it.id,
                name = KeyletCrypto.decryptToString(it.name, key) ?: "Untitled"
            )
        }
        val ciphers = sync.ciphers
            .filter { it.deletedDate == null }
            .map { c ->
                val fields = c.fields.orEmpty().map { f ->
                    DecryptedField(
                        name = KeyletCrypto.decryptToString(f.name, key).orEmpty(),
                        value = KeyletCrypto.decryptToString(f.value, key).orEmpty(),
                        type = f.type
                    )
                }
                val uris = c.login?.uris.orEmpty().mapNotNull { u ->
                    val dec = KeyletCrypto.decryptToString(u.uri, key)
                    if (dec.isNullOrBlank()) null else DecryptedUri(dec, u.match)
                }
                DecryptedCipher(
                    id = c.id,
                    folderId = c.folderId,
                    type = c.type,
                    name = KeyletCrypto.decryptToString(c.name, key) ?: "Untitled",
                    notes = KeyletCrypto.decryptToString(c.notes, key),
                    favorite = c.favorite,
                    fields = fields,
                    username = KeyletCrypto.decryptToString(c.login?.username, key),
                    password = KeyletCrypto.decryptToString(c.login?.password, key),
                    totp = KeyletCrypto.decryptToString(c.login?.totp, key),
                    uris = uris,
                    cardholderName = KeyletCrypto.decryptToString(c.card?.cardholderName, key),
                    cardBrand = KeyletCrypto.decryptToString(c.card?.brand, key),
                    cardNumber = KeyletCrypto.decryptToString(c.card?.number, key),
                    cardExpMonth = KeyletCrypto.decryptToString(c.card?.expMonth, key),
                    cardExpYear = KeyletCrypto.decryptToString(c.card?.expYear, key),
                    cardCode = KeyletCrypto.decryptToString(c.card?.code, key)
                )
            }
            .sortedWith(compareByDescending<DecryptedCipher> { it.favorite }.thenBy { it.name.lowercase() })

        return ciphers to folders
    }

    companion object {
        @Volatile
        private var instance: VaultRepository? = null

        fun get(context: Context): VaultRepository =
            instance ?: synchronized(this) {
                instance ?: VaultRepository(context).also { instance = it }
            }
    }
}
