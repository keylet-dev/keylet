package me.keylet.app.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

object CipherType {
    const val LOGIN = 1
    const val SECURE_NOTE = 2
    const val CARD = 3
    const val IDENTITY = 4
}

@Serializable
data class EncryptedUri(
    val uri: String? = null,
    val match: Int? = null
)

@Serializable
data class EncryptedField(
    val name: String? = null,
    val value: String? = null,
    val type: Int = 0
)

@Serializable
data class EncryptedLogin(
    val username: String? = null,
    val password: String? = null,
    val totp: String? = null,
    val uris: List<EncryptedUri>? = null
)

@Serializable
data class EncryptedCard(
    val cardholderName: String? = null,
    val brand: String? = null,
    val number: String? = null,
    val expMonth: String? = null,
    val expYear: String? = null,
    val code: String? = null
)

@Serializable
data class EncryptedIdentity(
    val firstName: String? = null,
    val lastName: String? = null,
    val email: String? = null,
    val phone: String? = null,
    val username: String? = null
)

@Serializable
data class EncryptedSecureNote(
    val type: Int = 0
)

@Serializable
data class EncryptedCipher(
    val id: String,
    val folderId: String? = null,
    val type: Int,
    val name: String? = null,
    val notes: String? = null,
    val favorite: Boolean = false,
    val deletedDate: String? = null,
    val fields: List<EncryptedField>? = null,
    val login: EncryptedLogin? = null,
    val card: EncryptedCard? = null,
    val identity: EncryptedIdentity? = null,
    val secureNote: EncryptedSecureNote? = null
)

@Serializable
data class EncryptedFolder(
    val id: String,
    val name: String? = null
)

@Serializable
data class SyncProfile(
    val id: String,
    val email: String,
    val key: String
)

@Serializable
data class EncryptedSyncResponse(
    val profile: SyncProfile,
    val folders: List<EncryptedFolder> = emptyList(),
    val ciphers: List<EncryptedCipher> = emptyList()
)

@Serializable
data class TokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("expires_in") val expiresIn: Int = 3600,
    @SerialName("Key") val key: String
)

@Serializable
data class CreateCipherRequest(
    val type: Int,
    val name: String,
    val notes: String? = null,
    val favorite: Boolean = false,
    val folderId: String? = null,
    val encryptedFor: String? = null,
    val login: EncryptedLogin? = null,
    val secureNote: EncryptedSecureNote? = null,
    val card: EncryptedCard? = null
)

data class DecryptedUri(val uri: String, val match: Int? = null)
data class DecryptedField(val name: String, val value: String, val type: Int)

data class DecryptedCipher(
    val id: String,
    val folderId: String?,
    val type: Int,
    val name: String,
    val notes: String?,
    val favorite: Boolean,
    val fields: List<DecryptedField>,
    val username: String? = null,
    val password: String? = null,
    val totp: String? = null,
    val uris: List<DecryptedUri> = emptyList(),
    val cardholderName: String? = null,
    val cardBrand: String? = null,
    val cardNumber: String? = null,
    val cardExpMonth: String? = null,
    val cardExpYear: String? = null,
    val cardCode: String? = null
)

data class DecryptedFolder(val id: String, val name: String)
