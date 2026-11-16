package me.keylet.app.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

enum class KdfType(val value: Int) {
    PBKDF2_SHA256(0),
    ARGON2ID(1);

    companion object {
        fun fromInt(value: Int): KdfType =
            entries.firstOrNull { it.value == value }
                ?: throw IllegalArgumentException("Unsupported KDF type: $value")
    }
}

data class KdfConfig(
    val kdf: Int = 0,
    val kdfIterations: Int = 600_000,
    val kdfMemory: Int? = null,
    val kdfParallelism: Int? = null
)

class SymmetricKey(val raw: ByteArray) {
    init {
        require(raw.size == 64) { "Expected 64-byte symmetric key, got ${raw.size}" }
    }

    val encKey: ByteArray get() = raw.copyOfRange(0, 32)
    val macKey: ByteArray get() = raw.copyOfRange(32, 64)

    fun wipe() {
        raw.fill(0)
    }
}

object KeyletCrypto {
    private val secureRandom = SecureRandom()

    fun deriveMasterKey(password: String, email: String, config: KdfConfig): ByteArray {
        val normalizedEmail = email.trim().lowercase()
        val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)
        val emailBytes = normalizedEmail.toByteArray(StandardCharsets.UTF_8)

        return when (KdfType.fromInt(config.kdf)) {
            KdfType.PBKDF2_SHA256 -> {
                require(config.kdfIterations >= 1) { "Invalid PBKDF2 iterations: ${config.kdfIterations}" }
                pbkdf2Sha256(password.toCharArray(), emailBytes, config.kdfIterations, 256)
            }
            KdfType.ARGON2ID -> {
                val salt = MessageDigest.getInstance("SHA-256").digest(emailBytes)
                val iterations = if (config.kdfIterations > 0) config.kdfIterations else 3
                val memoryMiB = config.kdfMemory ?: 64
                val parallelism = config.kdfParallelism ?: 4
                val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withSalt(salt)
                    .withIterations(iterations)
                    .withMemoryAsKB(memoryMiB * 1024)
                    .withParallelism(parallelism)
                    .build()
                val generator = Argon2BytesGenerator()
                generator.init(params)
                val out = ByteArray(32)
                generator.generateBytes(passwordBytes, out)
                out
            }
        }
    }

    fun deriveMasterPasswordHash(masterKey: ByteArray, masterPassword: String): String {
        // Bitwarden runs 1 iteration of PBKDF2-SHA256 with masterKey as key and password as salt
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(masterKey, "HmacSHA256"))
        val salt = masterPassword.toByteArray(StandardCharsets.UTF_8)
        val block = ByteArray(salt.size + 4)
        System.arraycopy(salt, 0, block, 0, salt.size)
        block[salt.size + 3] = 1
        val hash = mac.doFinal(block)
        return Base64.getEncoder().encodeToString(hash)
    }

    fun stretchKey(masterKey: ByteArray): SymmetricKey {
        val encKey = hkdfExpandSha256(masterKey, "enc".toByteArray(StandardCharsets.UTF_8), 32)
        val macKey = hkdfExpandSha256(masterKey, "mac".toByteArray(StandardCharsets.UTF_8), 32)
        return SymmetricKey(encKey + macKey)
    }

    fun hkdfExpandSha256(prk: ByteArray, info: ByteArray, lengthBytes: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val n = (lengthBytes + 31) / 32
        var prev = ByteArray(0)
        val out = ByteArray(n * 32)
        for (i in 1..n) {
            mac.reset()
            mac.update(prev)
            mac.update(info)
            mac.update(i.toByte())
            prev = mac.doFinal()
            System.arraycopy(prev, 0, out, (i - 1) * 32, 32)
        }
        return out.copyOf(lengthBytes)
    }

    fun decryptProtectedSymmetricKey(protectedKey: String, stretched: SymmetricKey): SymmetricKey {
        return SymmetricKey(decryptToBytes(protectedKey, stretched))
    }

    fun decryptToBytes(encString: String, key: SymmetricKey): ByteArray {
        val dot = encString.indexOf('.')
        require(dot > 0) { "Invalid EncString: missing encType" }
        val encType = encString.substring(0, dot).toInt()
        val parts = encString.substring(dot + 1).split('|')
        val decoder = Base64.getDecoder()

        when (encType) {
            0 -> {
                require(parts.size == 2) { "Invalid EncType 0 format" }
                val iv = decoder.decode(parts[0])
                val data = decoder.decode(parts[1])
                return aesCbcDecrypt(key.encKey, iv, data)
            }
            2 -> {
                require(parts.size == 3) { "Invalid EncType 2 format" }
                val iv = decoder.decode(parts[0])
                val data = decoder.decode(parts[1])
                val macBytes = decoder.decode(parts[2])
                val expectedMac = computeHmacSha256(key.macKey, iv, data)
                if (!MessageDigest.isEqual(macBytes, expectedMac)) {
                    throw SecurityException("MAC verification failed")
                }
                return aesCbcDecrypt(key.encKey, iv, data)
            }
            else -> throw IllegalArgumentException("Unsupported EncType: $encType")
        }
    }

    fun decryptToString(encString: String?, key: SymmetricKey): String? {
        if (encString.isNullOrEmpty()) return null
        return String(decryptToBytes(encString, key), StandardCharsets.UTF_8)
    }

    fun encryptBytes(plain: ByteArray, key: SymmetricKey): String {
        val iv = ByteArray(16)
        secureRandom.nextBytes(iv)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.encKey, "AES"), IvParameterSpec(iv))
        val ct = cipher.doFinal(plain)
        val mac = computeHmacSha256(key.macKey, iv, ct)
        val enc = Base64.getEncoder()
        return "2.${enc.encodeToString(iv)}|${enc.encodeToString(ct)}|${enc.encodeToString(mac)}"
    }

    fun encryptString(plain: String, key: SymmetricKey): String =
        encryptBytes(plain.toByteArray(StandardCharsets.UTF_8), key)

    private fun pbkdf2Sha256(
        password: CharArray,
        salt: ByteArray,
        iterations: Int,
        keyLengthBits: Int
    ): ByteArray {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password, salt, iterations, keyLengthBits)
        return factory.generateSecret(spec).encoded
    }

    private fun aesCbcDecrypt(encKey: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(encKey, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    private fun computeHmacSha256(macKey: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(macKey, "HmacSHA256"))
        mac.update(iv)
        mac.update(data)
        return mac.doFinal()
    }
}
