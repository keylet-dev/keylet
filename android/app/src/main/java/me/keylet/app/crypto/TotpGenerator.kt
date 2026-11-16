package me.keylet.app.crypto

import java.net.URI
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

data class TotpResult(
    val code: String,
    val remainingSeconds: Int,
    val period: Int
)

object TotpGenerator {
    private const val BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun decodeBase32(input: String): ByteArray {
        val cleaned = input.replace(Regex("[\\s\\-=]+"), "").uppercase()
        require(cleaned.isNotEmpty()) { "Empty Base32 secret" }
        var bits = 0
        var value = 0
        val out = ArrayList<Byte>(cleaned.length * 5 / 8)
        for (ch in cleaned) {
            val idx = BASE32.indexOf(ch)
            require(idx >= 0) { "Invalid Base32 character: $ch" }
            value = (value shl 5) or idx
            bits += 5
            if (bits >= 8) {
                out.add(((value ushr (bits - 8)) and 0xff).toByte())
                bits -= 8
            }
        }
        return out.toByteArray()
    }

    fun generate(secretOrUri: String, timestampMs: Long = System.currentTimeMillis()): TotpResult {
        val trimmed = secretOrUri.trim()
        var secretBytes: ByteArray
        var period = 30
        var digits = 6
        var algorithm = "HmacSHA1"

        if (trimmed.lowercase().startsWith("otpauth://")) {
            val uri = URI(trimmed)
            val params = (uri.rawQuery ?: "").split('&')
                .mapNotNull {
                    val eq = it.indexOf('=')
                    if (eq > 0) it.substring(0, eq).lowercase() to it.substring(eq + 1) else null
                }
                .toMap()
            val secretParam = params["secret"] ?: throw IllegalArgumentException("Missing secret in otpauth URI")
            secretBytes = decodeBase32(secretParam)
            period = (params["period"]?.toIntOrNull() ?: 30).coerceAtLeast(1)
            digits = (params["digits"]?.toIntOrNull() ?: 6).coerceIn(4, 10)
            algorithm = when (params["algorithm"]?.uppercase()) {
                "SHA256", "SHA-256" -> "HmacSHA256"
                "SHA512", "SHA-512" -> "HmacSHA512"
                else -> "HmacSHA1"
            }
        } else {
            secretBytes = decodeBase32(trimmed)
        }

        val epochSeconds = timestampMs / 1000L
        val counter = epochSeconds / period
        val remaining = (period - (epochSeconds % period)).toInt()

        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(secretBytes, algorithm))
        val hmac = mac.doFinal(counterBytes)

        val offset = hmac.last().toInt() and 0x0f
        val binary =
            ((hmac[offset].toInt() and 0x7f) shl 24) or
                ((hmac[offset + 1].toInt() and 0xff) shl 16) or
                ((hmac[offset + 2].toInt() and 0xff) shl 8) or
                (hmac[offset + 3].toInt() and 0xff)

        val mod = 10.0.pow(digits).toInt()
        val code = (binary % mod).toString().padStart(digits, '0')
        return TotpResult(code = code, remainingSeconds = remaining, period = period)
    }
}
