package me.keylet.app

import me.keylet.app.crypto.KdfConfig
import me.keylet.app.crypto.KeyletCrypto
import me.keylet.app.crypto.PasswordGenerator
import me.keylet.app.crypto.PasswordOptions
import me.keylet.app.crypto.SymmetricKey
import me.keylet.app.crypto.TotpGenerator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class KeyletCryptoTest {

    @Test
    fun pbkdf2AndKeyStretchingAreDeterministic() {
        val k1 = KeyletCrypto.deriveMasterKey("correct-horse", " User@Example.COM ", KdfConfig(0, 1000))
        val k2 = KeyletCrypto.deriveMasterKey("correct-horse", "user@example.com", KdfConfig(0, 1000))
        assertArrayEquals(k1, k2)
        assertEquals(32, k1.size)

        val hash = KeyletCrypto.deriveMasterPasswordHash(k1, "correct-horse")
        assertTrue(hash.isNotBlank())

        val stretched = KeyletCrypto.stretchKey(k1)
        assertEquals(64, stretched.raw.size)
    }

    @Test
    fun argon2idDerives32ByteKey() {
        val k = KeyletCrypto.deriveMasterKey("vault-pass", "alice@example.com", KdfConfig(1, 1, 8, 1))
        assertEquals(32, k.size)
    }

    @Test
    fun encryptThenMacRoundTripAndTamperRejection() {
        val raw = ByteArray(64).also { SecureRandom().nextBytes(it) }
        val key = SymmetricKey(raw)
        val enc = KeyletCrypto.encryptString("Super secret Android entry", key)
        assertTrue(enc.startsWith("2."))
        assertEquals("Super secret Android entry", KeyletCrypto.decryptToString(enc, key))

        val parts = enc.substring(2).split('|')
        val badMac = parts[2].dropLast(2) + if (parts[2].endsWith("AA")) "BB" else "AA"
        val tampered = "2.${parts[0]}|${parts[1]}|$badMac"

        var failed = false
        try {
            KeyletCrypto.decryptToString(tampered, key)
        } catch (e: SecurityException) {
            failed = e.message?.contains("MAC") == true
        }
        assertTrue(failed)
    }

    @Test
    fun rfc6238TotpVector() {
        val uri = "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1"
        val res = TotpGenerator.generate(uri, 59_000L)
        assertEquals("94287082", res.code)
        assertEquals(1, res.remainingSeconds)
    }

    @Test
    fun passwordGeneratorRespectsLengthAndEntropy() {
        val (pw, entropy) = PasswordGenerator.generate(PasswordOptions(length = 24, excludeAmbiguous = true))
        assertEquals(24, pw.length)
        assertTrue(entropy > 100)
    }
}
