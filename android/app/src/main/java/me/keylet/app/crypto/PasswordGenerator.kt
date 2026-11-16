package me.keylet.app.crypto

import java.security.SecureRandom
import kotlin.math.log2
import kotlin.math.roundToInt

data class PasswordOptions(
    val length: Int = 20,
    val uppercase: Boolean = true,
    val lowercase: Boolean = true,
    val numbers: Boolean = true,
    val symbols: Boolean = true,
    val excludeAmbiguous: Boolean = false
)

object PasswordGenerator {
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!@#\$%^&*()-_=+[]{}|;:,.<>?"
    private val AMBIGUOUS = setOf('I', 'l', '1', 'O', '0', 'o')
    private val rng = SecureRandom()

    private fun filter(chars: String, exclude: Boolean): String =
        if (!exclude) chars else chars.filter { it !in AMBIGUOUS }

    fun generate(opts: PasswordOptions = PasswordOptions()): Pair<String, Int> {
        val pools = mutableListOf<String>()
        if (opts.uppercase) pools.add(filter(UPPER, opts.excludeAmbiguous))
        if (opts.lowercase) pools.add(filter(LOWER, opts.excludeAmbiguous))
        if (opts.numbers) pools.add(filter(DIGITS, opts.excludeAmbiguous))
        if (opts.symbols) pools.add(SYMBOLS)
        if (pools.isEmpty()) pools.add(filter(LOWER, opts.excludeAmbiguous))

        val length = opts.length.coerceIn(4, 128)
        val combined = pools.joinToString("")
        val chars = CharArray(length)
        var idx = 0

        for (pool in pools) {
            if (idx < length) {
                chars[idx++] = pool[rng.nextInt(pool.length)]
            }
        }
        while (idx < length) {
            chars[idx++] = combined[rng.nextInt(combined.length)]
        }
        for (i in length - 1 downTo 1) {
            val j = rng.nextInt(i + 1)
            val tmp = chars[i]
            chars[i] = chars[j]
            chars[j] = tmp
        }

        val entropy = (length * log2(combined.length.toDouble())).roundToInt()
        return String(chars) to entropy
    }
}
