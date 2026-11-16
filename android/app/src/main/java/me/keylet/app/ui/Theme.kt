package me.keylet.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

object KeyletColors {
    val BgBase = Color(0xFF0D0F13)
    val BgElevated = Color(0xFF151820)
    val BgActive = Color(0xFF232938)
    val BorderSubtle = Color(0x14FFFFFF)
    val TextPrimary = Color(0xFFF3F4F6)
    val TextSecondary = Color(0xFF9CA3AF)
    val TextMuted = Color(0xFF6B7280)
    val Accent = Color(0xFF3B82F6)
    val Success = Color(0xFF10B981)
    val Warning = Color(0xFFF59E0B)
    val Danger = Color(0xFFEF4444)
}

private val DarkPalette = darkColorScheme(
    primary = KeyletColors.Accent,
    onPrimary = Color.White,
    background = KeyletColors.BgBase,
    onBackground = KeyletColors.TextPrimary,
    surface = KeyletColors.BgElevated,
    onSurface = KeyletColors.TextPrimary,
    surfaceVariant = KeyletColors.BgActive,
    onSurfaceVariant = KeyletColors.TextSecondary,
    error = KeyletColors.Danger,
    outline = KeyletColors.BorderSubtle
)

@Composable
fun KeyletTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkPalette,
        content = content
    )
}
