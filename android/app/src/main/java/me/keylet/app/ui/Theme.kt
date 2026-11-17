package me.keylet.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

object KeyletColors {
    val BgBase = Color(0xFF0E1117)
    val BgTop = Color(0xFF141821)
    val BgElevated = Color(0x0EFFFFFF)
    val BgActive = Color(0x2B3B82F6)
    val BorderSubtle = Color(0x18FFFFFF)
    val BorderAccent = Color(0x473B82F6)
    val TextPrimary = Color(0xFFF3F4F6)
    val TextSecondary = Color(0xFF9CA3AF)
    val TextMuted = Color(0xFF6B7280)
    val Accent = Color(0xFF3B82F6)
    val AccentLight = Color(0xFF60A5FA)
    val Success = Color(0xFF34D399)
    val Warning = Color(0xFFF59E0B)
    val Danger = Color(0xFFEF4444)
}

private val DarkPalette = darkColorScheme(
    primary = KeyletColors.Accent,
    onPrimary = Color.White,
    background = KeyletColors.BgBase,
    onBackground = KeyletColors.TextPrimary,
    surface = Color(0xFF151820),
    onSurface = KeyletColors.TextPrimary,
    surfaceVariant = Color(0xFF1E2430),
    onSurfaceVariant = KeyletColors.TextSecondary,
    error = KeyletColors.Danger,
    outline = KeyletColors.BorderSubtle
)

@Composable
fun KeyletTheme(
    content: @Composable () -> Unit
) {
    // Screens use a fixed dark backdrop and dark-theme tokens, so Material
    // controls must use the same palette regardless of the system theme.
    MaterialTheme(
        colorScheme = DarkPalette,
        content = content
    )
}

@Composable
fun KeyletGlassBackdrop(
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit
) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(KeyletColors.BgTop, KeyletColors.BgBase)
                )
            )
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        Color(0x243B82F6),
                        Color.Transparent
                    ),
                    center = Offset(size.width * 0.5f, 0f),
                    radius = size.width * 0.85f
                ),
                center = Offset(size.width * 0.5f, 0f),
                radius = size.width * 0.85f
            )
        }
        content()
    }
}

@Composable
fun KeyletLogo(size: Dp = 40.dp) {
    val radius = size * 0.24f
    Box(
        modifier = Modifier
            .size(size)
            .clip(RoundedCornerShape(radius))
            .background(
                Brush.linearGradient(
                    listOf(Color(0xFF3B82F6), Color(0xFF1D4ED8))
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.size(size * 0.56f)) {
            val s = this.size.width / 24f
            val stroke = 2.5f * s
            drawCircle(
                color = Color.White,
                radius = 4.5f * s,
                center = Offset(7.5f * s, 15.5f * s),
                style = Stroke(width = stroke)
            )
            drawLine(
                color = Color.White,
                start = Offset(21f * s, 2f * s),
                end = Offset(11.4f * s, 11.6f * s),
                strokeWidth = stroke,
                cap = StrokeCap.Round
            )
            drawLine(
                color = Color.White,
                start = Offset(15.5f * s, 7.5f * s),
                end = Offset(18.5f * s, 10.5f * s),
                strokeWidth = stroke,
                cap = StrokeCap.Round
            )
            drawLine(
                color = Color.White,
                start = Offset(18.5f * s, 10.5f * s),
                end = Offset(22f * s, 7f * s),
                strokeWidth = stroke,
                cap = StrokeCap.Round
            )
            drawLine(
                color = Color.White,
                start = Offset(22f * s, 7f * s),
                end = Offset(19f * s, 4f * s),
                strokeWidth = stroke,
                cap = StrokeCap.Round
            )
        }
    }
}
