package com.payphone.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

val MatrixBlack = Color(0xFF000000)
val MatrixGreen = Color(0xFF00FF41)
val MatrixGreenBright = Color(0xFF39FF14)
val MatrixGreenDim = Color(0xFF008F11)
val MatrixGreenHead = Color(0xFFE0FFE0)

private val MatrixColors = darkColorScheme(
    primary = MatrixGreen,
    onPrimary = MatrixBlack,
    secondary = MatrixGreenDim,
    background = MatrixBlack,
    onBackground = MatrixGreen,
    surface = MatrixBlack,
    onSurface = MatrixGreen,
    outline = MatrixGreenDim,
)

private val MatrixTypography = Typography(
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        color = MatrixGreen,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Normal,
        fontSize = 22.sp,
        letterSpacing = 4.sp,
        color = MatrixGreenBright,
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 12.sp,
        color = MatrixGreenDim,
    ),
)

@Composable
fun MatrixTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = MatrixColors,
        typography = MatrixTypography,
        content = content,
    )
}
