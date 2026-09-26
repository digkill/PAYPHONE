package com.payphone.android.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.sp
import com.payphone.android.ui.theme.MatrixGreen
import com.payphone.android.ui.theme.MatrixGreenBright
import com.payphone.android.ui.theme.MatrixGreenDim
import com.payphone.android.ui.theme.MatrixGreenHead
import kotlinx.coroutines.delay
import kotlin.random.Random

private val GLYPHS = charArrayOf(
    'ｱ', 'ｲ', 'ｳ', 'ｴ', 'ｵ', 'ｶ', 'ｷ', 'ｸ', 'ｹ', 'ｺ', 'ｻ', 'ｼ', 'ｽ', 'ｾ', 'ｿ', 'ﾀ', 'ﾁ', 'ﾂ', 'ﾃ',
    'ﾄ', 'ﾅ', 'ﾆ', 'ﾇ', 'ﾈ', 'ﾉ', 'ﾊ', 'ﾋ', 'ﾌ', 'ﾍ', 'ﾎ', 'ﾏ', 'ﾐ', 'ﾑ', 'ﾒ', 'ﾓ', 'ﾔ', 'ﾕ', 'ﾖ',
    'ﾗ', 'ﾘ', 'ﾙ', 'ﾚ', 'ﾛ', 'ﾜ', 'ﾝ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '☎', '⌁',
)

private data class RainState(
    val cols: Int,
    val rows: Int,
    val heads: FloatArray,
    val delays: IntArray,
    val chars: CharArray,
    val glow: IntArray,
)

@Composable
fun MatrixRain(
    modifier: Modifier = Modifier,
    busy: Boolean = false,
    tickMs: Long = 48L,
) {
    val measurer = rememberTextMeasurer()
    val density = LocalDensity.current
    val cellPx = with(density) { 14.sp.toPx() }
    var frame by remember { mutableIntStateOf(0) }
    var rain by remember { mutableStateOf<RainState?>(null) }

    LaunchedEffect(busy, tickMs) {
        val rng = Random(0x9e3779b97f4a7c15UL.toLong())
        while (true) {
            delay(tickMs)
            frame++
            rain = rain?.let { state ->
                val next = state.copy(
                    chars = state.chars.copyOf(),
                    glow = state.glow.copyOf(),
                    heads = state.heads.copyOf(),
                    delays = state.delays.copyOf(),
                )
                for (index in next.glow.indices) {
                    if (next.glow[index] > 0) next.glow[index]--
                }
                for (col in 0 until next.cols) {
                    if (next.delays[col] > 0) {
                        next.delays[col] -= if (busy) 2 else 1
                        continue
                    }
                    next.heads[col] += if (busy) 1.6f else 1f
                    val row = next.heads[col].toInt()
                    if (row in 0 until next.rows) {
                        next.chars[row * next.cols + col] = GLYPHS[rng.nextInt(GLYPHS.size)]
                        next.glow[row * next.cols + col] = 12
                    }
                    if (next.heads[col] > next.rows + 14) {
                        next.heads[col] = -rng.nextInt(10).toFloat()
                        next.delays[col] = rng.nextInt(if (busy) 4 else 14)
                    }
                }
                next
            }
        }
    }

    Canvas(modifier = modifier.fillMaxSize()) {
        val cols = (size.width / cellPx).toInt().coerceAtLeast(8)
        val rows = (size.height / cellPx).toInt().coerceAtLeast(12)
        if (rain == null || rain!!.cols != cols || rain!!.rows != rows) {
            val rng = Random(0xDEADBEEFL)
            rain = RainState(
                cols = cols,
                rows = rows,
                heads = FloatArray(cols) { -rng.nextInt(rows + 6).toFloat() },
                delays = IntArray(cols) { rng.nextInt(8) },
                chars = CharArray(cols * rows) { ' ' },
                glow = IntArray(cols * rows),
            )
        }
        val state = rain ?: return@Canvas
        for (row in 0 until state.rows) {
            for (col in 0 until state.cols) {
                val index = row * state.cols + col
                val g = state.glow[index]
                if (g == 0) continue
                val color = when {
                    g >= 11 -> MatrixGreenHead
                    g >= 8 -> MatrixGreenBright
                    g >= 4 -> MatrixGreen
                    else -> MatrixGreenDim
                }
                drawText(
                    textMeasurer = measurer,
                    text = state.chars[index].toString(),
                    topLeft = Offset(col * cellPx, row * cellPx),
                    style = TextStyle(
                        fontSize = 14.sp,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        color = color,
                    ),
                )
            }
        }
    }
}

@Composable
fun MatrixTagline(text: String, modifier: Modifier = Modifier) {
    androidx.compose.material3.Text(
        text = text,
        modifier = modifier,
        style = androidx.compose.material3.MaterialTheme.typography.labelMedium,
        color = MatrixGreenDim,
    )
}
