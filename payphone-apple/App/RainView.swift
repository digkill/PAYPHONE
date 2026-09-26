import SwiftUI

// Green digital rain — the same voice as payphone-client/src/matrix.rs
// (CLI) and https_front.rs's "Follow the white rabbit." landing page.
// Purely cosmetic, exactly like on every other PAYPHONE client: it does
// not touch the protocol, the connection, or anything network-related.
//
// Lesson already paid for once on the CLI (see .cursor/memory/gotchas.md,
// "Матрица в терминале"): full-width katakana render as two terminal
// columns and desync a fixed-pitch grid. SwiftUI's Canvas measures glyphs
// by real width instead of assuming a column grid, so that specific bug
// can't recur here — but we still stick to the same half-width glyph set
// for a consistent look across CLI, Android, and this client.
struct RainView: View {
    /// 0 = idle shimmer, 1 = as intense as the tunnel-open pulse gets.
    var intensity: Double = 0

    @State private var columns: [RainColumn] = []
    @State private var lastSize: CGSize = .zero

    private static let glyphs: [Character] = Array(
        "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789"
    )

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 24.0)) { timeline in
            Canvas { context, size in
                if size != lastSize {
                    // Deferred to the next state-writable phase; Canvas
                    // itself is drawn synchronously in `body`, but this
                    // guard just stops us from ever using a stale
                    // column layout after a resize/rotation.
                    DispatchQueue.main.async { self.reflow(for: size) }
                }

                let fontSize: CGFloat = 15
                let font = Font.system(size: fontSize, weight: .medium, design: .monospaced)

                for column in columns {
                    column.draw(in: &context, font: font, fontSize: fontSize, time: timeline.date.timeIntervalSinceReferenceDate)
                }
            }
            .background(Color.black)
            .drawingGroup()
        }
        .onAppear { reflow(for: lastSize) }
    }

    private func reflow(for size: CGSize) {
        guard size.width > 0, size.height > 0 else { return }
        lastSize = size

        let columnWidth: CGFloat = 16
        let count = max(1, Int(size.width / columnWidth))

        columns = (0..<count).map { index in
            RainColumn(x: CGFloat(index) * columnWidth, height: size.height, glyphs: Self.glyphs, speedBias: intensity)
        }
    }
}

private struct RainColumn {
    let x: CGFloat
    let height: CGFloat
    let glyphs: [Character]
    let speedBias: Double

    // Deterministic-enough per-column phase/speed so the field doesn't
    // look synchronized, without needing to store mutable per-frame
    // state (Canvas draws are re-run every frame anyway).
    private let seed: Double
    private let speed: CGFloat
    private let trailLength: Int
    private let rowHeight: CGFloat = 18

    init(x: CGFloat, height: CGFloat, glyphs: [Character], speedBias: Double) {
        self.x = x
        self.height = height
        self.glyphs = glyphs
        self.speedBias = speedBias
        self.seed = Double.random(in: 0..<1000)
        self.speed = CGFloat.random(in: 60...160) * (1.0 + speedBias)
        self.trailLength = Int.random(in: 8...20)
    }

    func draw(in context: inout GraphicsContext, font: Font, fontSize: CGFloat, time: TimeInterval) {
        let rowCount = Int(height / rowHeight) + trailLength + 2
        let headRow = Int((time * Double(speed) / Double(rowHeight) + seed).truncatingRemainder(dividingBy: Double(rowCount)))

        for offset in 0..<trailLength {
            let row = headRow - offset
            guard row >= 0, row < Int(height / rowHeight) + 1 else { continue }

            let y = CGFloat(row) * rowHeight
            let fade = 1.0 - (Double(offset) / Double(trailLength))
            let glyph = glyphs[Int((time * 3 + seed + Double(row)).truncatingRemainder(dividingBy: Double(glyphs.count)))]

            let color: Color = offset == 0
                ? Color(red: 0.75, green: 1.0, blue: 0.75)
                : Color.green.opacity(max(0.08, fade))

            context.draw(
                Text(String(glyph)).font(font).foregroundColor(color),
                at: CGPoint(x: x, y: y),
                anchor: .topLeading
            )
        }
    }
}

#Preview {
    RainView(intensity: 0.3)
        .frame(width: 400, height: 700)
}
