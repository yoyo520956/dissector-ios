import SwiftUI

// 代码页签：类转储 / Swift 元数据 / 符号 / 反汇编 / Hex（专业层）

struct CodeTab: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var mode = 0

    var body: some View {
        VStack(spacing: 0) {
            Picker("视图", selection: $mode) {
                Text("类转储").tag(0)
                Text("Swift").tag(1)
                Text("符号").tag(2)
                Text("汇编").tag(3)
                Text("Hex").tag(4)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            switch mode {
            case 0: ObjCDumpView(engine: engine)
            case 1: SwiftMetaView(engine: engine)
            case 2: ClassesTab(engine: engine)
            case 3: DisasmTab(engine: engine)
            default: HexView(engine: engine)
            }
        }
    }
}

// MARK: - Hex 查看器（专业功能：任意地址 16 进制 + ASCII 双栏）

struct HexView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var addrText: String = ""
    @State private var baseVA: UInt64 = 0
    @State private var page = 0
    private let rows = 24

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                TextField("地址 (0x…)", text: $addrText)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.asciiCapable)
                    .font(.system(.footnote, design: .monospaced))
                    .onSubmit { jump() }
                Button("跳转") { jump() }
                    .buttonStyle(.bordered)
            }
            .padding(.horizontal, 12)
            .padding(.top, 8)

            HStack {
                Text(String(format: "0x%llX", baseVA))
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer()
                Button { page = max(0, page - 1); load() } label: {
                    Image(systemName: "chevron.left")
                }.disabled(page == 0)
                Text("页 \(page + 1)").font(.caption2)
                Button { page += 1; load() } label: {
                    Image(systemName: "chevron.right")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)

            if let d = data {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(0..<(d.count / 16 + (d.count % 16 > 0 ? 1 : 0)), id: \.self) { r in
                            hexRow(d, row: r)
                        }
                    }
                    .padding(.horizontal, 10)
                }
            } else {
                ContentUnavailableView("无数据", systemImage: "number",
                    description: Text("输入 VA 地址（如 0x100000000），或先完成分析"))
            }
        }
        .onAppear { load() }
    }

    private var data: Data? {
        engine.hexData(atVA: baseVA, count: rows * 16)
    }

    private func load() {
        baseVA = UInt64(page) * UInt64(rows * 16)
    }

    private func jump() {
        var t = addrText.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("0x") || t.hasPrefix("0X") { t = String(t.dropFirst(2)) }
        guard let va = UInt64(t, radix: 16) else { return }
        baseVA = va
        page = Int(va / UInt64(rows * 16))
    }

    @ViewBuilder
    private func hexRow(_ d: Data, row: Int) -> some View {
        let s = row * 16
        let e = min(s + 16, d.count)
        let chunk = [UInt8](d[s..<e])
        HStack(spacing: 10) {
            Text(String(format: "%08X", Int(baseVA) + s))
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.blue)
            Text(chunk.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " "))
                .font(.system(.caption2, design: .monospaced))
            Text(chunk.count > 8 ? chunk[8...].map { String(format: "%02X", $0) }.joined(separator: " ") : "  ")
                .font(.system(.caption2, design: .monospaced))
            Spacer(minLength: 4)
            Text(chunk.map { b in
                (b >= 0x20 && b < 0x7F) ? String(UnicodeScalar(b)) : "."
            }.joined())
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }
}
