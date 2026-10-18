import SwiftUI

// MARK: - 符号页：ObjC 类名 / 方法选择器 / Swift 还原符号 / Mach-O 符号表

struct ClassesTab: View {
    @ObservedObject var engine: AnalysisEngine

    var body: some View {
        NavigationStack {
            Group {
                if engine.phase != .done {
                    VStack(spacing: 12) {
                        Image(systemName: "c.circle")
                            .font(.system(size: 40))
                            .foregroundStyle(.blue.gradient)
                        Text("导入 IPA 后可查看符号")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    SymbolListView(engine: engine)
                }
            }
            .navigationTitle("符号")
            .navigationBarTitleDisplayMode(.inline)
            .background(Color(.systemGroupedBackground))
        }
    }
}

struct SymbolListView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var query = ""

    // 后台过滤结果（61 万符号禁每帧 filter）
    @State private var classes: [String] = []
    @State private var methods: [String] = []
    @State private var swiftNames: [String] = []
    @State private var machSymbols: [MachSymbol] = []

    private func recompute() async {
        let q = query
        try? await Task.sleep(nanoseconds: 220_000_000)
        guard !Task.isCancelled, q == query else { return }
        let cls = engine.result.classNames
        let mth = engine.result.methodNames
        let sw = engine.result.swiftSymbols
        let syms = engine.result.symbolsFull
        let q2 = q.lowercased()
        let out = await Task.detached(priority: .userInitiated) { () -> ([String], [String], [String], [MachSymbol]) in
            func f(_ list: [String], _ cap: Int) -> [String] {
                q2.isEmpty ? Array(list.prefix(cap))
                    : Array(list.filter { $0.lowercased().contains(q2) }.prefix(cap))
            }
            let ms = q2.isEmpty ? Array(syms.prefix(800))
                : Array(syms.filter { $0.name.lowercased().contains(q2) }.prefix(800))
            return (f(cls, 600), f(mth, 600), f(sw, 600), ms)
        }.value
        guard q == query, !Task.isCancelled else { return }
        classes = out.0; methods = out.1; swiftNames = out.2; machSymbols = out.3
    }

    var body: some View {
        List {
            Section {
                NavigationLink {
                    ObjCDumpView(engine: engine)
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "doc.text.below.ecg")
                            .foregroundStyle(.blue)
                            .font(.title3)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("ObjC 类完整转储")
                                .font(.footnote.weight(.semibold))
                            Text("class-dump 风格：类/属性/方法完整签名，可导出 .h")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                NavigationLink {
                    SwiftMetaView(engine: engine)
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "swift")
                            .foregroundStyle(.orange)
                            .font(.title3)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Swift 元数据深解")
                                .font(.footnote.weight(.semibold))
                            Text("类型/字段完整解析（struct/class/enum + 属性类型）")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            if !swiftNames.isEmpty {
                Section("Swift 符号（已还原 · \(engine.result.swiftSymbols.count) 条）") {
                    ForEach(swiftNames, id: \.self) { s in
                        Text(s)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
            if !classes.isEmpty {
                Section("ObjC 类名 (\(engine.result.classNames.count))") {
                    ForEach(classes, id: \.self) { s in
                        Text(s)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
            if !methods.isEmpty {
                Section("ObjC 方法选择器 (\(engine.result.methodNames.count))") {
                    ForEach(methods, id: \.self) { s in
                        Text(s)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }
            if !machSymbols.isEmpty {
                Section("Mach-O 符号表 (\(engine.result.symbolsFull.count) 条，显示前 \(machSymbols.count))") {
                    ForEach(machSymbols) { sym in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(sym.name)
                                .font(.caption.monospaced())
                                .lineLimit(2)
                                .textSelection(.enabled)
                            Text("\(sym.kind) · \(String(format: "0x%llX", sym.value))")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            if classes.isEmpty && methods.isEmpty && machSymbols.isEmpty && swiftNames.isEmpty {
                Section {
                    Text("未找到符号（二进制可能已被 strip）")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .listStyle(.insetGrouped)
        .searchable(text: $query, prompt: "搜类名 / 方法 / 符号")
        .task(id: query) { await recompute() }
    }
}
