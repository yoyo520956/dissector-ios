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

    private var classes: [String] { filtered(engine.result.classNames) }
    private var methods: [String] { filtered(engine.result.methodNames) }
    private var swiftNames: [String] { filtered(engine.result.swiftSymbols) }
    private var machSymbols: [MachSymbol] {
        let r = engine.result.symbolsFull
        if query.isEmpty { return Array(r.prefix(800)) }
        return Array(r.filter { $0.name.localizedCaseInsensitiveContains(query) }.prefix(800))
    }

    private func filtered(_ list: [String]) -> [String] {
        let base = query.isEmpty ? list : list.filter { $0.localizedCaseInsensitiveContains(query) }
        return Array(base.prefix(600))
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
    }
}
