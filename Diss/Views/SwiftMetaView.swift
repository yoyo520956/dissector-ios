import SwiftUI

// MARK: - Swift 元数据页：类型列表 → 字段详情（比符号还原更深一层）

struct SwiftMetaView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var types: [SwiftTypeDump] = []
    @State private var loaded = false
    @State private var query = ""

    private var filtered: [SwiftTypeDump] {
        query.isEmpty ? types : types.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        Group {
            if !loaded {
                ProgressView("解析 Swift 元数据…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if types.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "swift")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("未解析到 Swift 元数据（可能是 ObjC-only 或被裁剪）")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 30)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filtered) { t in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text(t.name)
                                .font(.footnote.weight(.semibold))
                            Text(t.kind)
                                .font(.caption2)
                                .foregroundStyle(.white)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1)
                                .background(t.kind == "class" ? Color.blue : (t.kind == "struct" ? Color.green : Color.orange), in: Capsule())
                        }
                        if !t.fields.isEmpty {
                            Text(t.fields.prefix(4).map { "var \($0.name): \($0.typeName)" }.joined(separator: "\n"))
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                            if t.fields.count > 4 {
                                Text("… 共 \(t.fields.count) 个字段")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.insetGrouped)
                .searchable(text: $query, prompt: "搜类型名")
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            exportAll()
                        } label: {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                }
            }
        }
        .navigationTitle("Swift 元数据 (\(types.count))")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if !loaded {
                types = engine.swiftMeta()
                loaded = true
            }
        }
    }

    private func exportAll() {
        var lines: [String] = []
        lines.append("// 由拆解者 Dissector 从 Swift 元数据解析的类型与字段")
        lines.append("")
        for t in types {
            lines.append("\(t.kind) \(t.name) {")
            for f in t.fields {
                lines.append("    var \(f.name): \(f.typeName)")
            }
            lines.append("}")
            lines.append("")
        }
        engine.saveExport(Data(lines.joined(separator: "\n").utf8),
                          name: "\(engine.result.info.displayName.isEmpty ? "app" : engine.result.info.displayName)-swift-types.swift")
    }
}
