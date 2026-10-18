import SwiftUI

// 专业功能 · 交叉引用面板：谁调用了这个函数

struct XrefSheet: View {
    @ObservedObject var engine: AnalysisEngine
    let targetVA: UInt64
    @Environment(\.dismiss) private var dismiss

    private var sites: [XrefSite] { engine.callers(of: targetVA) }

    var body: some View {
        NavigationStack {
            Group {
                if sites.isEmpty {
                    ContentUnavailableView(
                        "无调用者",
                        systemImage: "arrow.triangle.branch",
                        description: Text(String(format: "0x%llX 没有被 bl/b 直接调用（可能通过消息分发/间接调用）", targetVA))
                    )
                } else {
                    List {
                        Section("调用点（\(sites.count)）") {
                            ForEach(sites) { site in
                                Button {
                                    NotificationCenter.default.post(
                                        name: .dissJumpToVA, object: site.fromVA)
                                    dismiss()
                                } label: {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(engine.nearestSymbol(va: site.fromVA)?.name ?? "未知函数")
                                                .font(.subheadline)
                                                .foregroundStyle(.primary)
                                            Text(String(format: "%@ 0x%llX", site.kind, site.fromVA))
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundStyle(.secondary)
                                        }
                                        Spacer()
                                        Image(systemName: "arrow.up.right")
                                            .font(.caption)
                                            .foregroundStyle(.blue)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("调用者")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("完成") { dismiss() }
                }
            }
        }
    }
}

extension Notification.Name {
    static let dissJumpToVA = Notification.Name("dissJumpToVA")
}

// MARK: - 标注编辑面板（专业功能：符号重命名 + 备注）

struct AnnotationSheet: View {
    let targetVA: UInt64
    let fallbackName: String
    @ObservedObject private var ann = AnnotationStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var nameText = ""
    @State private var noteText = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("目标") {
                    LabeledContent("地址", value: String(format: "0x%llX", targetVA))
                    LabeledContent("原名", value: fallbackName)
                }
                Section("重命名") {
                    TextField("新名字（留空 = 用原名）", text: $nameText)
                }
                Section("备注") {
                    TextField("这个函数是干什么的…", text: $noteText, axis: .vertical)
                        .lineLimit(3)
                }
                Section {
                    Button(role: .destructive) {
                        ann.remove(key: AnnotationStore.addrKey(targetVA))
                        dismiss()
                    } label: {
                        Label("删除此标注", systemImage: "trash")
                    }
                }
            }
            .navigationTitle("标注")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("保存") {
                        ann.set(key: AnnotationStore.addrKey(targetVA),
                                name: nameText, note: noteText)
                        dismiss()
                    }
                }
            }
            .onAppear {
                if let n = ann.notes[AnnotationStore.addrKey(targetVA)] {
                    nameText = n.name
                    noteText = n.note
                }
            }
        }
    }
}
