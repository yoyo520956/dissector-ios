import SwiftUI

struct SectionsTab: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var selected: MachSection?

    var body: some View {
        NavigationStack {
            Group {
                if engine.phase == .done {
                    sectionList()
                } else {
                    emptyHint
                }
            }
            .navigationTitle("结构")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(item: $selected) { sec in
                SectionDetailSheet(engine: engine, section: sec)
            }
        }
    }

    // ForEach 安全形态：helper 函数 + 链式过滤，绝不传裸 computed var

    private var emptyHint: some View {
        VStack(spacing: 8) {
            Image(systemName: "square.split.2x2")
                .font(.system(size: 30))
                .foregroundStyle(.tertiary)
            Text("先在「概览」选择 IPA")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func sectionList() -> some View {
        List {
            ForEach(engine.result.segments) { seg in
                Section(seg.name + "  ·  " + ByteFmt.text(seg.fileSize)) {
                    segRows(seg)
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    private func segRows(_ seg: MachSegment) -> some View {
        ForEach(seg.sections) { sec in
            Button {
                selected = sec
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(sec.name)
                            .font(.footnote.weight(.medium))
                            .foregroundStyle(.primary)
                        Text("0x\(String(sec.addr, radix: 16))  ·  offset 0x\(String(sec.fileOffset, radix: 16))")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(sec.sizeText)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.blue)
                    Image(systemName: "chevron.right")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
    }
}

// MARK: - Section 详情（hex 预览）

struct SectionDetailSheet: View {
    @ObservedObject var engine: AnalysisEngine
    let section: MachSection
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView([.horizontal, .vertical]) {
                Text(hexText)
                    .font(.system(size: 10, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
            }
            .navigationTitle(section.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("完成") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
    }

    private var hexText: String {
        let d = engine.sectionRaw(section)
        if d.isEmpty { return "（无可预览数据）" }
        return HexTool.dump(d, limit: 2048)
    }
}
