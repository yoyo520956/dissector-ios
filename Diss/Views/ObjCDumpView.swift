import SwiftUI

// MARK: - ObjC 类转储：类列表 → 完整 @interface → 导出 .h（class-dump 风格）

struct ObjCDumpView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var query = ""
    @State private var classes: [ObjCClassDump] = []
    @State private var loaded = false

    private var filtered: [ObjCClassDump] {
        query.isEmpty ? classes : classes.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        Group {
            if !loaded {
                ProgressView("解析类结构…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if classes.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("未解析到 ObjC 类（可能是 Swift-only 或 strip 过的二进制）")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 30)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filtered) { c in
                    NavigationLink {
                        ObjCClassDetailView(engine: engine, cls: c, allClasses: classes)
                    } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(c.name)
                                .font(.footnote.weight(.semibold))
                                .lineLimit(1)
                            HStack(spacing: 8) {
                                if !c.superName.isEmpty {
                                    Text(": \(c.superName)")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Text("\(c.methodCount) 方法")
                                    .font(.caption2)
                                    .foregroundStyle(.blue)
                                if !c.props.isEmpty {
                                    Text("\(c.props.count) 属性")
                                        .font(.caption2)
                                        .foregroundStyle(.green)
                                }
                            }
                        }
                    }
                }
                .listStyle(.insetGrouped)
                .searchable(text: $query, prompt: "搜类名")
            }
        }
        .navigationTitle("类转储 (\(classes.count))")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if !loaded {
                let r = engine.dumpClasses()
                classes = r
                loaded = true
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    exportAll()
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .disabled(classes.isEmpty)
            }
        }
    }

    private func exportAll() {
        let text = ObjCDumper.headerText(classes)
        let base = (engine.result.info.displayName.isEmpty ? engine.fileName : engine.result.info.displayName)
            .replacingOccurrences(of: ".ipa", with: "")
        engine.saveExport(Data(text.utf8), name: "\(base)-classdump.h")
    }
}

// MARK: - 单类详情：完整 @interface + 方法列表

struct ObjCClassDetailView: View {
    @ObservedObject var engine: AnalysisEngine
    let cls: ObjCClassDump
    let allClasses: [ObjCClassDump]
    @State private var headerText = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(headerText)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .padding(.horizontal, 14)

                if !cls.instanceMethods.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("实例方法 (\(cls.instanceMethods.count))", systemImage: "wrench.and.screwdriver")
                            .font(.subheadline.weight(.semibold))
                        ForEach(cls.instanceMethods) { m in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(m.readable)
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                Text("IMP \(String(format: "0x%llX", m.imp)) · 原始编码 \(m.typeEnc)")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                            .padding(.vertical, 2)
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .padding(.horizontal, 14)
                }

                if !cls.classMethods.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("类方法 (\(cls.classMethods.count))", systemImage: "plus.circle")
                            .font(.subheadline.weight(.semibold))
                        ForEach(cls.classMethods) { m in
                            Text(m.readable)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(.secondarySystemGroupedBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .padding(.horizontal, 14)
                }

                Button {
                    exportSingle()
                } label: {
                    Label("导出此类为 .h", systemImage: "square.and.arrow.up")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .padding(.horizontal, 14)
            }
            .padding(.vertical, 12)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle(cls.name)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if headerText.isEmpty {
                headerText = ObjCDumper.headerText([cls])
            }
        }
    }

    private func exportSingle() {
        engine.saveExport(Data(headerText.utf8), name: "\(cls.name).h")
    }
}
