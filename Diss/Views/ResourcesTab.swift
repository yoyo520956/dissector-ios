import SwiftUI
import UIKit

// MARK: - 资源页：浏览 IPA 包内全部文件，图片/配置/文本可预览，支持多选打包导出

struct ResourcesTab: View {
    @ObservedObject var engine: AnalysisEngine

    var body: some View {
        NavigationStack {
            Group {
                if engine.phase != .done {
                    VStack(spacing: 12) {
                        Image(systemName: "folder")
                            .font(.system(size: 40))
                            .foregroundStyle(.blue.gradient)
                        Text("导入 IPA 后可浏览包内资源")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ResourceListView(engine: engine)
                }
            }
            .navigationTitle("资源浏览")
            .navigationBarTitleDisplayMode(.inline)
            .background(Color(.systemGroupedBackground))
        }
    }
}

// MARK: - 资源分类

enum ResCategory: String, CaseIterable, Identifiable {
    case all = "全部"
    case image = "图片"
    case text = "文本"
    case config = "配置"
    case other = "其他"
    var id: String { rawValue }

    static func of(_ entry: ZipEntry) -> ResCategory {
        let p = entry.path.lowercased()
        if ["png", "jpg", "jpeg", "heic", "webp", "gif", "ico"].contains(where: { p.hasSuffix("." + $0) }) {
            return .image
        }
        if ["txt", "strings", "json", "html", "css", "js", "xml", "csv", "log", "md", "h", "m", "swift", "entitlements"].contains(where: { p.hasSuffix("." + $0) }) {
            return .text
        }
        if p.hasSuffix(".plist") || p.hasSuffix(".mobileprovision") {
            return .config
        }
        return .other
    }
}

struct ResourceListView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var query = ""
    @State private var cat: ResCategory = .all
    @State private var selectMode = false
    @State private var selection = Set<Int>()

    private var items: [ZipEntry] {
        let files = engine.result.entries.filter { !$0.isDirectory }
        var list = files
        if cat != .all {
            list = list.filter { ResCategory.of($0) == cat }
        }
        if !query.isEmpty {
            list = list.filter { $0.path.localizedCaseInsensitiveContains(query) }
        }
        return list.sorted { $0.path < $1.path }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("分类", selection: $cat) {
                ForEach(ResCategory.allCases) { c in
                    Text(c.rawValue).tag(c)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)

            List(items) { e in
                row(for: e)
            }
            .listStyle(.insetGrouped)
            .searchable(text: $query, prompt: "搜资源路径")
            .overlay {
                if items.isEmpty {
                    Text("没有匹配的资源")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    selectMode.toggle()
                    if !selectMode { selection.removeAll() }
                } label: {
                    Text(selectMode ? "取消" : "选择")
                }
            }
            if selectMode {
                ToolbarItem(placement: .bottomBar) {
                    HStack {
                        Button {
                            selection = Set(items.map { $0.id })
                        } label: {
                            Text("全选本页(\(items.count))")
                        }
                        Spacer()
                        Button {
                            exportSelected()
                        } label: {
                            Label("打包导出 (\(selection.count))", systemImage: "shippingbox.and.arrow.backward")
                                .fontWeight(.semibold)
                        }
                        .disabled(selection.isEmpty)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func row(for e: ZipEntry) -> some View {
        if selectMode {
            Button {
                if selection.contains(e.id) {
                    selection.remove(e.id)
                } else {
                    selection.insert(e.id)
                }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: selection.contains(e.id) ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(selection.contains(e.id) ? .blue : .secondary)
                    rowInner(e)
                }
            }
            .buttonStyle(.plain)
        } else {
            NavigationLink {
                ResourceDetailView(engine: engine, entry: e)
            } label: {
                rowInner(e)
            }
        }
    }

    private func rowInner(_ e: ZipEntry) -> some View {
        HStack(spacing: 10) {
            Image(systemName: iconFor(e))
                .foregroundStyle(colorFor(e))
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(e.fileName)
                    .font(.footnote.weight(.medium))
                    .lineLimit(1)
                Text(e.path)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text(ByteFmt.text(e.size))
                .font(.caption2.monospaced())
                .foregroundStyle(.tertiary)
        }
    }

    private func exportSelected() {
        let chosen = items.filter { selection.contains($0.id) }
        guard !chosen.isEmpty else { return }
        let base = (engine.result.info.displayName.isEmpty ? engine.fileName : engine.result.info.displayName)
            .replacingOccurrences(of: ".ipa", with: "")
            .replacingOccurrences(of: " ", with: "_")
        engine.exportResourcesZip(chosen, zipName: "\(base)-资源包.zip")
    }

    private func iconFor(_ e: ZipEntry) -> String {
        switch ResCategory.of(e) {
        case .image: return "photo"
        case .text: return "doc.plaintext"
        case .config: return "gearshape"
        case .other: return "doc"
        case .all: return "doc"
        }
    }

    private func colorFor(_ e: ZipEntry) -> Color {
        switch ResCategory.of(e) {
        case .image: return .green
        case .text: return .blue
        case .config: return .orange
        default: return .secondary
        }
    }
}

// MARK: - 资源详情预览

struct ResourceDetailView: View {
    @ObservedObject var engine: AnalysisEngine
    let entry: ZipEntry
    @State private var data: Data?
    @State private var plistText: String?
    @State private var failed = false
    @State private var showCar = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let d = data {
                    preview(for: d)
                } else if failed {
                    Label("解压失败（文件过大或损坏）", systemImage: "exclamationmark.triangle")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                } else {
                    ProgressView("解压中…")
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(14)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle(entry.fileName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    exportSingle()
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
            }
        }
        .onAppear {
            load()
            if entry.path.lowercased().hasSuffix("assets.car") {
                showCar = true
            }
        }
        .sheet(isPresented: $showCar) {
            NavigationStack {
                AssetsCarView(engine: engine)
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("完成") { showCar = false }
                        }
                    }
            }
        }
    }

    private func load() {
        let d = engine.resourceData(for: entry, limit: 8 * 1024 * 1024)
        if d == nil { failed = true }
        data = d
        if let d = d {
            plistText = ResPreview.formatted(d, entry: entry)
        }
    }

    private func exportSingle() {
        guard let d = data else { return }
        engine.saveExport(d, name: entry.fileName)
    }

    @ViewBuilder
    private func preview(for d: Data) -> some View {
        switch ResCategory.of(entry) {
        case .image:
            if let img = UIImage(data: d) {
                VStack(spacing: 8) {
                    Image(uiImage: img)
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(maxHeight: 380)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    Text("\(Int(img.size.width)) × \(Int(img.size.height)) · \(ByteFmt.text(UInt64(d.count)))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } else {
                hexBlock(d)
            }
        case .text, .config:
            if let t = plistText {
                Text(t)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                hexBlock(d)
            }
        default:
            hexBlock(d)
        }
    }

    private func hexBlock(_ d: Data) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("原始数据（前 1KB）")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(HexTool.dump(d, limit: 1024))
                .font(.caption2.monospaced())
                .textSelection(.enabled)
        }
    }
}

// MARK: - 预览格式化

enum ResPreview {
    static func formatted(_ d: Data, entry: ZipEntry) -> String? {
        let p = entry.path.lowercased()

        // plist / mobileprovision：二进制或 XML 都转可读
        if p.hasSuffix(".plist") || p.hasSuffix(".mobileprovision") {
            if let obj = try? PropertyListSerialization.propertyList(from: d, options: [], format: nil) {
                return describe(obj, indent: 0)
            }
            return String(data: d, encoding: .utf8)
        }

        // strings：二进制 plist 或 UTF-16 明文表
        if p.hasSuffix(".strings") {
            if let obj = try? PropertyListSerialization.propertyList(from: d, options: [], format: nil),
               let dict = obj as? [String: Any] {
                let lines = dict.sorted { $0.key < $1.key }
                    .map { "\"\($0.key)\" = \"\(describe($0.value, indent: 0))\";" }
                return lines.joined(separator: "\n")
            }
            return String(data: d, encoding: .utf8) ?? String(data: d, encoding: .utf16)
        }

        // json
        if p.hasSuffix(".json") {
            if let obj = try? JSONSerialization.jsonObject(with: d),
               let pretty = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) {
                return String(data: pretty, encoding: .utf8)
            }
            return String(data: d, encoding: .utf8)
        }

        // 纯文本类
        if ["txt", "html", "css", "js", "xml", "csv", "log", "md", "entitlements"].contains(where: { p.hasSuffix("." + $0) }) {
            return String(data: d, encoding: .utf8)
        }
        return nil
    }

    // plist 对象 → 缩进文本
    static func describe(_ obj: Any, indent: Int) -> String {
        let pad = String(repeating: "  ", count: indent)
        if let dict = obj as? [String: Any] {
            if dict.isEmpty { return "{}" }
            let inner = dict.sorted { $0.key < $1.key }
                .map { "\(pad)  \(describeKey($0.key)): \(describe($0.value, indent: indent + 1))" }
            return "{\n" + inner.joined(separator: ",\n") + "\n\(pad)}"
        }
        if let arr = obj as? [Any] {
            if arr.isEmpty { return "[]" }
            let inner = arr.map { "\(pad)  \(describe($0, indent: indent + 1))" }
            return "[\n" + inner.joined(separator: ",\n") + "\n\(pad)]"
        }
        if let s = obj as? String { return s }
        if let n = obj as? NSNumber { return n.stringValue }
        if obj is Data { return "<data>" }
        if obj is Date { return "<date>" }
        return "\(obj)"
    }

    private static func describeKey(_ k: String) -> String {
        k.contains(":") || k.contains(" ") ? "\"\(k)\"" : k
    }
}
