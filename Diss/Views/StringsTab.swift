import SwiftUI

struct StringsTab: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var query = ""
    @State private var displayRows: [StringItem] = []

    private func recompute() async {
        let q = query
        try? await Task.sleep(nanoseconds: 220_000_000)
        guard !Task.isCancelled, q == query else { return }
        let all = engine.result.cstrings
        displayRows = await Task.detached(priority: .userInitiated) {
            Repos.filtered(all, q, cap: 8000)
        }.value
    }

    var body: some View {
        NavigationStack {
            Group {
                if engine.phase == .done {
                    listArea
                } else {
                    emptyHint
                }
            }
            .navigationTitle("字符串")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var emptyHint: some View {
        VStack(spacing: 8) {
            Image(systemName: "textformat")
                .font(.system(size: 30))
                .foregroundStyle(.tertiary)
            Text("先在「概览」选择 IPA")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private var listArea: some View {
        VStack(spacing: 0) {
            HStack {
                Text("共 \(engine.result.cstrings.count) 条（去重后）")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                NavigationLink {
                    NetworkView(engine: engine)
                } label: {
                    Label("网络接口", systemImage: "network")
                        .font(.caption.weight(.semibold))
                }
                .padding(.trailing, 8)
                NavigationLink {
                    JailbreakScanView(engine: engine)
                } label: {
                    Label("风控扫描", systemImage: "shield.lefthalf.filled")
                        .font(.caption.weight(.semibold))
                }
            }
            .padding(.horizontal, 14)
            .padding(.top, 8)

            TextField("搜索字符串…", text: $query)
                .textFieldStyle(.roundedBorder)
                .padding(12)

            List {
                rows(displayRows)
            }
            .listStyle(.plain)
            .task(id: query) { await recompute() }
        }
    }

    private func rows(_ items: [StringItem]) -> some View {
        ForEach(items) { item in
            Text(item.text)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(3)
        }
    }
}

// MARK: - 字符串列表模型与过滤（v2.0 符号页重构后回归此处）

struct StringItem: Identifiable, Hashable {
    let id: Int
    let text: String
}

enum Repos {
    static func filtered(_ all: [String], _ query: String, cap: Int) -> [StringItem] {
        var list = all
        if !query.isEmpty {
            let q2 = query.lowercased()
            list = list.filter { $0.lowercased().contains(q2) }
        }
        return list.prefix(cap).enumerated().map { StringItem(id: $0.offset, text: $0.element) }
    }
}
