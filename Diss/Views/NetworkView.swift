import SwiftUI

// MARK: - 网络接口页：URL / 域名 / API 路径汇总

struct NetworkView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var report: NetworkExtract.Report?
    @State private var query = ""

    private func filter(_ list: [NetworkExtract.Hit]) -> [NetworkExtract.Hit] {
        query.isEmpty ? list : list.filter { $0.value.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        Group {
            if let r = report {
                if r.total == 0 {
                    VStack(spacing: 12) {
                        Image(systemName: "network")
                            .font(.system(size: 40))
                            .foregroundStyle(.secondary)
                        Text("未在字符串池中找到网络接口")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List {
                        if !r.urls.isEmpty {
                            Section("完整 URL (\(r.urls.count))") {
                                ForEach(filter(r.urls)) { h in
                                    hitRow(h)
                                }
                            }
                        }
                        if !r.hosts.isEmpty {
                            Section("域名 (\(r.hosts.count))") {
                                ForEach(filter(r.hosts)) { h in
                                    hitRow(h)
                                }
                            }
                        }
                        if !r.paths.isEmpty {
                            Section("API 路径 (\(r.paths.count))") {
                                ForEach(filter(r.paths)) { h in
                                    hitRow(h)
                                }
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .searchable(text: $query, prompt: "搜接口/域名")
                }
            } else {
                ProgressView("提取中…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle("网络接口")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    if let r = report {
                        engine.saveExport(Data(NetworkExtract.reportText(r).utf8),
                                          name: "\(exportBase())-network.txt")
                    }
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .disabled(report == nil || report?.total == 0)
            }
        }
        .onAppear {
            if report == nil {
                report = NetworkExtract.extract(engine.result.cstrings)
            }
        }
    }

    private func hitRow(_ h: NetworkExtract.Hit) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(h.value)
                .font(.caption.monospaced())
                .textSelection(.enabled)
            if h.count > 1 {
                Text("出现 \(h.count) 次")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private func exportBase() -> String {
        (engine.result.info.displayName.isEmpty ? engine.fileName : engine.result.info.displayName)
            .replacingOccurrences(of: ".ipa", with: "")
            .replacingOccurrences(of: " ", with: "_")
    }
}
