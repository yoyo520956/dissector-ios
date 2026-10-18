import SwiftUI

// MARK: - 完整性校验视图

struct IntegrityView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var items: [IntegrityItem] = []
    @State private var running = false

    private var failed: [IntegrityItem] { items.filter { !$0.ok } }

    var body: some View {
        Group {
            if running {
                VStack(spacing: 14) {
                    ProgressView(value: engine.integrityProgress.1 > 0
                                 ? Double(engine.integrityProgress.0) / Double(engine.integrityProgress.1) : 0)
                        .padding(.horizontal, 40)
                    Text("校验中 \(engine.integrityProgress.0)/\(engine.integrityProgress.1)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if items.isEmpty {
                VStack(spacing: 14) {
                    Image(systemName: "checkmark.seal")
                        .font(.system(size: 40))
                        .foregroundStyle(.blue.gradient)
                    Text("对 ZIP 全部条目做 CRC32 实算校验")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button {
                        start()
                    } label: {
                        Label("开始校验", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    Section("结果") {
                        HStack {
                            Label("\(items.count) 条目", systemImage: "shippingbox")
                            Spacer()
                            Text(failed.isEmpty ? "全部通过 ✓" : "损坏 \(failed.count) 条")
                                .foregroundStyle(failed.isEmpty ? .green : .red)
                                .font(.footnote.weight(.semibold))
                        }
                    }
                    if !failed.isEmpty {
                        Section("损坏条目") {
                            ForEach(failed) { it in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(it.path).font(.caption.monospaced()).lineLimit(2)
                                    Text(String(format: "登记 %08X ≠ 实算 %08X", it.expected, it.actual))
                                        .font(.caption2.monospaced())
                                        .foregroundStyle(.red)
                                }
                            }
                        }
                    }
                }
                .listStyle(.insetGrouped)
            }
        }
        .navigationTitle("完整性校验")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func start() {
        running = true
        Task {
            let r = await engine.runIntegrityCheck()
            items = r
            running = false
        }
    }
}

// MARK: - 越狱/风控特征视图

struct JailbreakScanView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var hits: [JBSignature] = []

    private var grouped: [(String, [JBSignature])] {
        Dictionary(grouping: hits, by: { $0.category })
            .sorted { $0.key < $1.key }
    }

    var body: some View {
        Group {
            if hits.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 40))
                        .foregroundStyle(.green)
                    Text("未发现明显越狱 / Hook / 风控特征")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    Section("研判") {
                        Text(JailbreakScan.summaryText(hits))
                            .font(.footnote)
                    }
                    ForEach(grouped, id: \.0) { cat, list in
                        Section("\(cat) (\(list.count))") {
                            ForEach(list) { h in
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack {
                                        Text(h.keyword)
                                            .font(.footnote.weight(.semibold))
                                            .foregroundStyle(.orange)
                                        Spacer()
                                        Text(String(format: "@0x%llX", UInt64(h.sample.utf8.count)))
                                            .font(.caption2)
                                            .foregroundStyle(.tertiary)
                                    }
                                    Text(h.sample)
                                        .font(.caption2.monospaced())
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }
                            }
                        }
                    }
                }
                .listStyle(.insetGrouped)
            }
        }
        .navigationTitle("越狱/风控扫描")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { hits = engine.jailbreakScan() }
    }
}

// MARK: - 隐私权限画像视图

struct PrivacyProfileView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var perms: [PrivacyPermission] = []

    var body: some View {
        Group {
            if perms.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "hand.raised")
                        .font(.system(size: 40))
                        .foregroundStyle(.secondary)
                    Text("未发现敏感权限申请")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(perms) { p in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(p.name)
                            .font(.footnote.weight(.semibold))
                        if !p.usageText.isEmpty {
                            Text("用途：\(p.usageText)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 8) {
                            Text(p.plistKey)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.tertiary)
                            if !p.codeEvidence.isEmpty {
                                Text("代码证据：\(p.codeEvidence)")
                                    .font(.caption2)
                                    .foregroundStyle(.blue)
                            }
                        }
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.insetGrouped)
            }
        }
        .navigationTitle("隐私权限画像 (\(perms.count))")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { perms = engine.privacyProfile() }
    }
}

// MARK: - 代码签名深度解析视图

struct CodeSigView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var info: CodeSigInfo?

    var body: some View {
        Group {
            if let i = info {
                List {
                    if !i.errors.isEmpty {
                        Section("异常") {
                            ForEach(i.errors, id: \.self) { e in
                                Text(e).font(.footnote).foregroundStyle(.orange)
                            }
                        }
                    }
                    Section("CodeDirectory") {
                        kv("标识符", i.identifier)
                        kv("团队 ID", i.teamID.isEmpty ? "—" : i.teamID)
                        kv("目录版本", i.version)
                        kv("哈希算法", i.hashSize == 32 ? "SHA-256" : (i.hashSize == 20 ? "SHA-1" : "hashSize=\(i.hashSize)"))
                        kv("代码页哈希", "\(i.codeSlots) 页")
                        kv("特殊槽位", "\(i.specialSlots)")
                        kv("标志位", i.flagsText)
                        kv("CMS 签名", i.hasCMS ? "存在（正式分发签名）" : "无")
                    }
                    if !i.entitlementsKV.isEmpty {
                        Section("真实生效的 Entitlements (\(i.entitlementsKV.count))") {
                            ForEach(Array(i.entitlementsKV.enumerated()), id: \.offset) { _, kv in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(kv.0).font(.caption.monospaced()).textSelection(.enabled)
                                    Text(kv.1).font(.caption2.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                                }
                            }
                        }
                    }
                    if !i.entitlementsXML.isEmpty {
                        Section("原始 XML") {
                            Text(i.entitlementsXML)
                                .font(.caption2.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                }
                .listStyle(.insetGrouped)
            } else {
                ProgressView("解析签名…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle("签名深度解析")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if info == nil { info = engine.codeSignature() }
        }
    }

    private func kv(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).font(.footnote).foregroundStyle(.secondary).frame(width: 100, alignment: .leading)
            Text(v.isEmpty ? "—" : v).font(.footnote.monospaced()).textSelection(.enabled)
        }
    }
}
