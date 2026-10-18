import SwiftUI
import UIKit

struct OverviewTab: View {
    @ObservedObject var engine: AnalysisEngine
    @Binding var showPicker: Bool

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    pickerCard
                    libraryCard
                    statusCard
                    if engine.phase == .done {
                        toolsCard
                        infoCard
                        summaryCard
                        warningCard
                    }
                }
                .padding(14)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("IPA 解剖台")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { engine.refreshImportList() }
        }
    }

    // MARK: - 深度分析工具

    private var toolsCard: some View {
        SectionCard(title: "深度分析工具", icon: "wrench.and.screwdriver.fill") {
            VStack(spacing: 8) {
                toolLink("完整性校验", "checkmark.seal", "ZIP 全条目 CRC32 实算", .blue) {
                    IntegrityView(engine: engine)
                }
                toolLink("越狱/风控扫描", "shield.lefthalf.filled", "越狱检测/Hook框架/调试特征", .green) {
                    JailbreakScanView(engine: engine)
                }
                toolLink("隐私权限画像", "hand.raised", "权限申请 + 代码证据", .orange) {
                    PrivacyProfileView(engine: engine)
                }
                toolLink("签名深度解析", "signature", "CodeDirectory + 真实 Entitlements", .purple) {
                    CodeSigView(engine: engine)
                }
            }
        }
    }

    private func toolLink<Content: View>(_ title: String, _ icon: String, _ sub: String,
                                         _ color: Color, @ViewBuilder dest: () -> Content) -> some View {
        NavigationLink { dest() } label: {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .foregroundStyle(color)
                    .font(.title3)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.footnote.weight(.semibold))
                    Text(sub).font(.caption2).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
            }
        }
        .buttonStyle(.plain)
    }

    // MARK: - 卡片

    private var pickerCard: some View {
        VStack(spacing: 10) {
            Image(systemName: "shippingbox")
                .font(.system(size: 34))
                .foregroundStyle(.blue.gradient)
            Text(engine.fileName.isEmpty ? "选择一个 IPA 文件开始解剖" : engine.fileName)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Button {
                showPicker = true
            } label: {
                Label(engine.phase == .done ? "换个文件" : "选择 IPA",
                      systemImage: "folder.badge.plus")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            Text("也可以在文件 App 里把 IPA 拷进「拆解者」文件夹，或长按 IPA 分享到本 App")
                .font(.caption2)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
        }
        .cardStyle()
    }

    // MARK: - IPA 库（Documents 目录）

    @ViewBuilder
    private var libraryCard: some View {
        if !engine.importedURLs.isEmpty {
            SectionCard(title: "我的 IPA 库 (\(engine.importedURLs.count))", icon: "archivebox") {
                ForEach(engine.importedURLs, id: \.absoluteString) { u in
                    HStack(spacing: 10) {
                        Image(systemName: "shippingbox.fill")
                            .foregroundStyle(.blue)
                            .font(.footnote)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(u.lastPathComponent)
                                .font(.footnote.weight(.medium))
                                .lineLimit(1)
                            if engine.pickedURL == u {
                                Text("当前分析中")
                                    .font(.caption2)
                                    .foregroundStyle(.green)
                            }
                        }
                        Spacer()
                        Button {
                            engine.openLocal(u)
                        } label: {
                            Image(systemName: "magnifyingglass.circle.fill")
                                .font(.title3)
                        }
                        .buttonStyle(.borderless)
                        Button(role: .destructive) {
                            engine.deleteImported(u)
                        } label: {
                            Image(systemName: "trash")
                                .font(.footnote)
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var statusCard: some View {
        switch engine.phase {
        case .working(let s):
            HStack(spacing: 10) {
                ProgressView()
                Text(s).font(.footnote)
                Spacer()
            }
            .cardStyle()
        case .failed(let s):
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(s).font(.footnote)
                Spacer()
            }
            .cardStyle()
        default:
            EmptyView()
        }
    }

    @ViewBuilder
    private var infoCard: some View {
        let i = engine.result.info
        SectionCard(title: "App 信息", icon: "info.circle") {
            KVRow(k: "名称", v: i.displayName)
            KVRow(k: "Bundle ID", v: i.bundleID)
            KVRow(k: "版本", v: i.version + " (" + i.build + ")")
            KVRow(k: "最低系统", v: i.minOS)
            KVRow(k: "App 包位置", v: engine.result.appFolder)
        }
    }

    @ViewBuilder
    private var summaryCard: some View {
        let s = engine.result.summary
        SectionCard(title: "主二进制", icon: "wrench.and.screwdriver") {
            KVRow(k: "架构", v: s.format)
            KVRow(k: "类型", v: s.fileType)
            KVRow(k: "体积", v: ByteFmt.text(s.fileSize))
            KVRow(k: "UUID", v: s.uuid)
            KVRow(k: "编译 SDK", v: s.sdkVersion)
            KVRow(k: "加密状态", v: cryptText(s.encrypted))
            KVRow(k: "依赖库", v: "\(s.dylibCount) 个")
            KVRow(k: "符号", v: "\(s.symbolCount) 条")
            KVRow(k: "ObjC 类", v: "\(s.classCount) 个")
            KVRow(k: "方法名", v: "\(s.methodCount) 条")
            KVRow(k: "包内条目", v: "\(engine.result.entries.count) 项 / 解压 \(ByteFmt.text(engine.result.totalUncompressed))")
        }
    }

    @ViewBuilder
    private var warningCard: some View {
        let warns = engine.result.warnings
        if !warns.isEmpty {
            SectionCard(title: "提示", icon: "lightbulb") {
                Text(warns.joined(separator: "\n"))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func cryptText(_ n: Int) -> String {
        switch n {
        case 1: return "已加密（App Store 壳）"
        case 0: return "未加密（可完整解析）"
        default: return "未报告"
        }
    }
}

// MARK: - 通用组件

struct SectionCard<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: icon)
                .font(.subheadline.weight(.semibold))
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardStyle()
    }
}

struct KVRow: View {
    let k: String
    let v: String

    var body: some View {
        HStack(alignment: .top) {
            Text(k)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .frame(width: 88, alignment: .leading)
            Text(v.isEmpty ? "—" : v)
                .font(.footnote.weight(.medium))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

extension View {
    func cardStyle() -> some View {
        padding(14)
            .background(Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}
