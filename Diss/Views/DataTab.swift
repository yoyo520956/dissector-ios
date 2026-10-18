import SwiftUI

// 数据页签：字符串 / 资源 / Assets.car / 网络接口

struct DataTab: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var mode = 0

    var body: some View {
        VStack(spacing: 0) {
            Picker("视图", selection: $mode) {
                Text("字符串").tag(0)
                Text("资源").tag(1)
                Text("Assets").tag(2)
                Text("网络").tag(3)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            switch mode {
            case 0: StringsTab(engine: engine)
            case 1: ResourcesTab(engine: engine)
            case 2: AssetsCarView(engine: engine)
            default: NetworkView(engine: engine)
            }
        }
    }
}

// 深度页签：结构 / 签名 / 完整性 / 风控 / 隐私 / 报告

struct DeepTab: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var mode = 0

    var body: some View {
        VStack(spacing: 0) {
            Picker("视图", selection: $mode) {
                Text("结构").tag(0)
                Text("签名").tag(1)
                Text("完整性").tag(2)
                Text("风控").tag(3)
                Text("隐私").tag(4)
                Text("报告").tag(5)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 8)
            .padding(.vertical, 8)

            switch mode {
            case 0: SectionsTab(engine: engine)
            case 1: ProvisionTab(engine: engine)
            case 2: IntegrityView(engine: engine)
            case 3: JailbreakScanView(engine: engine)
            case 4: PrivacyProfileView(engine: engine)
            default: ReportView(engine: engine)
            }
        }
    }
}

// MARK: - 报告视图（专业功能：完整 HTML 报告导出）

struct ReportView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var html: String = ""
    @State private var fileURL: URL?

    var body: some View {
        List {
            Section("报告内容") {
                LabeledContent("应用信息", value: "显示名/版本/UUID/加密位")
                LabeledContent("结构", value: "\(engine.result.segments.count) 段")
                LabeledContent("依赖库", value: "\(engine.result.dylibs.count) 条")
                LabeledContent("类转储", value: "\(engine.result.summary.classCount) 类")
                LabeledContent("符号", value: "\(engine.result.symbolsFull.count) 条")
                LabeledContent("字符串", value: "\(engine.result.cstrings.count) 条")
                LabeledContent("交叉引用", value: "\(engine.xrefStats.sites) 调用点")
            }
            Section {
                Button {
                    exportReport()
                } label: {
                    Label("生成完整 HTML 报告", systemImage: "doc.richtext")
                }
                if let u = fileURL {
                    ShareLink(item: u) {
                        Label("分享报告文件", systemImage: "square.and.arrow.up")
                    }
                }
            } footer: {
                Text("报告保存到 exports/ 目录，包含概览/结构/类转储/符号/字符串/网络/风控/隐私全部九段")
            }
        }
    }

    private func exportReport() {
        let content = ReportExport.build(engine: engine)
        html = content
        if let name = engine.saveExport(Data(content.utf8), name: "拆解者报告.html") {
            fileURL = AnalysisEngine.exportsDir().appendingPathComponent(name)
        }
    }
}
