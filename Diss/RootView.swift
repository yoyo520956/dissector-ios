import SwiftUI

// 拆解者 · 根视图：五页签（库 / 概览 / 代码 / 数据 / 深度）
// 每页签内部用 Picker 组织子视图——避免 7 页签被 iOS 折叠进 More 的老问题

struct RootView: View {
    @StateObject private var engine = AnalysisEngine()
    @State private var showPicker = false

    var body: some View {
        TabView {
            LibraryView(engine: engine, showPicker: $showPicker)
                .tabItem { Label("库", systemImage: "archivebox") }

            OverviewTab(engine: engine, showPicker: $showPicker)
                .tabItem { Label("概览", systemImage: "doc.text.magnifyingglass") }

            CodeTab(engine: engine)
                .tabItem { Label("代码", systemImage: "chevron.left.forwardslash.chevron.right") }

            DataTab(engine: engine)
                .tabItem { Label("数据", systemImage: "externaldrive") }

            DeepTab(engine: engine)
                .tabItem { Label("深度", systemImage: "microscope") }
        }
        .onAppear {
            engine.refreshImportList()
            AnnotationStore.shared.load(for: engine.fileName)
        }
        // 导入通道 1：文件选择器
        .fileImporter(isPresented: $showPicker,
                      allowedContentTypes: [.data],
                      allowsMultipleSelection: false) { res in
            if case .success(let urls) = res, let u = urls.first {
                engine.importFromURL(u)
            }
        }
        // 导入通道 2：文件 App 分享打开
        .onOpenURL { url in
            engine.importFromURL(url)
        }
        .alert("分析失败", isPresented: .init(
            get: { if case .failed = engine.phase { return true }; return false },
            set: { _ in })) {
            Button("好", role: .cancel) {}
        } message: {
            if case .failed(let msg) = engine.phase { Text(msg) }
        }
        .overlay(alignment: .top) {
            if let t = engine.toast {
                Text(t)
                    .font(.footnote)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(.ultraThinMaterial, in: Capsule())
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .onAppear {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                            withAnimation { engine.toast = nil }
                        }
                    }
            }
        }
    }
}
