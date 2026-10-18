import SwiftUI

// 库页签：IPA 导入三通道 + 文件库管理

struct LibraryView: View {
    @ObservedObject var engine: AnalysisEngine
    @Binding var showPicker: Bool

    var body: some View {
        NavigationStack {
            Group {
                if engine.importedURLs.isEmpty {
                    ContentUnavailableView(
                        "IPA 库为空",
                        systemImage: "archivebox",
                        description: Text("通过下方按钮选择文件，或在文件 App 里分享给「拆解者」")
                    )
                } else {
                    List {
                        ForEach(engine.importedURLs, id: \.self) { url in
                            Button {
                                engine.openLocal(url)
                            } label: {
                                HStack {
                                    Image(systemName: "shippingbox")
                                        .foregroundStyle(.blue)
                                        .font(.title3)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(url.lastPathComponent)
                                            .font(.subheadline)
                                            .foregroundStyle(.primary)
                                            .lineLimit(1)
                                        if engine.pickedURL == url {
                                            Text("当前分析对象")
                                                .font(.caption2)
                                                .foregroundStyle(.blue)
                                        }
                                    }
                                    Spacer()
                                    if engine.pickedURL == url, engine.phase != .idle {
                                        ProgressView()
                                    }
                                }
                            }
                        }
                        .onDelete { idx in
                            for i in idx { engine.deleteImported(engine.importedURLs[i]) }
                        }
                    }
                }
            }
            .navigationTitle("IPA 库")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showPicker = true
                    } label: {
                        Image(systemName: "plus.circle.fill")
                    }
                }
            }
        }
    }
}
