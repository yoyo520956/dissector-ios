import SwiftUI
import UIKit

// MARK: - Assets.car 提取视图：魔数扫描 + 图片网格 + 导出

struct AssetsCarView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var report: AssetsCar.ScanReport?
    @State private var exported = 0

    var body: some View {
        Group {
            if let r = report {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(AssetsCar.reportText(r))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(.secondarySystemGroupedBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 12))

                        if !r.images.isEmpty {
                            Button {
                                exportAll(r)
                            } label: {
                                Label("导出全部 \(r.images.count) 张到 exports/", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)

                            LazyVGrid(columns: [GridItem(.adaptive(minimum: 90), spacing: 10)], spacing: 10) {
                                ForEach(r.images) { img in
                                    VStack(spacing: 4) {
                                        if let ui = UIImage(data: img.data) {
                                            Image(uiImage: ui)
                                                .resizable()
                                                .aspectRatio(contentMode: .fit)
                                                .frame(width: 84, height: 84)
                                                .background(Color(.tertiarySystemBackground))
                                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                        }
                                        Text(img.fileName)
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                    }
                                }
                            }
                            if exported > 0 {
                                Label("已导出 \(exported) 张到 exports/ 文件夹", systemImage: "checkmark.circle")
                                    .font(.footnote)
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                    .padding(14)
                }
                .background(Color(.systemGroupedBackground))
            } else {
                ProgressView("扫描 Assets.car…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle("Assets.car 提取")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if report == nil {
                if let d = engine.assetsCarData() {
                    report = AssetsCar.scan(d)
                } else {
                    report = AssetsCar.ScanReport()
                }
            }
        }
    }

    private func exportAll(_ r: AssetsCar.ScanReport) {
        var files: [ZIPEntry] = []
        for img in r.images {
            files.append(ZIPEntry(path: img.fileName, data: img.data))
        }
        if let zipData = ZIPWriter.write(files) {
            _ = engine.saveExport(zipData, name: "assets-car-提取.zip")
            exported = files.count
        }
    }
}
