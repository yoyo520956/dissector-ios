import SwiftUI
import UIKit

struct ProvisionTab: View {
    @ObservedObject var engine: AnalysisEngine

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    if engine.phase == .done {
                        profileCard
                        entCard
                        dylibCard
                    } else {
                        emptyHint
                    }
                }
                .padding(14)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("签名")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var emptyHint: some View {
        VStack(spacing: 8) {
            Image(systemName: "checkmark.seal")
                .font(.system(size: 30))
                .foregroundStyle(.tertiary)
            Text("先在「概览」选择 IPA")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding(.top, 40)
        }
    }

    @ViewBuilder
    private var profileCard: some View {
        let p = engine.result.provision
        SectionCard(title: "描述文件", icon: "checkmark.seal") {
            if p.rawError.isEmpty {
                KVRow(k: "名称", v: p.name)
                KVRow(k: "团队", v: p.teamName + "（" + p.teamID + "）")
                KVRow(k: "创建", v: p.created)
                KVRow(k: "到期", v: p.expires)
                KVRow(k: "授权范围", v: p.bundleIDInProfile)
                KVRow(k: "授权设备", v: p.deviceCount == 0 ? "无（企业分发/开发通用）" : "\(p.deviceCount) 台")
            } else {
                Text(p.rawError).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var entCard: some View {
        let ents = engine.result.provision.entitlements
        SectionCard(title: "权限 (\(ents.count))", icon: "lock.shield") {
            if ents.isEmpty {
                Text("无权限信息").font(.footnote).foregroundStyle(.secondary)
            } else {
                entRows(ents)
            }
        }
    }

    private func entRows(_ list: [EntKV]) -> some View {
        ForEach(list) { e in
            VStack(alignment: .leading, spacing: 1) {
                Text(e.key)
                    .font(.system(size: 11, design: .monospaced).weight(.medium))
                Text(e.value)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            .padding(.vertical, 2)
        }
    }

    @ViewBuilder
    private var dylibCard: some View {
        let libs = engine.result.dylibs
        SectionCard(title: "依赖库 (\(libs.count))", icon: "link") {
            dylibRows(libs)
        }
    }

    private func dylibRows(_ libs: [MachDylib]) -> some View {
        ForEach(libs) { lib in
            HStack(spacing: 6) {
                Image(systemName: lib.weak ? "link.badge.plus" : "link")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                Text(lib.path)
                    .font(.system(size: 11, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .padding(.vertical, 2)
        }
    }
}
