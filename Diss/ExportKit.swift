import Foundation

// 专业功能 · 一键导出完整工程素材包
// 产物结构（zip）：
//   README.txt            应用信息 + 素材说明
//   classes/*.h           每个 ObjC 类一个头文件 + all-classdump.h 合集
//   symbols.txt           全量符号表（限 40 万行）
//   strings.txt           全量字符串
//   network.txt           网络接口提取
//   report.html           精简分析报告
//   ui/                   UI 文件原样（storyboardc / nib / xib / strings）
//   ui-xml/               可解析为 bplist 的 UI 文件转可读 XML
//   resources/            其余资源文件（单文件 ≤16MB，总量 ≤120MB）
//   metadata/             Info.plist / embedded.mobileprovision

enum ExportKit {

    struct Snapshot {
        let fileName: String
        let url: URL
        let bin: Data
        let segments: [MachSegment]
        let sections: [MachSection]
        let entries: [ZipEntry]
        let appFolder: String
        let result: AnalysisResult
    }

    static func buildProject(_ s: Snapshot,
                             progress: @escaping @Sendable (String, Int, Int) -> Void) -> (Data, Int)? {
        var files: [ZIPEntry] = []
        var skipped = 0
        var totalBytes = 0
        let maxTotal = 120 * 1024 * 1024
        let maxFile = 16 * 1024 * 1024

        func add(_ path: String, _ data: Data, countIt: Bool = true) -> Bool {
            guard data.count <= maxFile else { skipped += 1; return false }
            guard totalBytes + data.count <= maxTotal else { skipped += 1; return false }
            files.append(ZIPEntry(path: path, data: data))
            if countIt { totalBytes += data.count }
            return true
        }

        // 自己的 reader（避免与主线程 FileHandle 竞争）
        guard let reader = try? ZipReader(url: s.url) else { return nil }

        // ① README
        let info = s.result.info
        var readme = """
        ══════════════════════════════════════
          拆解者 Dissector · 工程素材包
        ══════════════════════════════════════
        来源 IPA: \(s.fileName)
        显示名:   \(info.displayName)
        Bundle:   \(info.bundleID)
        版本:     \(info.version) (\(info.build))
        主二进制: \(info.executable) · \(ByteFmt.text(s.result.summary.fileSize))
        生成于:   \(Date().formatted())

        【素材说明 · 如何用这些内容重建 App】
        1. classes/  —— ObjC 类完整接口声明（.h），可直接读类名/父类/方法/属性/ivar，
                        是重建代码结构的第一手资料。
        2. ui/       —— 原样导出 Storyboard/NIB/XIB/本地化文件（App 的界面定义都在这里）。
           ui-xml/   —— 其中可反序列化的已转成 XML，可直接查看界面控件树与约束。
        3. resources/—— 图片/JSON/plist/字体等全部素材，重建界面时直接复用。
        4. symbols.txt / strings.txt —— 全部符号与字符串，用于还原命名与文案。
        5. report.html —— 应用信息/结构/网络/风控/隐私汇总报告。
        6. network.txt —— 提取的所有 URL / 域名 / API 路径。
        说明: 本包为静态分析产物，用于学习与研究目的。
        """
        _ = add("README.txt", Data(readme.utf8))

        // ② 类头文件
        progress("导出类转储", 0, 1)
        let dumper = ObjCDumper(data: s.bin, segments: s.segments, sections: s.sections)
        let classes = dumper.dump()
        for (i, c) in classes.enumerated() {
            let h = ObjCDumper.headerText([c])
            _ = add("classes/\(c.name).h", Data(h.utf8))
            if i % 20 == 0 { progress("导出类头文件", i, classes.count) }
        }
        _ = add("classes/all-classdump.h", Data(ObjCDumper.headerText(classes).utf8))
        progress("导出类头文件", classes.count, max(classes.count, 1))

        // ③ 符号表
        progress("导出符号表", 0, 1)
        var symText = "# 符号表 · \(s.result.symbolsFull.count) 条\n"
        for sym in s.result.symbolsFull.prefix(400_000) {
            symText += String(format: "0x%llX\t%@\n", sym.value, sym.name)
        }
        _ = add("symbols.txt", Data(symText.utf8))

        // ④ 字符串
        progress("导出字符串", 0, 1)
        _ = add("strings.txt", Data(s.result.cstrings.prefix(400_000).joined(separator: "\n").utf8))

        // ⑤ 网络
        let net = NetworkExtract.extract(s.result.cstrings)
        _ = add("network.txt", Data(NetworkExtract.reportText(net).utf8))

        // ⑥ 精简报告
        progress("生成报告", 0, 1)
        _ = add("report.html", Data(buildReport(s, classes: classes, net: net).utf8))

        // ⑦ UI 文件 + ⑧ 资源（按类型分流）
        progress("导出 UI 与资源", 0, s.entries.count)
        let uiExts: Set<String> = ["storyboardc", "nib", "xib", "storyboard", "strings", "stringsdict"]
        let metaNames: Set<String> = ["Info.plist", "PkgInfo"]
        var done = 0
        for e in s.entries {
            done += 1
            if done % 15 == 0 { progress("导出 UI 与资源", done, s.entries.count) }
            guard !e.isDirectory else { continue }
            guard let d = try? reader.data(for: e, maxBytes: maxFile) else { skipped += 1; continue }
            var rel = e.path
            if rel.hasPrefix(s.appFolder) { rel = String(rel.dropFirst(s.appFolder.count)) }
            let ext = (rel as NSString).pathExtension.lowercased()
            let base = (rel as NSString).lastPathComponent

            // metadata
            if rel == "Info.plist" || rel == "embedded.mobileprovision" || base == "PkgInfo" {
                _ = add("metadata/\(base)", d)
                continue
            }
            // UI 类：原样 + 可读化
            if uiExts.contains(ext) || rel.contains(".storyboardc/") || rel.contains(".nib") {
                _ = add("ui/\(rel)", d)
                if let obj = try? PropertyListSerialization.propertyList(from: d, format: nil),
                   let xml = try? PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0) {
                    _ = add("ui-xml/\(rel).xml", xml)
                }
                continue
            }
            // 跳过主二进制本身（已在硬盘上）
            if rel == s.result.info.executable { continue }
            // 其余资源
            if rel.hasPrefix("Frameworks/") && ext == "dylib" { skipped += 1; continue }
            if ext == "car" && d.count > maxFile { skipped += 1; continue }
            _ = add("resources/\(rel)", d)
        }
        progress("导出 UI 与资源", s.entries.count, s.entries.count)

        // 打包
        progress("压缩打包", 0, 1)
        guard let zip = ZIPWriter.write(files) else { return nil }
        progress("压缩打包", 1, 1)
        return (zip, skipped)
    }

    // MARK: - 精简报告（不依赖主线程引擎）

    private static func buildReport(_ s: Snapshot, classes: [ObjCClassDump],
                                    net: NetworkExtract.Report) -> String {
        func esc(_ t: String) -> String {
            t.replacingOccurrences(of: "&", with: "\u{26}amp;")
                .replacingOccurrences(of: "<", with: "\u{26}lt;")
                .replacingOccurrences(of: ">", with: "\u{26}gt;")
        }
        let r = s.result
        var h = """
        <!DOCTYPE html><html><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>拆解者报告 · \(esc(s.fileName))</title><style>
        body{font-family:-apple-system,sans-serif;margin:0;background:#f2f4f8;color:#1a1d24}
        .wrap{max-width:760px;margin:0 auto;padding:16px}
        h1{font-size:21px}h2{font-size:16px;color:#0a58c8;border-left:4px solid #0a58c8;padding-left:8px;margin:22px 0 8px}
        .card{background:#fff;border-radius:12px;padding:12px 14px;margin:8px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
        table{width:100%;border-collapse:collapse;font-size:13px}
        td,th{padding:5px 8px;border-bottom:1px solid #eef0f4;text-align:left;word-break:break-all}
        th{color:#666;background:#f8f9fb}code{background:#eef2f8;padding:1px 5px;border-radius:5px;font-size:12px}
        .muted{color:#888;font-size:12px}</style></head><body><div class="wrap">
        <h1>🧩 拆解者 · 工程素材报告</h1>
        <p class="muted">\(esc(s.fileName)) · \(Date().formatted())</p>
        <h2>① 应用信息</h2><div class="card"><table>
        <tr><td>显示名</td><td>\(esc(r.info.displayName))</td></tr>
        <tr><td>Bundle ID</td><td><code>\(esc(r.info.bundleID))</code></td></tr>
        <tr><td>版本</td><td>\(esc(r.info.version)) (\(esc(r.info.build)))</td></tr>
        <tr><td>主二进制</td><td>\(esc(r.info.executable)) · \(ByteFmt.text(r.summary.fileSize))</td></tr>
        <tr><td>最低系统</td><td>\(esc(r.summary.minOS))</td></tr>
        <tr><td>符号 / 类</td><td>\(r.summary.symbolCount) / \(classes.count)</td></tr>
        <tr><td>依赖库</td><td>\(r.dylibs.count)</td></tr>
        </table></div>
        <h2>② 依赖库（\(r.dylibs.count)）</h2><div class="card"><table>
        """
        for d in r.dylibs.prefix(120) {
            h += "<tr><td><code>\(esc(d.path))</code></td><td>\(d.weak ? "weak" : "")</td></tr>"
        }
        h += "</table></div><h2>③ ObjC 类（\(classes.count)，前 60）</h2>"
        for c in classes.prefix(60) {
            let sup = c.superName.isEmpty ? "" : " : \(esc(c.superName))"
            h += "<div class='card'><code>@interface \(esc(c.name))\(sup)</code>"
            for m in c.instanceMethods.prefix(25) {
                h += "<br><span class='muted'>\(esc(m.readable))</span>"
            }
            if c.methodCount > 25 { h += "<br><span class='muted'>… 共 \(c.methodCount) 方法</span>" }
            h += "</div>"
        }
        h += "<h2>④ 网络接口</h2><div class='card'>"
        for u in net.urls.prefix(80) { h += "<code>\(esc(u.value))</code><br>" }
        h += "</div><h2>⑤ 越狱风控特征</h2><div class='card'>"
        let jb = JailbreakScan.scan(r.cstrings)
        if jb.isEmpty { h += "<span class='muted'>未发现</span>" }
        for j in jb.prefix(30) {
            h += "<code>\(esc(j.sample))</code> <span class='muted'>— \(esc(j.category))</span><br>"
        }
        h += "</div><p class='muted'>拆解者 Dissector 生成</p></div></body></html>"
        return h
    }
}
