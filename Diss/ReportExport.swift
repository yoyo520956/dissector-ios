import Foundation

// 专业功能 · 完整 HTML 分析报告
// 概览 / 结构 / 依赖库 / 类转储 / 符号 / 字符串 / 网络 / 风控 / 隐私 九段合一
// 保存到 exports/ 后可分享

enum ReportExport {

    static func esc(_ s: String) -> String {
        s.replacingOccurrences(of: "<", with: "<")
            .replacingOccurrences(of: ">", with: ">")
            .replacingOccurrences(of: "&", with: "&")
    }

    static func build(engine: AnalysisEngine) -> String {
        let r = engine.result
        var h = """
        <!DOCTYPE html><html><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>拆解者报告 · \(esc(engine.fileName))</title>
        <style>
        body{font-family:-apple-system,sans-serif;margin:0;background:#f2f4f8;color:#1a1d24}
        .wrap{max-width:760px;margin:0 auto;padding:16px}
        h1{font-size:22px;margin:8px 0} h2{font-size:17px;margin:24px 0 8px;color:#0a58c8;
        border-left:4px solid #0a58c8;padding-left:8px}
        .card{background:#fff;border-radius:12px;padding:12px 14px;margin:8px 0;
        box-shadow:0 1px 3px rgba(0,0,0,.08)}
        table{width:100%;border-collapse:collapse;font-size:13px}
        td,th{padding:5px 8px;border-bottom:1px solid #eef0f4;text-align:left;word-break:break-all}
        th{color:#666;font-weight:600;background:#f8f9fb}
        .kv td:first-child{color:#666;width:130px}
        code{background:#eef2f8;padding:1px 5px;border-radius:5px;font-size:12px}
        .muted{color:#888;font-size:12px}
        </style></head><body><div class="wrap">
        <h1>🧩 拆解者 · 分析报告</h1>
        <p class="muted">\(esc(engine.fileName)) · 生成于 \(Date().formatted())</p>
        """

        // ① 概览
        h += "<h2>① 应用信息</h2><div class='card'><table class='kv'>"
        let i = r.info
        h += "<tr><td>显示名</td><td>\(esc(i.displayName))</td></tr>"
        h += "<tr><td>Bundle ID</td><td><code>\(esc(i.bundleID))</code></td></tr>"
        h += "<tr><td>版本</td><td>\(esc(i.version)) (\(esc(i.build)))</td></tr>"
        h += "<tr><td>主二进制</td><td>\(esc(i.executable)) · \(ByteFmt.text(r.summary.fileSize))</td></tr>"
        h += "<tr><td>最低系统</td><td>\(esc(r.summary.minOS))</td></tr>"
        h += "<tr><td>UUID</td><td><code>\(esc(r.summary.uuid))</code></td></tr>"
        h += "<tr><td>加密位</td><td>cryptid=\(r.summary.encrypted)</td></tr>"
        h += "<tr><td>符号/类/方法</td><td>\(r.summary.symbolCount) / \(r.summary.classCount) / \(r.summary.methodCount)</td></tr>"
        h += "<tr><td>依赖库</td><td>\(r.dylibs.count)</td></tr>"
        h += "<tr><td>交叉引用</td><td>\(engine.xrefStats.sites) 个调用点 → \(engine.xrefStats.targets) 个目标</td></tr>"
        h += "</table></div>"

        // ② 段表
        h += "<h2>② Mach-O 段表</h2><div class='card'><table><tr><th>段</th><th>VM 地址</th><th>文件大小</th><th>节</th></tr>"
        for s in r.segments {
            h += "<tr><td>\(esc(s.name))</td><td><code>0x\(String(s.vmaddr, radix: 16))</code></td><td>\(ByteFmt.text(s.fileSize))</td><td>\(s.sections.count)</td></tr>"
        }
        h += "</table></div>"

        // ③ 依赖库
        h += "<h2>③ 依赖库（\(r.dylibs.count)）</h2><div class='card'><table>"
        for d in r.dylibs {
            h += "<tr><td>\(esc(d.path))</td><td>\(d.weak ? "weak" : "")</td></tr>"
        }
        h += "</table></div>"

        // ④ 类转储（前 80 类完整方法）
        let classes = engine.dumpClasses()
        h += "<h2>④ ObjC 类转储（\(classes.count) 类，显示前 80）</h2>"
        for c in classes.prefix(80) {
            let sup = c.superName.isEmpty ? "" : " : \(esc(c.superName))"
            h += "<div class='card'><code>@interface \(esc(c.name))\(sup)</code>"
            for m in c.instanceMethods.prefix(40) {
                h += "<br><span class='muted'>\(esc(m.readable))</span>"
            }
            if c.instanceMethods.count > 40 { h += "<br><span class='muted'>… 共 \(c.methodCount) 方法</span>" }
            h += "</div>"
        }

        // ⑤ 符号（前 150）
        h += "<h2>⑤ 符号表样本（前 150 / 共 \(r.symbolsFull.count)）</h2><div class='card'><table>"
        for s in r.symbolsFull.prefix(150) {
            h += "<tr><td><code>0x\(String(s.value, radix: 16))</code></td><td>\(esc(s.name))</td></tr>"
        }
        h += "</table></div>"

        // ⑥ 字符串（前 200）
        h += "<h2>⑥ 字符串样本（前 200 / 共 \(r.cstrings.count)）</h2><div class='card'>"
        for s in r.cstrings.prefix(200) {
            h += "<code>\(esc(s.prefix(120)))</code> "
        }
        h += "</div>"

        // ⑦ 网络
        let net = NetworkExtract.extract(r.cstrings)
        h += "<h2>⑦ 网络接口（URL \(net.urls.count) / Host \(net.hosts.count)）</h2><div class='card'>"
        for u in net.urls.prefix(80) { h += "<code>\(esc(u.text))</code><br>" }
        h += "</div>"

        // ⑧ 风控
        let jb = JailbreakScan.scan(r.cstrings)
        h += "<h2>⑧ 越狱风控特征（\(jb.count)）</h2><div class='card'>"
        if jb.isEmpty { h += "<span class='muted'>未发现越狱检测特征</span>" }
        for j in jb.prefix(40) {
            h += "<code>\(esc(j.sample))</code> <span class='muted'>— \(esc(j.category))</span><br>"
        }
        h += "</div>"

        // ⑨ 隐私
        let priv = engine.privacyProfile()
        h += "<h2>⑨ 隐私画像（\(priv.count)）</h2><div class='card'><table><tr><th>权限</th><th>依据</th></tr>"
        for p in priv.prefix(40) {
            h += "<tr><td>\(esc(p.name))</td><td>\(esc(p.codeEvidence))</td></tr>"
        }
        h += "</table></div>"

        h += "<p class='muted'>拆解者 Dissector 生成 · 设备端静态分析报告</p></div></body></html>"
        return h
    }
}
