import Foundation

// MARK: - 网络接口提取：从字符串池里挖 URL / 域名 / API 路径

enum NetworkExtract {

    struct Hit: Identifiable, Hashable {
        let id: Int
        let value: String
        var count: Int
    }

    struct Report {
        var urls: [Hit] = []
        var hosts: [Hit] = []
        var paths: [Hit] = []
        var total: Int { urls.count + hosts.count + paths.count }
    }

    private static let tldPattern = "(?:com|cn|net|org|io|app|dev|xyz|top|cc|me|co|tv|ai|cloud|site|online|tech|vip|shop|link|pro|fun|zone|info|biz|wang|ltd|group)"

    static func extract(_ strings: [String]) -> Report {
        var urlMap: [String: Int] = [:]
        var hostMap: [String: Int] = [:]
        var pathMap: [String: Int] = [:]

        let urlRe = try? NSRegularExpression(pattern: "https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\\[\\]-]+")
        let hostRe = try? NSRegularExpression(pattern: "(?:[a-zA-Z0-9-]{1,63}\\.)+\(tldPattern)(?::\\d+)?(?![A-Za-z0-9-])")
        let pathRe = try? NSRegularExpression(pattern: "/(?:api|v[0-9]{1,2}|app|service|gateway|open|user|order|pay|login|auth|config)/[A-Za-z0-9_/.-]{2,80}")

        for s in strings {
            guard s.count < 4000 else { continue }
            if let re = urlRe {
                for m in matches(re, s) {
                    urlMap[m, default: 0] += 1
                }
            }
            if let re = hostRe {
                for m in matches(re, s) {
                    // 排除苹果自家元数据域名噪音
                    if m.hasSuffix(".apple.com") || m.hasSuffix("schema.org") { continue }
                    hostMap[m, default: 0] += 1
                }
            }
            if let re = pathRe {
                for m in matches(re, s) {
                    pathMap[m, default: 0] += 1
                }
            }
        }

        func toHits(_ d: [String: Int]) -> [Hit] {
            d.sorted { $0.value > $1.value }.enumerated()
                .map { Hit(id: $0.offset, value: $0.element.key, count: $0.element.value) }
        }

        var rep = Report()
        rep.urls = toHits(urlMap)
        rep.hosts = toHits(hostMap.filter { k, _ in !urlMap.keys.contains(where: { $0.contains(k) }) })
        rep.paths = toHits(pathMap)
        return rep
    }

    private static func matches(_ re: NSRegularExpression, _ s: String) -> [String] {
        let ns = s as NSString
        return re.matches(in: s, range: NSRange(location: 0, length: ns.length))
            .map { ns.substring(with: $0.range) }
    }

    static func reportText(_ r: Report) -> String {
        var lines: [String] = []
        lines.append("// 由拆解者 Dissector 提取的网络接口")
        lines.append("")
        if !r.urls.isEmpty {
            lines.append("== 完整 URL (\(r.urls.count)) ==")
            for h in r.urls {
                lines.append(h.count > 1 ? "\(h.value)   （出现 \(h.count) 次）" : h.value)
            }
            lines.append("")
        }
        if !r.hosts.isEmpty {
            lines.append("== 域名 (\(r.hosts.count)) ==")
            for h in r.hosts {
                lines.append(h.count > 1 ? "\(h.value)   （出现 \(h.count) 次）" : h.value)
            }
            lines.append("")
        }
        if !r.paths.isEmpty {
            lines.append("== API 路径 (\(r.paths.count)) ==")
            for h in r.paths {
                lines.append(h.count > 1 ? "\(h.value)   （出现 \(h.count) 次）" : h.value)
            }
        }
        return lines.joined(separator: "\n")
    }
}
