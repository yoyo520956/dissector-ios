import Foundation

// MARK: - Swift 符号还原（简化版 demangler，零依赖）
// 目标：把 $s8IPAScope9ZipReaderC6entrySSF 这类符号还原为可读的
// "IPAScope.ZipReader.entry()" 形式。不求完整语义，只求 80% 可读性。
// 同时处理 ObjC-Swift 桥接符号 __TtC<module><class>。

enum SwiftDemangle {

    static func isSwiftMangled(_ s: String) -> Bool {
        s.hasPrefix("_$s") || s.hasPrefix("$s") || s.hasPrefix("__TtC")
    }

    // 返回 (还原结果, 是否成功)
    static func demangle(_ raw: String) -> String {
        if raw.hasPrefix("__TtC") || raw.hasPrefix("_TtC") {
            return parseTtBridge(raw)
        }
        var body = raw
        if body.hasPrefix("_$s") {
            body.removeFirst(2)
        } else if body.hasPrefix("$s") {
            body.removeFirst(2)
        } else {
            return raw
        }
        return parseWordStream(body, raw: raw)
    }

    // MARK: - 主体词流解析

    // 词法：[长度][单词]...，词后可能跟 kind 字符（C=class V=struct O=enum P=protocol）
    // 遇到非数字即停（类型引用 SS/Si/替换码等不再往下解）
    private static func parseWordStream(_ body: String, raw: String) -> String {
        var words: [String] = []
        var kindText = ""
        var memberKind = ""
        var i = body.startIndex
        let end = body.endIndex

        while i < end {
            // 读数字（长度）
            var numStr = ""
            while i < end, let d = body[i].wholeNumberValue, d >= 0, d <= 9 {
                numStr.append(body[i])
                i = body.index(after: i)
            }
            guard !numStr.isEmpty, let n = Int(numStr), n > 0, n < 256 else { break }
            // 读单词
            guard let wordEnd = body.index(i, offsetBy: n, limitedBy: end) else { break }
            let word = String(body[i..<wordEnd])
            // 单词必须全是可打印 ASCII（mangled 名都如此），否则解析走偏
            if word.isEmpty || word.contains(where: { $0.asciiValue == nil || $0.asciiValue! < 0x20 }) { break }
            words.append(word)
            i = wordEnd
            // kind 字符
            if i < end {
                let k = body[i]
                if "CVOP".contains(k) {
                    switch k {
                    case "C": kindText = "class"
                    case "V": kindText = "struct"
                    case "O": kindText = "enum"
                    case "P": kindText = "protocol"
                    default: break
                    }
                    i = body.index(after: i)
                    continue
                }
                // 成员 kind（首个词是模块，后面的可能带成员标记）
                if words.count >= 2 {
                    if k == "F" || k == "f" {
                        memberKind = "()"
                        i = body.index(after: i)
                        break
                    }
                    if k == "v" {
                        memberKind = "（属性）"
                        i = body.index(after: i)
                        break
                    }
                    if k == "y" {
                        // 参数块开始：函数签名
                        memberKind = "()"
                        break
                    }
                }
                break
            }
        }

        guard !words.isEmpty else { return raw }
        var result = words.joined(separator: ".")
        if !memberKind.isEmpty { result += memberKind }
        if !kindText.isEmpty { result += "（\(kindText)）" }
        return result
    }

    // MARK: - ObjC-Swift 桥接：__TtC<module><class> / _TtC...

    private static func parseTtBridge(_ raw: String) -> String {
        // __TtC8IPAScope9ZipReader → IPAScope.ZipReader（class）
        var body = raw
        for pfx in ["__TtC", "_TtC", "__TtV", "_TtV", "__TtO", "_TtO"] {
            if body.hasPrefix(pfx) {
                body.removeFirst(pfx.count)
                let words = readWords(body, maxCount: 4)
                if words.count >= 2 {
                    let kind = pfx.hasSuffix("C") ? "class" : (pfx.hasSuffix("V") ? "struct" : "enum")
                    return words.joined(separator: ".") + "（\(kind)）"
                }
            }
        }
        return raw
    }

    private static func readWords(_ s: String, maxCount: Int) -> [String] {
        var out: [String] = []
        var i = s.startIndex
        let end = s.endIndex
        while out.count < maxCount, i < end {
            var numStr = ""
            while i < end, let d = s[i].wholeNumberValue, d >= 0, d <= 9 {
                numStr.append(s[i])
                i = s.index(after: i)
            }
            guard !numStr.isEmpty, let n = Int(numStr), n > 0, n < 256 else { break }
            guard let wordEnd = s.index(i, offsetBy: n, limitedBy: end) else { break }
            out.append(String(s[i..<wordEnd]))
            i = wordEnd
        }
        return out
    }

    // MARK: - 批量

    static func demangleList(_ names: [String]) -> [String] {
        var out: [String] = []
        for n in names where isSwiftMangled(n) {
            let d = demangle(n)
            if d != n { out.append(d) }
        }
        return Array(Set(out)).sorted()
    }
}
