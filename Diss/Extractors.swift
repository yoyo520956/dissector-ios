import Foundation

// 字符串/类名/方法名/描述文件提取

enum Extractors {

    // MARK: - C 字符串段扫描

    static func cStrings(from data: Data, limit: Int = 200_000) -> [String] {
        let b = [UInt8](data)
        var out: [String] = []
        out.reserveCapacity(1024)
        var i = 0
        while i < b.count, out.count < limit {
            if b[i] < 0x20 || b[i] > 0x7e {
                i += 1
                continue
            }
            var e = i
            while e < b.count, b[e] >= 0x20, b[e] != 0x7f { e += 1 }
            if e - i >= 4, e < b.count {
                if let s = String(bytes: b[i..<e], encoding: .utf8), s.count >= 4 {
                    out.append(s)
                }
            }
            i = e + 1
        }
        return out
    }

    // MARK: - ObjC 类/方法

    static func objcNames(_ strings: [String]) -> (classes: [String], methods: [String]) {
        var classes: Set<String> = []
        var methods: Set<String> = []
        for s in strings {
            if s.contains(" "), s.contains(":") {
                methods.insert(s)
            } else if looksLikeClass(s) {
                classes.insert(s)
            }
        }
        return (classes.sorted(), methods.sorted())
    }

    private static func looksLikeClass(_ s: String) -> Bool {
        guard s.count >= 3, s.count <= 128 else { return false }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
        guard s.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return false }
        guard let f = s.first else { return false }
        return !f.isNumber
    }

    // MARK: - 描述文件（embedded.mobileprovision）

    static func provision(from raw: Data) -> ProvisionInfo {
        var info = ProvisionInfo()
        guard let text = String(bytes: raw, encoding: .isoLatin1) ?? String(data: raw, encoding: .utf8) else {
            info.rawError = "无法读取描述文件"
            return info
        }
        guard let s = text.range(of: "<?xml"),
              let e = text.range(of: "</plist>") else {
            info.rawError = "未找到内嵌 plist（可能非分发描述文件）"
            return info
        }
        let xml = String(text[s.lowerBound..<e.upperBound])
        guard let d = xml.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] else {
            info.rawError = "内嵌 plist 解析失败"
            return info
        }
        info.name = plist["Name"] as? String ?? ""
        info.teamName = plist["TeamName"] as? String ?? ""
        if let team = plist["TeamIdentifier"] as? [String], let first = team.first {
            info.teamID = first
        }
        info.created = dateText(plist["CreationDate"])
        info.expires = dateText(plist["ExpirationDate"])
        if let ae = plist["ApplicationIdentifierPrefix"] as? [String], let pfx = ae.first {
            info.appIDPrefix = pfx
        }
        if let ent = plist["Entitlements"] as? [String: Any] {
            if let bid = ent["application-identifier"] as? String {
                info.bundleIDInProfile = bid
            }
            for key in ent.keys.sorted() {
                var text2 = ""
                if let v = ent[key] as? String { text2 = v }
                else if let v = ent[key] as? Bool { text2 = v ? "true" : "false" }
                else if let v = ent[key] as? Int { text2 = String(v) }
                else if let v = ent[key] as? [Any] { text2 = "数组（\(v.count) 项）" }
                else if let v = ent[key] as? [String: Any] { text2 = "字典（\(v.count) 键）" }
                else { text2 = "…" }
                info.entitlements.append(EntKV(id: info.entitlements.count, key: key, value: text2))
            }
        }
        if let devs = plist["ProvisionedDevices"] as? [Any] {
            info.deviceCount = devs.count
        }
        return info
    }

    private static func dateText(_ v: Any?) -> String {
        guard let d = v as? Date else { return "" }
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        f.timeZone = TimeZone(identifier: "Asia/Shanghai")
        return f.string(from: d)
    }

    // MARK: - Info.plist

    static func appInfo(from plistData: Data) -> AppInfo {
        var a = AppInfo()
        guard let plist = try? PropertyListSerialization.propertyList(
            from: plistData, format: nil) as? [String: Any] else { return a }
        a.displayName = plist["CFBundleDisplayName"] as? String
            ?? plist["CFBundleName"] as? String ?? ""
        a.bundleID = plist["CFBundleIdentifier"] as? String ?? ""
        a.version = plist["CFBundleShortVersionString"] as? String ?? ""
        a.build = plist["CFBundleVersion"] as? String ?? ""
        a.executable = plist["CFBundleExecutable"] as? String ?? ""
        a.minOS = plist["MinimumOSVersion"] as? String ?? ""
        a.platform = plist["DTPlatformName"] as? String ?? ""
        return a
    }
}
