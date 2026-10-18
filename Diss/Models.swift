import Foundation

// MARK: - ZIP 条目

struct ZipEntry: Identifiable, Hashable {
    let id: Int              // central directory 序号
    let path: String
    let size: UInt64         // 解压后
    let packed: UInt64       // 压缩后
    let method: UInt16       // 0=store 8=deflate
    let offset: UInt64       // local header 偏移
    let crc: UInt32          // 目录登记的 CRC32
    var isDirectory: Bool { path.hasSuffix("/") }
    var fileName: String {
        (path as NSString).lastPathComponent
    }
}

// MARK: - Mach-O 结构

struct MachSection: Identifiable, Hashable {
    let id: Int
    let segment: String
    let name: String
    let addr: UInt64
    let size: UInt64
    let fileOffset: UInt64

    var displayName: String { "\(segment).\(name)" }
    var sizeText: String { ByteFmt.text(size) }
}

struct MachSegment: Identifiable, Hashable {
    let id: Int
    let name: String
    let vmaddr: UInt64        // 段虚拟起始地址
    let vmSize: UInt64        // 虚拟大小
    let fileOff: UInt64       // 文件内偏移（VM→file 映射用）
    let fileSize: UInt64      // 文件内大小（bss 段可小于 vmSize）
    let sections: [MachSection]
}

struct MachDylib: Identifiable, Hashable {
    let id: Int
    let path: String
    let weak: Bool
    var name: String { (path as NSString).lastPathComponent }
}

// MARK: - 符号（带地址，供反汇编标注）

struct MachSymbol: Identifiable, Hashable {
    let id: Int
    let name: String
    let value: UInt64        // 符号虚拟地址
    let kind: String         // "func" / "objc类" / "数据" / "未知"
}

// MARK: - 摘要信息

struct BinarySummary: Hashable {
    var format: String = ""          // "arm64 (thin)" / "arm64 (fat 内 1/2)"
    var minOS: String = ""           // 最低系统版本
    var sdkVersion: String = ""
    var uuid: String = ""
    var encrypted: Int = -1          // cryptid: 1=App Store 加密 0=已解密
    var fileType: String = ""        // MH_EXECUTE 等
    var fileSize: UInt64 = 0
    var symbolCount: Int = 0
    var classCount: Int = 0
    var methodCount: Int = 0
    var dylibCount: Int = 0
}

struct AppInfo: Hashable {
    var displayName: String = ""
    var bundleID: String = ""
    var version: String = ""
    var build: String = ""
    var executable: String = ""
    var minOS: String = ""
    var platform: String = ""
}

struct EntKV: Identifiable, Hashable {
    let id: Int
    let key: String
    let value: String
}

struct ProvisionInfo: Hashable {
    var name: String = ""
    var teamName: String = ""
    var teamID: String = ""
    var created: String = ""
    var expires: String = ""
    var appIDPrefix: String = ""
    var bundleIDInProfile: String = ""
    var deviceCount: Int = 0
    var entitlements: [EntKV] = []
    var rawError: String = ""
}

// MARK: - 分析结果

final class AnalysisResult {
    var entries: [ZipEntry] = []
    var totalUncompressed: UInt64 = 0
    var appFolder: String = ""                    // Payload/XXX.app/
    var info: AppInfo = AppInfo()
    var summary: BinarySummary = BinarySummary()
    var segments: [MachSegment] = []
    var allSections: [MachSection] = []
    var dylibs: [MachDylib] = []
    var classNames: [String] = []
    var methodNames: [String] = []
    var cstrings: [String] = []
    var symbols: [String] = []
    var symbolsFull: [MachSymbol] = []      // 带地址符号（反汇编标注用）
    var swiftSymbols: [String] = []          // 已还原的 Swift 符号
    var textSection: MachSection?            // __text 段（反汇编入口）
    var provision: ProvisionInfo = ProvisionInfo()
    var warnings: [String] = []
}

// MARK: - 工具

enum ByteFmt {
    static func text(_ v: UInt64) -> String {
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f.string(fromByteCount: Int64(v))
    }
}

enum HexTool {
    static func dump(_ data: Data, limit: Int = 256) -> String {
        let n = min(data.count, limit)
        var lines: [String] = []
        var i = 0
        while i < n {
            let end = min(i + 16, n)
            let slice = data.subdata(in: i..<end)
            var hex = ""
            var ascii = ""
            for b in slice {
                hex += String(format: "%02x ", b)
                ascii += (b >= 0x20 && b < 0x7f) ? String(UnicodeScalar(b)) : "."
            }
            let pad = String(repeating: " ", count: max(0, 48 - hex.count))
            lines.append(String(format: "%08x  ", i) + hex + pad + ascii)
            i = end
        }
        if data.count > limit {
            lines.append("…… 后续 \(ByteFmt.text(UInt64(data.count - limit))) 略")
        }
        return lines.joined(separator: "\n")
    }

    static func uuidText(_ d: Data) -> String {
        guard d.count >= 16 else { return "" }
        let b = [UInt8](d.prefix(16))
        let s = b.map { String(format: "%02X", $0) }
        return "\(s[0..<(4)].joined())-\(s[4..<6].joined())-\(s[6..<8].joined())-\(s[8..<10].joined())-\(s[10..<16].joined())"
    }
}
