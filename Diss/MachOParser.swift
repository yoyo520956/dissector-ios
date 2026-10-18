import Foundation

// 零依赖 Mach-O 解析器：
// fat 头 → arm64 slice → load commands → 段/节表、符号表、依赖库、加密状态、UUID、构建版本。
// 输入是已解压的主二进制 Data。

final class MachOParser {
    static let MH_EXECUTE: UInt32 = 0x2

    private let bytes: [UInt8]
    private var pos = 0
    private(set) var segments: [MachSegment] = []
    private(set) var allSections: [MachSection] = []
    private(set) var dylibs: [MachDylib] = []
    private(set) var summary = BinarySummary()

    init(data: Data) {
        bytes = [UInt8](data)
    }

    // MARK: - 入口

    func parse() throws {
        guard bytes.count > 64 else { throw IPAError.notZip("二进制过小") }
        let magic = ZipReader.u32(bytes, 0)
        if magic == 0xfeedfacf {
            summary.format = archName(cputype: ZipReader.u32(bytes, 4))
            try parseHeader(base: 0)
        } else if magic == 0xbebafeca || magic == 0xcafebabe {
            try parseFatAndPickArm64()
        } else {
            throw IPAError.unsupported("非 Mach-O（magic 0x\(String(magic, radix: 16))）")
        }
    }

    // MARK: - Fat 容器

    private func parseFatAndPickArm64() throws {
        // fat_header 全大端：magic(4) nfat_arch(4) → arch: cputype(4) cpusub(4) offset(4) size(4) align(4)
        let nfat = Int(Self.be32(bytes, 4))
        guard nfat > 0, nfat < 32 else { throw IPAError.notZip("fat 架构数异常") }
        var chosen = -1
        var idx = 0
        while idx < nfat {
            let o = 8 + idx * 20
            guard o + 20 <= bytes.count else { break }
            let cpu = Self.be32(bytes, o)
            if cpu == 0x0100000C { chosen = idx; break }   // CPU_TYPE_ARM64
            idx += 1
        }
        if chosen < 0 { chosen = 0 }
        let o = 8 + chosen * 20
        let off = UInt64(Self.be32(bytes, o + 8))
        let size = UInt64(Self.be32(bytes, o + 12))
        guard off + size <= UInt64(bytes.count) else { throw IPAError.notZip("fat slice 越界") }
        let sub = Array(bytes[Int(off)..<Int(off + size)])
        guard sub.count > 64, ZipReader.u32(sub, 0) == 0xfeedfacf else {
            throw IPAError.notZip("fat 内非 64 位 Mach-O")
        }
        summary.format = "arm64（fat 容器内 \(chosen + 1)/\(nfat)）"
        try parseHeader(base: 0, bytes: sub)
    }

    // MARK: - Header + Load Commands

    private func parseHeader(base: Int, bytes input: [UInt8]? = nil) throws {
        let b = input ?? bytes
        let cputype = ZipReader.u32(b, base + 4)
        let filetype = ZipReader.u32(b, base + 12)
        let ncmds = Int(ZipReader.u32(b, base + 16))
        if filetype == Self.MH_EXECUTE { summary.fileType = "主程序" }
        else if filetype == 0x6 { summary.fileType = "动态库" }
        else if filetype == 0x8 { summary.fileType = "bundle" }
        else { summary.fileType = "类型 \(filetype)" }
        if summary.format.isEmpty { summary.format = archName(cputype: cputype) }

        var p = base + 32
        var secIdx = 0
        var segIdx = 0
        for _ in 0..<min(ncmds, 4096) {
            guard p + 8 <= b.count else { break }
            let cmd = ZipReader.u32(b, p)
            let cmdsize = Int(ZipReader.u32(b, p + 4))
            guard cmdsize >= 8, p + cmdsize <= b.count else { break }
            let base = cmd & 0x7FFFFFFF   // 弱化命令带高位（如 0x80000018 = LC_LOAD_WEAK_DYLIB）
            switch base {
            case 0x19: // LC_SEGMENT_64
                let seg = readSegment(b, p, &secIdx, segIdx)
                segments.append(seg)
                segIdx += 1
            case 0x2:  // LC_SYMTAB
                readSymtab(b, p)
            case 0xc, 0xd, 0x18: // LC_LOAD_DYLIB / ID / WEAK（含高位变体）
                let weak = (base == 0x18)
                readDylib(b, p, weak)
            case 0x2c: // LC_ENCRYPTION_INFO_64
                summary.encrypted = Int(ZipReader.u32(b, p + 16))
            case 0x1b: // LC_UUID
                if p + 24 <= b.count {
                    summary.uuid = HexTool.uuidText(Data(b[(p+8)..<(p+24)]))
                }
            case 0x25: // LC_BUILD_VERSION
                let platform = ZipReader.u32(b, p + 8)
                let minos = versionText(ZipReader.u32(b, p + 12))
                let sdk = versionText(ZipReader.u32(b, p + 16))
                summary.minOS = minos
                summary.sdkVersion = sdk
                summary.minOS += "（\(platformName(platform))）"
            default:
                break
            }
            p += cmdsize
        }
        summary.dylibCount = dylibs.count
    }

    // MARK: - Segment / Section

    private func readSegment(_ b: [UInt8], _ p: Int, _ secIdx: inout Int, _ segIdx: Int) -> MachSegment {
        let segName = cstr(b, p + 8, 16)
        let vmaddr = ZipReader.u64(b, p + 16)
        let vmSize = ZipReader.u64(b, p + 24)
        let fileOff = ZipReader.u64(b, p + 32)
        let fileSize = ZipReader.u64(b, p + 40)
        let nsects = Int(ZipReader.u32(b, p + 64))
        var secs: [MachSection] = []
        var s = p + 72
        for _ in 0..<min(nsects, 256) {
            guard s + 80 <= b.count else { break }
            let sectName = cstr(b, s, 16)
            let sectSeg = cstr(b, s + 16, 16)
            let addr = ZipReader.u64(b, s + 32)
            let size = ZipReader.u64(b, s + 40)
            let offset = UInt64(ZipReader.u32(b, s + 48))
            let sec = MachSection(id: secIdx, segment: sectSeg, name: sectName,
                                  addr: addr, size: size, fileOffset: offset)
            secs.append(sec)
            allSections.append(sec)
            secIdx += 1
            s += 80
        }
        return MachSegment(id: segIdx, name: segName, vmaddr: vmaddr,
                           vmSize: vmSize, fileOff: fileOff,
                           fileSize: fileSize, sections: secs)
    }

    // MARK: - Symbol Table

    private func readSymtab(_ b: [UInt8], _ p: Int) {
        let symoff = Int(ZipReader.u32(b, p + 8))
        let nsyms = Int(ZipReader.u32(b, p + 12))
        let stroff = Int(ZipReader.u32(b, p + 16))
        let strsize = Int(ZipReader.u32(b, p + 20))
        guard symoff > 0, stroff > 0, stroff + strsize <= b.count else { return }
        var names: [String] = []
        var i = 0
        let cap = min(nsyms, 200_000)
        while i < cap {
            let o = symoff + i * 16
            guard o + 16 <= b.count else { break }
            let strx = Int(ZipReader.u32(b, o))
            let ntype = b[o + 4]
            if strx < strsize, (ntype & 0x0e) == 0x0e || (ntype & 0x01) == 0x01 {
                let name = cstr(b, stroff + strx, 512)
                if !name.isEmpty { names.append(name) }
            }
            // 全量符号（带地址）：nlist64 = n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(8)
            let value = ZipReader.u64(b, o + 8)
            if value > 0 {
                var kind = "未知"
                if (ntype & 0x0e) == 0x0e {
                    kind = (ntype & 0x01) == 0x01 ? "外部" : "本地"
                }
                let name = cstr(b, stroff + strx, 512)
                if !name.isEmpty, symbolsFull.count < 200_000 {
                    symbolsFull.append(MachSymbol(id: symbolsFull.count, name: name, value: value, kind: kind))
                }
            }
            i += 1
        }
        summary.symbolCount = names.count
        symbolsRaw = names
        strTabRange = stroff..<(stroff + strsize)
    }

    private(set) var symbolsRaw: [String] = []
    private(set) var symbolsFull: [MachSymbol] = []
    private(set) var strTabRange: Range<Int>?

    // MARK: - Dylib

    private func readDylib(_ b: [UInt8], _ p: Int, _ weak: Bool) {
        let nameOff = Int(ZipReader.u32(b, p + 8))
        guard nameOff > 0, p + nameOff < b.count else { return }
        let path = cstr(b, p + nameOff, 1024)
        guard !path.isEmpty else { return }
        dylibs.append(MachDylib(id: dylibs.count, path: path, weak: weak))
    }

    // MARK: - 工具

    private func cstr(_ b: [UInt8], _ off: Int, _ maxLen: Int) -> String {
        guard off >= 0, off < b.count else { return "" }
        var e = off
        let end = min(b.count, off + maxLen)
        while e < end, b[e] != 0 { e += 1 }
        return String(bytes: b[off..<e], encoding: .utf8)
            ?? String(bytes: b[off..<e], encoding: .isoLatin1)
            ?? ""
    }

    static func be32(_ b: [UInt8], _ o: Int) -> UInt32 {
        (UInt32(b[o]) << 24) | (UInt32(b[o+1]) << 16) | (UInt32(b[o+2]) << 8) | UInt32(b[o+3])
    }

    private func archName(cputype: UInt32) -> String {
        switch cputype {
        case 0x0100000C: return "arm64"
        case 0x01000007: return "x86_64"
        case 0x0000000C: return "arm"
        case 0x00000007: return "i386"
        default: return "cpu 0x\(String(cputype, radix: 16))"
        }
    }

    private func versionText(_ v: UInt32) -> String {
        let a = Int(v >> 16), bb = Int((v >> 8) & 0xff), c = Int(v & 0xff)
        return "\(a).\(bb).\(c)"
    }

    private func platformName(_ p: UInt32) -> String {
        switch p {
        case 2: return "iOS"
        case 6: return "iOS 模拟器"
        case 1: return "macOS"
        case 3: return "tvOS"
        case 7: return "visionOS"
        default: return "平台 \(p)"
        }
    }

    // MARK: - Section 数据读取

    func sectionData(_ sec: MachSection, from data: Data, limit: Int) -> Data {
        let off = Int(sec.fileOffset)
        guard off < data.count else { return Data() }
        let n = min(Int(sec.size), limit, data.count - off)
        return data.subdata(in: off..<(off + n))
    }
}
