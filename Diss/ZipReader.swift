import Foundation
import zlib
import CryptoKit

// 零依赖 ZIP 读取器：
// 只解析 EOCD + central directory，按需解压单条目（Compression raw deflate）。
// 适配 IPA 场景：大文件用 FileHandle 分段读，绝不整包进内存。

final class ZipReader {
    private let fh: FileHandle
    private let fileURL: URL
    /// 供导出模块使用（独立 reader 避免并发）
    var fileURLForExport: URL { fileURL }
    private let fileSize: UInt64
    private(set) var entries: [ZipEntry] = []
    private var entryByPath: [String: ZipEntry] = [:]
    private(set) var totalUncompressed: UInt64 = 0

    init(url: URL) throws {
        fh = try FileHandle(forReadingFrom: url)
        fileURL = url
        // 真实文件末尾：FileManager 属性会被 iCloud 占位文件欺骗，seekToEnd 永远可信
        let endPos = try fh.seekToEnd()
        fileSize = endPos
        try fh.seek(toOffset: 0)
        try locateCentralDirectory()
    }

    deinit {
        try? fh.close()
    }

    // MARK: - EOCD + Central Directory

    private func locateCentralDirectory() throws {
        // EOCD 固定 22 字节起，注释最多 65535 → 最多回扫 65557
        let scanLen = Int(min(fileSize, 65557 + 22))
        try fh.seek(toOffset: fileSize - UInt64(scanLen))
        let tail = fh.readData(ofLength: scanLen)
        let bytes = [UInt8](tail)
        var eocdPos = -1
        var i = bytes.count - 22
        while i >= 0 {
            if bytes[i] == 0x50, bytes[i+1] == 0x4b,
               bytes[i+2] == 0x05, bytes[i+3] == 0x06 {
                eocdPos = i
                break
            }
            i -= 1
        }
        guard eocdPos >= 0 else { throw IPAError.notZip("未找到 ZIP 结束标记（EOCD）") }

        let cdCount = Self.u16(bytes, eocdPos + 10)
        let cdSize = UInt64(Self.u32(bytes, eocdPos + 12))
        let cdOffset = UInt64(Self.u32(bytes, eocdPos + 16))

        try fh.seek(toOffset: cdOffset)
        let cdData = fh.readData(ofLength: Int(cdSize))
        let cd = [UInt8](cdData)

        var pos = 0
        var idx = 0
        while pos + 46 <= cd.count && idx < Int(cdCount) {
            guard cd[pos] == 0x50, cd[pos+1] == 0x4b, cd[pos+2] == 0x01, cd[pos+3] == 0x02 else { break }
            let method = Self.u16(cd, pos + 10)
            var packed = UInt64(Self.u32(cd, pos + 20))
            var size = UInt64(Self.u32(cd, pos + 24))
            let crc = Self.u32(cd, pos + 16)
            let nameLen = Int(Self.u16(cd, pos + 28))
            let extraLen = Int(Self.u16(cd, pos + 30))
            let commentLen = Int(Self.u16(cd, pos + 32))
            var localOff = UInt64(Self.u32(cd, pos + 42))
            guard pos + 46 + nameLen <= cd.count else { break }
            let name = String(bytes: cd[(pos+46)..<(pos+46+nameLen)], encoding: .utf8) ?? ""
            // ZIP64：主字段 0xFFFFFFFF 时真实值在 extra field（id 0x0001）里
            if packed == 0xFFFFFFFF || size == 0xFFFFFFFF || localOff == 0xFFFFFFFF {
                let extraBase = pos + 46 + nameLen
                var ep = extraBase
                let extraEnd = extraBase + extraLen
                while ep + 4 <= extraEnd, ep + 4 <= cd.count {
                    let hid = Self.u16(cd, ep)
                    let hsize = Int(Self.u16(cd, ep + 2))
                    if hid == 0x0001 {
                        var dp = ep + 4
                        if size == 0xFFFFFFFF, dp + 8 <= extraEnd {
                            size = Self.u64(cd, dp); dp += 8
                        }
                        if packed == 0xFFFFFFFF, dp + 8 <= extraEnd {
                            packed = Self.u64(cd, dp); dp += 8
                        }
                        if localOff == 0xFFFFFFFF, dp + 8 <= extraEnd {
                            localOff = Self.u64(cd, dp); dp += 8
                        }
                        break
                    }
                    ep += 4 + hsize
                }
            }
            let entry = ZipEntry(id: idx, path: name, size: size, packed: packed,
                                 method: method, offset: localOff, crc: crc)
            entries.append(entry)
            entryByPath[name] = entry
            totalUncompressed += size
            pos += 46 + nameLen + extraLen + commentLen
            idx += 1
        }
    }

    // MARK: - 单条目解压

    func data(for entry: ZipEntry, maxBytes: Int = 96 * 1024 * 1024) throws -> Data {
        guard !entry.isDirectory else { return Data() }
        guard Int(entry.size) <= maxBytes else {
            throw IPAError.tooLarge("\(entry.path) 解压后超 \(ByteFmt.text(UInt64(maxBytes)))")
        }
        // local header：30 字节 + 文件名 + 扩展区（长度可能与 central 不同，必须现场读）
        try fh.seek(toOffset: entry.offset)
        let lh = [UInt8](try readFull(fh, 30))
        guard lh.count == 30, lh[0] == 0x50, lh[1] == 0x4b, lh[2] == 0x03, lh[3] == 0x04 else {
            throw IPAError.notZip("局部头损坏: \(entry.path)")
        }
        let nameLen = Int(Self.u16(lh, 26))
        let extraLen = Int(Self.u16(lh, 28))
        let dataOff = entry.offset + 30 + UInt64(nameLen) + UInt64(extraLen)
        try fh.seek(toOffset: dataOff)
        let comp = try readFull(fh, Int(entry.packed))

        if entry.method == 0 {
            guard comp.count == Int(entry.size) else {
                throw IPAError.notZip("store 数据不完整: \(entry.path)（\(comp.count)/\(entry.size)）")
            }
            return comp
        }
        if entry.method == 8 {
            do {
                let out = try Self.inflate(comp, outSize: Int(entry.size))
                // CRC32 终检：读位置错误/数据损坏在此现形
                let got: UInt64 = out.withUnsafeBytes { sb -> UInt64 in
                    guard let sp = sb.bindMemory(to: Bytef.self).baseAddress else { return 0 }
                    return UInt64(zlib.crc32(0, sp, uInt(out.count)))
                }
                if got != UInt64(entry.crc) {
                    throw IPAError.notZip("CRC 不匹配: \(entry.path)｜文件大小=\(fileSize) md5=\(md5Fingerprint()) dataOff=\(dataOff) 算出 \(String(got, radix: 16)) 目录 \(String(entry.crc, radix: 16))")
                }
                guard out.count == Int(entry.size) else {
                    throw IPAError.notZip("解压不完整: \(entry.path)（\(out.count)/\(entry.size)）")
                }
                return out
            } catch {
                // 统一诊断包装（不透传）：文件身份 + 读取位置 + 数据指纹
                let head = comp.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " ")
                throw IPAError.unsupported("\(error.localizedDescription)｜诊断: 文件大小=\(fileSize) md5=\(md5Fingerprint()) localOff=\(entry.offset) dataOff=\(dataOff) packed读得\(comp.count) 前8字节=\(head)")
            }
        }
        throw IPAError.unsupported("压缩方法 \(entry.method) 暂不支持（仅 store/deflate）: \(entry.path)（packed=\(entry.packed) size=\(entry.size) off=\(entry.offset)）")
    }

    /// 文件 MD5 指纹（前 12 位，报错诊断用；懒计算一次）
    private var _md5Cache: String?
    /// 流式读取条目：store 分块回调；deflate 解压后一次性回调（≤maxBytes 保护）
    func streamBytes(for entry: ZipEntry, chunk: Int = 1 << 20, sink: @escaping (Data) -> Void) throws {
        guard !entry.isDirectory else { return }
        try fh.seek(toOffset: entry.offset)
        let lh = [UInt8](try readFull(fh, 30))
        guard lh.count == 30, lh[0] == 0x50, lh[1] == 0x4b, lh[2] == 0x03, lh[3] == 0x04 else {
            throw IPAError.notZip("局部头损坏: \(entry.path)")
        }
        let nameLen = Int(Self.u16(lh, 26))
        let extraLen = Int(Self.u16(lh, 28))
        try fh.seek(toOffset: entry.offset + 30 + UInt64(nameLen) + UInt64(extraLen))
        if entry.method == 0 {
            var remaining = Int(entry.packed)
            while remaining > 0 {
                let n = min(remaining, chunk)
                sink(try readFull(fh, n))
                remaining -= n
            }
        } else {
            // zlib 流式解压（跨块状态）——任意大小文件恒定内存
            var zs = z_stream()
            let initSt = inflateInit2_(&zs, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
            guard initSt == Z_OK else { throw IPAError.notZip("inflate 初始化失败") }
            defer { inflateEnd(&zs) }
            var inBuf = Data()
            let outCap = 1 << 18
            var outBuf = [UInt8](repeating: 0, count: outCap)
            var remaining = Int(entry.packed)
            var produced = 0
            var done = false
            while !done {
                if remaining > 0 && zs.avail_in == 0 {
                    inBuf = try readFull(fh, min(remaining, chunk))
                    remaining -= inBuf.count
                    let n = inBuf.count
                    inBuf.withUnsafeBytes { sb in
                        if let base = sb.bindMemory(to: Bytef.self).baseAddress {
                            zs.next_in = UnsafeMutablePointer<Bytef>(mutating: base)
                            zs.avail_in = uInt(n)
                        }
                    }
                }
                if zs.avail_in == 0 && remaining == 0 && produced == 0 {
                    // 无输入且无输出：数据异常，避免死循环
                    break
                }
                var wrote = 0
                outBuf.withUnsafeMutableBufferPointer { ob in
                    zs.next_out = ob.baseAddress
                    zs.avail_out = uInt(ob.count)
                    let st = zlib.inflate(&zs, Z_NO_FLUSH)
                    wrote = ob.count - Int(zs.avail_out)
                    if st == Z_STREAM_END { done = true }
                    else if st != Z_OK && st != Z_BUF_ERROR {
                        done = true
                        produced = -1
                    }
                }
                if produced < 0 { throw IPAError.notZip("流式解压失败: \(entry.path)") }
                if wrote > 0 {
                    produced += wrote
                    sink(Data(bytes: outBuf, count: wrote))
                } else if remaining == 0 && zs.avail_in == 0 {
                    done = true   // 输入耗尽且无输出
                }
            }
            guard produced == Int(entry.size) else {
                throw IPAError.notZip("流式解压不完整: \(entry.path)（\(produced)/\(entry.size)）")
            }
        }
    }

    /// 条目流式解压到磁盘文件（恒定内存，任意大小）
    @discardableResult
    func extractTo(_ entry: ZipEntry, to url: URL,
                   progress: ((Int, Int) -> Void)? = nil) throws -> Int {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        guard let fh = try? FileHandle(forWritingTo: url) else {
            throw IPAError.notZip("临时文件创建失败")
        }
        defer { try? fh.close() }
        var total = 0
        let size = Int(entry.size)
        let cb: (Data) -> Void = { chunk in
            try? fh.write(contentsOf: chunk)
            total += chunk.count
            // 节流：每 8MB 或末块回调（避免大文件数千次回调）
            if total / (8 * 1024 * 1024) != (total - chunk.count) / (8 * 1024 * 1024) || total == size {
                progress?(total, size)
            }
        }
        try streamBytes(for: entry, sink: cb)
        return total
    }

    func md5Fingerprint() -> String {
        if let c = _md5Cache { return c }
        guard let d = try? Data(contentsOf: fileURL) else { return "无法读取" }
        let h = CryptoKit.Insecure.MD5.hash(data: d).prefix(6)
            .map { String(format: "%02x", $0) }.joined()
        _md5Cache = h
        return h
    }

    /// FileHandle 读取可能短读——循环读满为止
    private func readFull(_ handle: FileHandle, _ count: Int) throws -> Data {
        var out = Data(capacity: count)
        var tries = 0
        while out.count < count {
            let chunk = handle.readData(ofLength: count - out.count)
            if chunk.isEmpty { break }
            out.append(chunk)
            tries += 1
            if tries > 100_000 { break }
        }
        guard out.count == count else {
            throw IPAError.notZip("文件读取不完整（\(out.count)/\(count)）")
        }
        return out
    }

    func entry(_ path: String) -> ZipEntry? { entryByPath[path] }

    func entries(in folder: String) -> [ZipEntry] {
        entries.filter { $0.path.hasPrefix(folder) && !$0.isDirectory }
    }

    static func inflate(_ src: Data, outSize: Int) throws -> Data {
        // 主路：纯 Swift RFC1951 解码器（零系统依赖，python 侧已验证算法）
        do {
            let arr = try SwiftInflate.inflate([UInt8](src), outSize: outSize)
            return Data(arr)
        } catch {
            // 备路：libz raw（万一大流路径有性能之外的差异）
            if let d = try? zlibInflate(src, outSize: outSize, windowBits: -15), d.count == outSize {
                return d
            }
            throw IPAError.unsupported("deflate 解压失败（SwiftInflate: \(error)｜libz 亦失败）packed=\(src.count) 期望输出 \(outSize)")
        }
    }

    /// libz 标准解压（iOS 系统自带 /usr/lib/libz，行为与所有 zip 工具一致）
    /// windowBits: -15 = raw deflate（zip 标准），15 = zlib wrapped
    private static func zlibInflate(_ src: Data, outSize: Int, windowBits: Int32) throws -> Data {
        var dst = Data(count: outSize)
        var produced = 0
        var ret: Int32 = 0
        dst.withUnsafeMutableBytes { (db: UnsafeMutableRawBufferPointer) in
            src.withUnsafeBytes { (sb: UnsafeRawBufferPointer) in
                guard let dp = db.bindMemory(to: Bytef.self).baseAddress,
                      let sp = sb.bindMemory(to: Bytef.self).baseAddress else {
                    ret = -100
                    return
                }
                var zs = z_stream()
                guard inflateInit2_(&zs, windowBits, nil, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
                    ret = -101
                    return
                }
                defer { inflateEnd(&zs) }
                zs.next_in = UnsafeMutablePointer<Bytef>(mutating: sp)
                zs.avail_in = uInt(src.count)
                zs.next_out = dp
                zs.avail_out = uInt(outSize)
                ret = zlib.inflate(&zs, Z_FINISH)
                produced = outSize - Int(zs.avail_out)
            }
        }
        guard ret == Z_STREAM_END || ret == Z_OK else {
            throw IPAError.unsupported("libz inflate 失败（windowBits=\(windowBits) ret=\(ret) 产出 \(produced)/\(outSize)）")
        }
        guard produced == outSize else {
            throw IPAError.notZip("解压产出不足（\(produced)/\(outSize)）")
        }
        return dst
    }

    static func u16(_ b: Data, _ o: Int) -> UInt16 {
        UInt16(b[o]) | (UInt16(b[o+1]) << 8)
    }
    static func u32(_ b: Data, _ o: Int) -> UInt32 {
        UInt32(b[o]) | (UInt32(b[o+1]) << 8) | (UInt32(b[o+2]) << 16) | (UInt32(b[o+3]) << 24)
    }
    static func u64(_ b: Data, _ o: Int) -> UInt64 {
        UInt64(b[o]) | (UInt64(b[o+1]) << 8) | (UInt64(b[o+2]) << 16) | (UInt64(b[o+3]) << 24)
            | (UInt64(b[o+4]) << 32) | (UInt64(b[o+5]) << 40) | (UInt64(b[o+6]) << 48) | (UInt64(b[o+7]) << 56)
    }
    static func u16(_ b: [UInt8], _ o: Int) -> UInt16 {
        UInt16(b[o]) | (UInt16(b[o+1]) << 8)
    }

    static func u32(_ b: [UInt8], _ o: Int) -> UInt32 {
        UInt32(b[o]) | (UInt32(b[o+1]) << 8) | (UInt32(b[o+2]) << 16) | (UInt32(b[o+3]) << 24)
    }

    static func u64(_ b: [UInt8], _ o: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(b[o+i]) << (8 * i) }
        return v
    }
}

// MARK: - 错误

enum IPAError: LocalizedError {
    case notZip(String)
    case tooLarge(String)
    case unsupported(String)
    case noBinary(String)

    var errorDescription: String? {
        switch self {
        case .notZip(let s): return "格式错误：\(s)"
        case .tooLarge(let s): return "体积超限：\(s)"
        case .unsupported(let s): return "不支持：\(s)"
        case .noBinary(let s): return "找不到主程序：\(s)"
        }
    }
}
