import Foundation
import Compression

// 零依赖 ZIP 读取器：
// 只解析 EOCD + central directory，按需解压单条目（Compression raw deflate）。
// 适配 IPA 场景：大文件用 FileHandle 分段读，绝不整包进内存。

final class ZipReader {
    private let fh: FileHandle
    private let fileSize: UInt64
    private(set) var entries: [ZipEntry] = []
    private var entryByPath: [String: ZipEntry] = [:]
    private(set) var totalUncompressed: UInt64 = 0

    init(url: URL) throws {
        fh = try FileHandle(forReadingFrom: url)
        let attr = try FileManager.default.attributesOfItem(atPath: url.path)
        fileSize = (attr[.size] as? NSNumber)?.uint64Value ?? 0
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
            let out = try Self.inflate(comp, outSize: Int(entry.size))
            guard out.count == Int(entry.size) else {
                throw IPAError.notZip("解压不完整: \(entry.path)（\(out.count)/\(entry.size)）——文件可能损坏")
            }
            return out
        }
        throw IPAError.unsupported("压缩方法 \(entry.method) 暂不支持（仅 store/deflate）: \(entry.path)（packed=\(entry.packed) size=\(entry.size) off=\(entry.offset)）")
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
        // 模式 1：标准 zip 的 raw deflate
        if let d = try? inflateRaw(src, outSize: outSize), d.count == outSize {
            return d
        }
        // 模式 2：非标打包器的 zlib 包裹格式（2 字节头 + adler32 尾）
        if src.count > 6, let d = try? inflateRaw(src.subdata(in: 2..<(src.count - 4)), outSize: outSize),
           d.count == outSize {
            return d
        }
        throw IPAError.unsupported("deflate 解压失败（raw/zlib 双模式均失败，packed=\(src.count) 期望输出 \(outSize)）")
    }

    private static func inflateRaw(_ src: Data, outSize: Int) throws -> Data {
        // 流式解压（compression_stream）：比 decode_buffer 可靠，不会静默提前返回
        var dst = Data(count: outSize)
        var produced = 0
        let status = dst.withUnsafeMutableBytes { (db: UnsafeMutableRawBufferPointer) -> compression_status in
            src.withUnsafeBytes { (sb: UnsafeRawBufferPointer) -> compression_status in
                guard let dp = db.bindMemory(to: UInt8.self).baseAddress,
                      let sp = sb.bindMemory(to: UInt8.self).baseAddress else { return COMPRESSION_STATUS_ERROR }
                var stream = compression_stream(dst_ptr: dp, dst_size: outSize,
                                                src_ptr: sp, src_size: src.count, state: nil)
                guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else {
                    return COMPRESSION_STATUS_ERROR
                }
                defer { compression_stream_destroy(&stream) }
                let finalize = Int32(COMPRESSION_STREAM_FINALIZE.rawValue)
                var st: compression_status = COMPRESSION_STATUS_OK
                while true {
                    st = compression_stream_process(&stream, finalize)
                    if st == COMPRESSION_STATUS_ERROR { return COMPRESSION_STATUS_ERROR }
                    if st == COMPRESSION_STATUS_END { break }
                    if stream.dst_size == 0 { break }   // 输出缓冲已满
                    if stream.src_size == 0 { break }   // 输入耗尽（防死循环，产出校验交给外层）
                }
                produced = outSize - Int(stream.dst_size)
                return st
            }
        }
        guard status == COMPRESSION_STATUS_END else {
            throw IPAError.unsupported("raw deflate 流式失败")
        }
        guard produced == outSize else {
            throw IPAError.notZip("解压产出不足（\(produced)/\(outSize)）")
        }
        return dst
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
