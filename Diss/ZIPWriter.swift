import Foundation

// MARK: - 轻量 ZIP 写入器（零依赖，store 模式）
// 用于把选中的资源打包成 .zip 导出。store 模式不压缩但 100% 兼容。

struct ZIPEntry {
    let path: String       // zip 内路径（相对）
    let data: Data
}

enum ZIPWriter {

    // MARK: - 流式写入（恒定内存，支持大素材包）

    struct StreamItem {
        let path: String
        let data: Data?          // 内存中的生成内容
        let entry: ZipEntry?     // 或从 reader 流式取
    }

    /// 流式打包到磁盘文件。store 条目分块两遍（先 crc 后写），deflate 解压后写。
    /// 全部字段为真实值（与 write 完全同构），兼容性 100%。
    static func writeStreaming(_ items: [StreamItem], to url: URL,
                               progress: @escaping (Int, Int) -> Void) -> Bool {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        guard let fh = try? FileHandle(forWritingTo: url) else { return false }
        defer { try? fh.close() }

        var central = Data()
        var count = 0
        var crcTable = table

        func writeHeaderAndData(_ path: String, size: Int, crc: UInt32,
                                localOff: UInt32, write: (FileHandle) -> Void) {
            let nameBytes = Array(path.utf8)
            var lh = Data()
            lh.appendLE(UInt32(0x04034b50))
            lh.appendLE(UInt16(20))
            lh.appendLE(UInt16(0x0800))
            lh.appendLE(UInt16(0))
            lh.appendLE(UInt16(0))
            lh.appendLE(UInt16(0x5421))
            lh.appendLE(crc)
            lh.appendLE(UInt32(size))
            lh.appendLE(UInt32(size))
            lh.appendLE(UInt16(nameBytes.count))
            lh.appendLE(UInt16(0))
            lh.append(contentsOf: nameBytes)
            try? fh.write(contentsOf: lh)

            var ce = Data()
            ce.appendLE(UInt32(0x02014b50))
            ce.appendLE(UInt16(20))
            ce.appendLE(UInt16(20))
            ce.appendLE(UInt16(0x0800))
            ce.appendLE(UInt16(0))
            ce.appendLE(UInt16(0))
            ce.appendLE(UInt16(0x5421))
            ce.appendLE(crc)
            ce.appendLE(UInt32(size))
            ce.appendLE(UInt32(size))
            ce.appendLE(UInt16(nameBytes.count))
            ce.appendLE(UInt16(0))
            ce.appendLE(UInt16(0))
            ce.appendLE(UInt16(0))
            ce.appendLE(UInt16(0))
            ce.appendLE(UInt32(0))
            ce.appendLE(localOff)
            ce.append(contentsOf: nameBytes)
            central.append(ce)
            count += 1
        }

        for (i, item) in items.enumerated() {
            let nameBytes = Array(item.path.utf8)
            guard !nameBytes.isEmpty, nameBytes.count < 0xFFFF else { continue }
            let localOff = UInt32(min(fh.offsetInFile, UInt64(UInt32.max)))
            do {
                if let d = item.data {
                    writeHeaderAndData(item.path, size: d.count, crc: crc32(d),
                                       localOff: localOff) { _ in try? fh.write(contentsOf: d) }
                } else if let e = item.entry, !e.isDirectory {
                    // deflate：解压到内存（受外层 maxFile 限制）；store：分块两遍
                    if e.method == 0 {
                        var crc: UInt32 = 0xFFFFFFFF
                        // 第一遍：crc
                        try? reader?.streamBytes(for: e) { chunk in
                            for b in [UInt8](chunk) {
                                crc = crcTable[Int((crc ^ UInt32(b)) & 0xFF)] ^ (crc >> 8)
                            }
                        }
                        crc ^= 0xFFFFFFFF
                        // 第二遍：写数据
                        writeHeaderAndData(item.path, size: Int(e.size), crc: crc, localOff: localOff) { _ in
                            try? reader?.streamBytes(for: e) { chunk in
                                try? fh.write(contentsOf: chunk)
                            }
                        }
                    } else {
                        var buf = Data()
                        try? reader?.streamBytes(for: e) { chunk in buf.append(chunk) }
                        guard buf.count == Int(e.size) else { continue }
                        writeHeaderAndData(item.path, size: buf.count, crc: crc32(buf),
                                           localOff: localOff) { _ in try? fh.write(contentsOf: buf) }
                        buf = Data()
                    }
                } else {
                    continue
                }
            }
            if i % 8 == 0 { progress(i, items.count) }
        }
        progress(items.count, items.count)

        let cdOff = fh.offsetInFile
        try? fh.write(contentsOf: central)
        var eocd = Data()
        eocd.appendLE(UInt32(0x06054b50))
        eocd.appendLE(UInt16(0))
        eocd.appendLE(UInt16(0))
        eocd.appendLE(UInt16(count))
        eocd.appendLE(UInt16(count))
        eocd.appendLE(UInt32(central.count))
        eocd.appendLE(UInt32(cdOff))
        eocd.appendLE(UInt16(0))
        try? fh.write(contentsOf: eocd)
        return count > 0
    }

    static func write(_ files: [ZIPEntry]) -> Data? {
        guard !files.isEmpty else { return nil }
        var out = Data()
        var central = Data()
        var count = 0

        for f in files {
            let nameBytes = Array(f.path.utf8)
            let crc = crc32(f.data)
            let size = UInt32(f.data.count)
            let localOff = UInt32(out.count)

            // local file header: PK\x03\x04
            out.appendLE(UInt32(0x04034b50))
            out.appendLE(UInt16(20))          // version needed
            out.appendLE(UInt16(0x0800))      // flags: UTF-8 文件名
            out.appendLE(UInt16(0))           // method: store
            out.appendLE(UInt16(0))           // mod time
            out.appendLE(UInt16(0x5421))      // mod date (2022-01-01 占位)
            out.appendLE(crc)
            out.appendLE(size)
            out.appendLE(size)
            out.appendLE(UInt16(nameBytes.count))
            out.appendLE(UInt16(0))           // extra len
            out.append(contentsOf: nameBytes)
            out.append(f.data)

            // central directory entry: PK\x01\x02
            central.appendLE(UInt32(0x02014b50))
            central.appendLE(UInt16(20))      // version made by
            central.appendLE(UInt16(20))      // version needed
            central.appendLE(UInt16(0x0800))
            central.appendLE(UInt16(0))
            central.appendLE(UInt16(0))
            central.appendLE(UInt16(0x5421))
            central.appendLE(crc)
            central.appendLE(size)
            central.appendLE(size)
            central.appendLE(UInt16(nameBytes.count))
            central.appendLE(UInt16(0))       // extra
            central.appendLE(UInt16(0))       // comment
            central.appendLE(UInt16(0))       // disk number
            central.appendLE(UInt16(0))       // internal attrs
            central.appendLE(UInt32(0))       // external attrs
            central.appendLE(localOff)
            central.append(contentsOf: nameBytes)
            count += 1
        }

        let cdOffset = UInt32(out.count)
        let cdSize = UInt32(central.count)

        // EOCD: PK\x05\x06
        out.appendLE(UInt32(0x06054b50))
        out.appendLE(UInt16(0))           // disk
        out.appendLE(UInt16(0))           // cd disk
        out.appendLE(UInt16(UInt16(count)))
        out.appendLE(UInt16(UInt16(count)))
        out.appendLE(cdSize)
        out.appendLE(cdOffset)
        out.appendLE(UInt16(0))           // comment len

        return out
    }

    // MARK: - CRC32 (zlib 多项式)

    private static var table: [UInt32] = {
        var t = [UInt32](repeating: 0, count: 256)
        for i in 0..<256 {
            var c = UInt32(i)
            for _ in 0..<8 {
                c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1)
            }
            t[i] = c
        }
        return t
    }()

    static func crc32(_ data: Data) -> UInt32 {
        var c: UInt32 = 0xFFFFFFFF
        for b in [UInt8](data) {
            c = table[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8)
        }
        return c ^ 0xFFFFFFFF
    }
}

extension Data {
    mutating func appendLE(_ v: UInt16) {
        append(UInt8(v & 0xff))
        append(UInt8((v >> 8) & 0xff))
    }
    mutating func appendLE(_ v: UInt32) {
        append(UInt8(v & 0xff))
        append(UInt8((v >> 8) & 0xff))
        append(UInt8((v >> 16) & 0xff))
        append(UInt8((v >> 24) & 0xff))
    }
}
