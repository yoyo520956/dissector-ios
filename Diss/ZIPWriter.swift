import Foundation

// MARK: - 轻量 ZIP 写入器（零依赖，store 模式）
// 用于把选中的资源打包成 .zip 导出。store 模式不压缩但 100% 兼容。

struct ZIPEntry {
    let path: String       // zip 内路径（相对）
    let data: Data
}

enum ZIPWriter {

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
