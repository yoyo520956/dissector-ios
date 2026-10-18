import Foundation
import Compression

// MARK: - Assets.car 图片提取（务实版）
// 策略：
// 1. 明文图片魔数扫描（PNG / JPEG / GIF / WEBP）——直接切片提取，保底出图
// 2. lzfse 压缩块（bvx 魔数）检测计数——完整 CAR 位图重组需要 rendition 头解析，暂不承诺
// 3. 输出提取报告

enum AssetsCar {

    struct ExtractedImage: Identifiable, Hashable {
        let id: Int
        let kind: String        // "png" / "jpeg" / "gif" / "webp"
        let data: Data
        var fileName: String { "asset_\(String(format: "%03d", id)).\(kind)" }
    }

    struct ScanReport {
        var images: [ExtractedImage] = []
        var lzfseBlocks = 0
        var carSize = 0
    }

    static func scan(_ data: Data) -> ScanReport {
        var rep = ScanReport()
        rep.carSize = data.count
        let bytes = [UInt8](data)
        let n = bytes.count
        guard n > 16 else { return rep }

        // ---- PNG：89 50 4E 47 0D 0A 1A 0A … IEND + CRC(4)
        let pngSig: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        var i = 0
        while i < n - 8 {
            if Array(bytes[i..<i+8]) == pngSig {
                // 找 IEND（7A 49 45 4E 44）
                var j = i + 8
                var found = -1
                while j < n - 4 {
                    if bytes[j] == 0x49 && bytes[j+1] == 0x45 && bytes[j+2] == 0x4E && bytes[j+3] == 0x44 {
                        found = j + 4 + 4   // IEND + CRC
                        break
                    }
                    j += 1
                }
                if found > 0, found - i > 100, found - i < 30 * 1024 * 1024 {
                    let d = data.subdata(in: i..<found)
                    if UIImage(data: d) != nil {
                        rep.images.append(ExtractedImage(id: rep.images.count, kind: "png", data: d))
                        i = found
                        continue
                    }
                }
            }
            i += 1
        }

        // ---- JPEG：FF D8 FF … FF D9
        i = 0
        while i < n - 3 {
            if bytes[i] == 0xFF && bytes[i+1] == 0xD8 && bytes[i+2] == 0xFF {
                var j = i + 3
                var found = -1
                while j < n - 1 {
                    if bytes[j] == 0xFF && bytes[j+1] == 0xD9 {
                        found = j + 2
                        break
                    }
                    j += 1
                }
                if found > 0, found - i > 200, found - i < 30 * 1024 * 1024 {
                    let d = data.subdata(in: i..<found)
                    if UIImage(data: d) != nil {
                        rep.images.append(ExtractedImage(id: rep.images.count, kind: "jpeg", data: d))
                        i = found
                        continue
                    }
                }
            }
            i += 1
        }

        // ---- lzfse 块计数（bvx 魔数：bvx2 / bvx- / bvx$）
        i = 0
        while i < n - 4 {
            if bytes[i] == 0x62 && bytes[i+1] == 0x76 && bytes[i+2] == 0x78 {
                rep.lzfseBlocks += 1
                i += 1024   // 块间距粗跳，避免重复计数
            } else {
                i += 1
            }
        }
        return rep
    }

    // 尝试解压 lzfse 块（供后续版本使用）
    static func tryLZFSE(_ data: Data, offset: UInt64) -> Data? {
        let start = Int(offset)
        guard start < data.count else { return nil }
        let src = data.subdata(in: start..<min(data.count, start + 4 * 1024 * 1024))
        let dstCap = 16 * 1024 * 1024
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: dstCap)
        defer { dst.deallocate() }
        let r = src.withUnsafeBytes { srcPtr -> Int in
            guard let base = srcPtr.baseAddress else { return 0 }
            return compression_decode_buffer(dst, dstCap, base.assumingMemoryBound(to: UInt8.self),
                                             src.count, nil, COMPRESSION_LZFSE)
        }
        guard r > 0 else { return nil }
        return Data(bytes: dst, count: r)
    }

    static func reportText(_ rep: ScanReport) -> String {
        var lines: [String] = []
        lines.append("Assets.car 大小：\(ByteFmt.text(UInt64(rep.carSize)))")
        lines.append("直接提取出图片：\(rep.images.count) 张")
        lines.append("lzfse 压缩位图块：\(rep.lzfseBlocks) 个（需完整 rendition 解析，暂未重组）")
        lines.append("")
        lines.append("说明：Assets.car 是苹果私有点阵归档。较老 App 多含明文 PNG/JPEG（可直接提取）；")
        lines.append("较新 App 的位图多为 lzfse 压缩的原始像素，需要解析 rendition 头（宽高/像素格式）才能重组，成功率不保证。")
        return lines.joined(separator: "\n")
    }
}

import UIKit
