import Foundation

// 纯 Swift RFC 1951 inflate 解码器（puff.c 算法移植，python 侧已对真实数据验证）
// 动机：iOS 的 Compression API（decode_buffer/stream）对标准 zip deflate 流真机返回 ERROR，
//      libz 的 z_stream Swift 导入同样不可靠——系统库全军覆没后自研，零依赖零布局问题。
// 支持：stored / fixed Huffman / dynamic Huffman 三类块；32 位 LSB 位读取器。

enum SwiftInflate {

    struct InflateError: Swift.Error { let msg: String }

    // MARK: - 位读取器（LSB first，32 位缓冲）

    struct BitReader {
        let d: [UInt8]
        var p = 0          // 下一个待读字节
        var acc: UInt32 = 0
        var cnt = 0        // acc 有效位数

        init(_ d: [UInt8]) { self.d = d }

        mutating func bits(_ n: Int) -> Int {
            while cnt < n {
                if p < d.count {
                    acc |= UInt32(d[p]) << cnt
                    p += 1
                }
                cnt += 8   // 越界按 0 填充，末端完整性由产出校验兜底
            }
            let v = acc & ((1 << UInt32(n)) - 1)
            acc >>= n
            cnt -= n
            return Int(v)
        }

        /// 对齐到下一字节边界（stored 块用）
        mutating func alignByte() {
            let consumed = p * 8 - cnt
            let aligned = (consumed + 7) & ~7
            p = aligned >> 3
            acc = 0
            cnt = 0
        }
    }

    // MARK: - 规范 Huffman 表（puff count/symbol 法）

    static func buildTable(_ lengths: [Int]) -> (count: [Int], symbol: [Int]) {
        var count = [Int](repeating: 0, count: 16)
        for l in lengths where l > 0 { count[l] += 1 }
        var offs = [Int](repeating: 0, count: 16)
        for i in 1..<16 { offs[i] = offs[i - 1] + count[i - 1] }
        var symbol = [Int](repeating: 0, count: lengths.count)
        for i in 0..<lengths.count where lengths[i] > 0 {
            symbol[offs[lengths[i]]] = i
            offs[lengths[i]] += 1
        }
        return (count, symbol)
    }

    static func decode(_ br: inout BitReader, _ count: [Int], _ symbol: [Int]) throws -> Int {
        var code = 0, first = 0, index = 0
        for len in 1...15 {
            code |= br.bits(1)
            let c = count[len]
            if code - first < c { return symbol[index + code - first] }
            index += c
            first = (first + c) << 1
            code <<= 1
        }
        throw InflateError(msg: "无效 Huffman 码")
    }

    // MARK: - 主入口

    static func inflate(_ src: [UInt8], outSize: Int) throws -> [UInt8] {
        var br = BitReader(src)
        var out = [UInt8](repeating: 0, count: outSize)
        var op = 0
        var blockNo = 0

        while true {
            let bfinal = br.bits(1)
            let btype = br.bits(2)
            blockNo += 1

            switch btype {
            case 0: // stored
                br.alignByte()
                guard br.p + 4 <= br.d.count else {
                    throw InflateError(msg: "stored 头越界（块\(blockNo)）")
                }
                let ln = Int(br.d[br.p]) | (Int(br.d[br.p + 1]) << 8)
                let nlen = Int(br.d[br.p + 2]) | (Int(br.d[br.p + 3]) << 8)
                guard ln ^ 0xFFFF == nlen else {
                    throw InflateError(msg: "stored LEN/NLEN 校验失败（块\(blockNo)）")
                }
                br.p += 4
                guard op + ln <= outSize, br.p + ln <= br.d.count else {
                    throw InflateError(msg: "stored 数据越界（块\(blockNo)）")
                }
                out.replaceSubrange(op..<(op + ln), with: br.d[br.p..<(br.p + ln)])
                op += ln
                br.p += ln

            case 1, 2: // Huffman
                var litLen: [Int]
                var distLen: [Int]
                if btype == 1 {
                    litLen = [Int](repeating: 8, count: 144)
                        + [Int](repeating: 9, count: 112)
                        + [Int](repeating: 7, count: 24)
                        + [Int](repeating: 8, count: 8)
                    distLen = [Int](repeating: 5, count: 30)
                } else {
                    let hlit = br.bits(5) + 257
                    let hdist = br.bits(5) + 1
                    let hclen = br.bits(4) + 4
                    let order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
                    var cl = [Int](repeating: 0, count: 19)
                    for i in 0..<hclen { cl[order[i]] = br.bits(3) }
                    let (cc, cs) = buildTable(cl)
                    var lens: [Int] = []
                    while lens.count < hlit + hdist {
                        let s = try decode(&br, cc, cs)
                        if s < 16 {
                            lens.append(s)
                        } else if s == 16 {
                            guard let last = lens.last else {
                                throw InflateError(msg: "repeat 无前值（块\(blockNo)）")
                            }
                            lens.append(contentsOf: [Int](repeating: last, count: br.bits(2) + 3))
                        } else if s == 17 {
                            lens.append(contentsOf: [Int](repeating: 0, count: br.bits(3) + 3))
                        } else {
                            lens.append(contentsOf: [Int](repeating: 0, count: br.bits(7) + 11))
                        }
                    }
                    litLen = Array(lens[0..<hlit])
                    distLen = Array(lens[hlit..<(hlit + hdist)])
                }

                let (lc, ls) = buildTable(litLen)
                let (dc, ds) = buildTable(distLen)
                while true {
                    let s = try decode(&br, lc, ls)
                    if s < 256 {
                        guard op < outSize else {
                            throw InflateError(msg: "输出越界（块\(blockNo)）")
                        }
                        out[op] = UInt8(s)
                        op += 1
                    } else if s == 256 {
                        break
                    } else {
                        let i = s - 257
                        guard i < LEN_BASE.count else {
                            throw InflateError(msg: "非法长度符号 \(s)（块\(blockNo)）")
                        }
                        let ln = LEN_BASE[i] + br.bits(LEN_EXTRA[i])
                        let dsym = try decode(&br, dc, ds)
                        guard dsym < DIST_BASE.count else {
                            throw InflateError(msg: "非法距离符号 \(dsym)（块\(blockNo)）")
                        }
                        let dist = DIST_BASE[dsym] + br.bits(DIST_EXTRA[dsym])
                        guard dist <= op, op + ln <= outSize else {
                            throw InflateError(msg: "距离/长度越界 dist=\(dist) ln=\(ln) op=\(op)（块\(blockNo)）")
                        }
                        for _ in 0..<ln {
                            out[op] = out[op - dist]
                            op += 1
                        }
                    }
                }

            default:
                throw InflateError(msg: "非法块类型 3（块\(blockNo)）")
            }

            if bfinal == 1 { break }
        }

        guard op == outSize else {
            throw InflateError(msg: "产出 \(op)/\(outSize)")
        }
        return out
    }

    // MARK: - 长度/距离基表（RFC 1951 §3.2.5）

    static let LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43,
                           51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
    static let LEN_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
                            4, 4, 4, 4, 5, 5, 5, 5, 0]
    static let DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257,
                            385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
                            16385, 24577]
    static let DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
                             9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
}
