import Foundation

// 专业功能 · 交叉引用引擎（Xref）
// 原理：ARM64 bl 指令字扫描（(w & 0xFC000000) == 0x94000000）
// imm26 有符号扩展 *4 + 当前 VA = 调用目标 → 建立 目标→调用者 全图
// 纯 u32 字扫描，百万级指令秒级完成，不做完整解码

struct XrefSite: Identifiable, Hashable {
    let id: Int
    let fromVA: UInt64      // 调用点地址
    let kind: String        // bl / b
}

enum XrefEngine {

    /// 扫描 __text 全段，构建 调用目标 → [调用点] 倒排表
    /// 返回 (graph, scannedInstructions)
    static func buildCallGraph(bin: Data, textSec: MachSection) -> ([UInt64: [XrefSite]], Int) {
        let base = Int(textSec.fileOffset)
        guard base >= 0, base + Int(textSec.size) <= bin.count, textSec.size >= 4 else {
            return ([:], 0)
        }
        let len = Int(textSec.size)
        var graph: [UInt64: [XrefSite]] = [:]
        var count = 0
        var totalSites = 0
        bin.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let p = raw.baseAddress else { return }
            var id = 0
            var off = 0
            // 4 字节对齐扫描
            while off + 4 <= len {
                let w = p.loadUnaligned(fromByteOffset: base + off, as: UInt32.self)
                let op = w & 0xFC000000
                if op == 0x94000000 || op == 0x14000000 {   // bl / b
                    var imm = Int32(w & 0x03FFFFFF)
                    // 符号扩展 26 位
                    if imm & 0x02000000 != 0 { imm |= -1 << 26 }
                    // 全程 Int64 运算：负偏移转 UInt64 会回绕成天文数字，加法溢出 = trap 闪退
                    let targetOff = Int64(off) + Int64(imm) * 4
                    if targetOff >= 0, targetOff < Int64(len) {   // 跳出 __text 的目标不记录
                        let target = textSec.addr + UInt64(targetOff)
                        let va = textSec.addr + UInt64(off)
                        if totalSites < 1_500_000 {   // 内存保护：调用点总量上限
                            graph[target, default: []].append(XrefSite(id: id, fromVA: va,
                                                                       kind: op == 0x94000000 ? "bl" : "b"))
                            totalSites += 1
                        }
                        id += 1
                    }
                }
                off += 4
                count += 1
            }
        }
        return (graph, count)
    }

    /// adrp+add / adrp+ldr 数据引用扫描（引用了哪些地址）——供"该函数引用了什么"用
    static func dataRefs(bin: Data, textSec: MachSection, fromVA: UInt64, count: Int) -> [UInt64] {
        let base = Int(textSec.fileOffset)
        guard base >= 0 else { return [] }
        let startOff = Int(fromVA - textSec.addr)
        guard startOff >= 0, startOff + count * 4 <= Int(textSec.size) else { return [] }
        var refs: [UInt64] = []
        var adrpPage: [UInt32: UInt64] = [:]   // 寄存器 → page
        bin.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let p = raw.baseAddress else { return }
            for i in 0..<count {
                let off = base + startOff + i * 4
                let w = p.loadUnaligned(fromByteOffset: off, as: UInt32.self)
                if w & 0x9F000000 == 0x90000000 {          // adrp
                    let rd = w & 0x1F
                    let immlo = Int64((w >> 29) & 0x3)     // bits 30-29
                    let immhi = Int64((w >> 5) & 0x7FFFF)  // bits 23-5
                    var imm = (immhi << 2) | immlo         // 21 位：immhi:immlo
                    if imm & 0x100000 != 0 { imm |= -1 << 21 }  // 符号扩展
                    let va = textSec.addr + UInt64(i * 4)
                    let page = va & ~UInt64(0xFFF)
                    adrpPage[rd] = UInt64(Int64(bitPattern: UInt64(page)) + (imm << 12))
                } else if w & 0xFF800000 == 0x91000000 {   // add Xd, Xn, #imm12
                    let rd = w & 0x1F
                    let rn = (w >> 5) & 0x1F
                    let imm = UInt64((w >> 10) & 0xFFF)
                    if let page = adrpPage[rn], rd == rn || adrpPage[rd] == nil {
                        refs.append(page + imm)
                    }
                }
            }
        }
        return refs
    }
}
