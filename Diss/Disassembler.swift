import Foundation

// MARK: - 反汇编行模型

struct DisasmLine: Identifiable, Hashable {
    let id: Int
    let addr: UInt64
    let hex: String
    let text: String
    var note: String
}

// MARK: - ARM64 轻量反汇编器
// 零依赖：覆盖 iOS 主二进制常见指令类；未识别指令显示 .inst 原始码。
// 设计目标：看懂调用链（bl → 符号）、数据引用（adrp/add）、控制流（b/cb/tb/ret）。

enum ARM64Disassembler {

    // data: 从某虚拟地址开始的连续指令字节；baseVA: data[0] 的虚拟地址
    static func disassemble(_ data: Data, baseVA: UInt64,
                            maxInstructions: Int = 400,
                            symbols: [UInt64: String] = [:]) -> [DisasmLine] {
        var out: [DisasmLine] = []
        let bytes = [UInt8](data)
        let n = min(bytes.count / 4, maxInstructions)
        out.reserveCapacity(n)
        for i in 0..<n {
            let off = i * 4
            let w = UInt32(bytes[off])
                | (UInt32(bytes[off + 1]) << 8)
                | (UInt32(bytes[off + 2]) << 16)
                | (UInt32(bytes[off + 3]) << 24)
            let pc = baseVA + UInt64(off)
            let r = decode(w, pc: pc, symbols: symbols)
            let hex = String(format: "%02x %02x %02x %02x",
                             bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3])
            out.append(DisasmLine(id: out.count, addr: pc, hex: hex, text: r.0, note: r.1))
        }
        return out
    }

    // MARK: - 位段工具

    private static func bits(_ w: UInt32, _ hi: Int, _ lo: Int) -> UInt32 {
        (w >> UInt32(lo)) & ((1 << UInt32(hi - lo + 1)) - 1)
    }

    private static func sx(_ v: UInt32, bits: Int) -> Int64 {
        let shift = 64 - bits
        return Int64(bitPattern: (UInt64(v) << UInt64(shift)) >> Int64(shift))
    }

    private static func xreg(_ r: UInt32) -> String { r == 31 ? "sp" : "x\(r)" }
    private static func xzr(_ r: UInt32) -> String { r == 31 ? "xzr" : "x\(r)" }
    private static func wreg(_ r: UInt32) -> String { r == 31 ? "wzr" : "w\(r)" }
    private static func genreg(_ r: UInt32, sf: Bool) -> String { sf ? xzr(r) : wreg(r) }
    private static func condName(_ c: UInt32) -> String {
        ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
         "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"][Int(c)]
    }
    private static func hx(_ v: UInt64) -> String { "0x" + String(v, radix: 16) }

    // MARK: - 解码核心：返回 (指令文本, 备注)

    private static func decode(_ w: UInt32, pc: UInt64, symbols: [UInt64: String]) -> (String, String) {
        let noteTarget: (UInt64) -> String = { target in
            if let s = symbols[target] { return "; → \(s)" }
            return "; → \(hx(target))"
        }

        // ---- b / bl：op(000101|100101) + imm26
        if w >> 26 == 0b000101 || w >> 26 == 0b100101 {
            let isLink = w >> 26 == 0b100101
            let imm = sx(bits(w, 25, 0), bits: 26) * 4
            let target = UInt64(bitPattern: Int64(pc) + imm)
            return (isLink ? "bl \(hx(target))" : "b \(hx(target))", noteTarget(target))
        }

        // ---- b.cond：01010100 imm19 0 cond
        if w >> 24 == 0b01010100 && bits(w, 4, 4) == 0 {
            let imm = sx(bits(w, 23, 5), bits: 19) * 4
            let target = UInt64(bitPattern: Int64(pc) + imm)
            return ("b.\(condName(bits(w, 3, 0))) \(hx(target))", noteTarget(target))
        }

        // ---- cbz / cbnz：sf 011010 op imm19 Rt
        if bits(w, 30, 25) == 0b011010 {
            let sf = bits(w, 31, 31) == 1
            let op = bits(w, 24, 24)
            let imm = sx(bits(w, 23, 5), bits: 19) * 4
            let target = UInt64(bitPattern: Int64(pc) + imm)
            let rt = genreg(bits(w, 4, 0), sf: sf)
            return ("\(op == 0 ? "cbz" : "cbnz") \(rt), \(hx(target))", noteTarget(target))
        }

        // ---- tbz / tbnz：b5 011011 op b40 imm14 Rt
        if bits(w, 30, 25) == 0b011011 {
            let op = bits(w, 24, 24)
            let bitNo = bits(w, 31, 31) * 32 + bits(w, 23, 19)
            let imm = sx(bits(w, 18, 5), bits: 14) * 4
            let target = UInt64(bitPattern: Int64(pc) + imm)
            return ("\(op == 0 ? "tbz" : "tbnz") x\(bits(w, 4, 0)), #\(bitNo), \(hx(target))", noteTarget(target))
        }

        // ---- adrp / adr：op immlo 10000 immhi Rd
        if bits(w, 28, 24) == 0b10000 {
            let isAdrp = bits(w, 31, 31) == 1
            let immlo = bits(w, 30, 29)
            let immhi = bits(w, 23, 5)
            let rd = bits(w, 4, 0)
            let imm = (Int64(immhi) << 2) | Int64(immlo)
            if isAdrp {
                let page = (pc & ~UInt64(0xfff)) &+ (UInt64(bitPattern: sx(UInt32(imm), bits: 21)) << 12)
                return ("adrp x\(rd), \(hx(page))", "; 页基址（常配合 add 取数据地址）")
            }
            let target = UInt64(bitPattern: Int64(pc) + sx(UInt32(imm), bits: 21))
            return ("adr x\(rd), \(hx(target))", noteTarget(target))
        }

        // ---- ret / br / blr：1101011 opc(0010=ret|0000=br|0001=blr) 11111000000 Rn 00000
        if w >> 25 == 0b1101011 {
            let opc = bits(w, 24, 21)
            let rn = bits(w, 9, 5)
            if bits(w, 20, 10) == 0b11111000000 && bits(w, 4, 0) == 0 {
                if opc == 0b0010 { return ("ret", rn == 30 ? "; 函数返回" : "; 返回到 \(xreg(rn))") }
                if opc == 0b0000 { return ("br \(xreg(rn))", "; 跳转 \(xreg(rn))") }
                if opc == 0b0001 { return ("blr \(xreg(rn))", "; 调用 \(xreg(rn))") }
            }
            return (".inst \(hx(UInt64(w)))", "")
        }

        // ---- svc：11010100 000 imm16 1 00001
        if w >> 24 == 0b11010100 && bits(w, 4, 0) == 1 {
            return ("svc #\(bits(w, 16, 5))", "; 系统调用")
        }

        // ---- mrs / msr：1101 0101 00 1L o0 op1 CRn CRm op2 Rt
        if bits(w, 31, 22) == 0b1101010100 && bits(w, 21, 20) == 0b01 || bits(w, 31, 22) == 0b1101010100 && bits(w, 21, 20) == 0b11 {
            let isRead = bits(w, 20, 20) == 1
            let op1 = bits(w, 18, 16)
            let crn = bits(w, 15, 12)
            let crm = bits(w, 11, 8)
            let op2 = bits(w, 7, 5)
            let reg = "s3_\(op1)_c\(crn)_c\(crm)_\(op2)"
            if isRead {
                return ("mrs x\(bits(w, 4, 0)), \(reg)", "; 读系统寄存器")
            }
            return ("msr \(reg), x\(bits(w, 4, 0))", "; 写系统寄存器")
        }

        // ---- nop
        if w == 0xd503201f { return ("nop", "") }

        // ---- movz / movk / movn：sf opc(00=n,10=z,11=k) 100101 hw imm16 Rd
        if bits(w, 28, 23) == 0b100101 {
            let sf = bits(w, 31, 31) == 1
            let opc = bits(w, 30, 29)
            let hw = bits(w, 22, 21)
            let imm = bits(w, 20, 5)
            let rd = genreg(bits(w, 4, 0), sf: sf)
            let name = opc == 0b10 ? "movz" : (opc == 0b11 ? "movk" : "movn")
            let shift = Int(hw) * 16
            return ("\(name) \(rd), #\(imm)" + (shift > 0 ? ", lsl #\(shift)" : ""), "; 常量构造")
        }

        // ---- add/sub (imm)：sf op S 100010 sh imm12 Rn Rd
        if bits(w, 28, 23) == 0b100010 {
            return decodeAddSub(w)
        }

        // ---- ldr/str (unsigned imm)：size opc 111001 V=0 01 imm12 Rn Rt
        if bits(w, 29, 24) == 0b111001 && bits(w, 26, 26) == 0 {
            let size = bits(w, 31, 30)
            let opc = bits(w, 23, 22)
            let imm12 = Int(bits(w, 21, 10))
            let rn = bits(w, 9, 5)
            let rt = bits(w, 4, 0)
            let bytes: Int
            switch size {
            case 0: bytes = 1
            case 1: bytes = 2
            case 2: bytes = 4
            default: bytes = 8
            }
            let off = imm12 * bytes
            let rnS = rn == 31 ? "[sp" : "[x\(rn)"
            if opc == 0b01 {
                let rtS = size == 3 ? xzr(rt) : wreg(rt)
                return ("ldr \(rtS), \(rnS), #\(off)]", "; 读内存")
            }
            if opc == 0b00 {
                let rtS = size == 3 ? xzr(rt) : wreg(rt)
                return ("str \(rtS), \(rnS), #\(off)]", "; 写内存")
            }
            if opc == 0b10 && size == 0b10 {
                return ("ldrsw x\(rt), \(rnS), #\(off)]", "; 读符号扩展字")
            }
        }

        // ---- ldp/stp：opc 101 V seq(010=off,011=post,001=pre) L imm7 Rt2 Rn Rt
        if bits(w, 29, 27) == 0b101 && bits(w, 26, 26) == 0 {
            let opc = bits(w, 31, 30)
            let seq = bits(w, 25, 23)
            let l = bits(w, 22, 22) == 1
            let imm7 = Int(sx(bits(w, 21, 15), bits: 7)) * (opc == 0b10 ? 8 : 4)
            let rt2 = bits(w, 14, 10)
            let rn = bits(w, 9, 5)
            let rt = bits(w, 4, 0)
            let rnS = rn == 31 ? "[sp" : "[x\(rn)"
            let name = l ? "ldp" : "stp"
            if seq == 0b010 {
                return ("\(name) x\(rt), x\(rt2), \(rnS), #\(imm7)]", "; 寄存器对")
            }
            if seq == 0b011 {
                return ("\(name) x\(rt), x\(rt2), \(rnS)], #\(imm7)", "; 寄存器对(后增)")
            }
            if seq == 0b001 {
                return ("\(name) x\(rt), x\(rt2), \(rnS), #\(imm7)]!", "; 寄存器对(先减)")
            }
        }

        // ---- mov 寄存器：ORR Xd, XZR, Xm = sf 0101010 shift=00 0 Rm imm6=0 Rn=11111 Rd
        if bits(w, 30, 24) == 0b0101010 && bits(w, 23, 22) == 0 && bits(w, 21, 21) == 0
            && bits(w, 15, 10) == 0 && bits(w, 9, 5) == 31 {
            let sf = bits(w, 31, 31) == 1
            return ("mov \(genreg(bits(w, 4, 0), sf: sf)), \(genreg(bits(w, 20, 16), sf: sf))", "")
        }

        // ---- cset：csinc Xd, XZR, XZR, cond = sf 00 11010100 11111 cond 11 11111 Rd
        if bits(w, 30, 21) == 0b0011010100 && bits(w, 20, 16) == 31
            && bits(w, 11, 10) == 0b11 && bits(w, 9, 5) == 31 {
            let sf = bits(w, 31, 31) == 1
            return ("cset \(genreg(bits(w, 4, 0), sf: sf)), \(condName(bits(w, 15, 12)))", "; 条件置位")
        }

        // ---- 位域 / 扩展 / 移位族：sf 00 100110 N immr imms Rn Rd
        if bits(w, 28, 23) == 0b100110 {
            return decodeBitfield(w)
        }

        return (".inst \(hx(UInt64(w)))", "")
    }

    // add/sub imm + cmp/cmn 变体
    private static func decodeAddSub(_ w: UInt32) -> (String, String) {
        let sf = bits(w, 31, 31) == 1
        if bits(w, 28, 23) == 0b100010 {
            let op = bits(w, 30, 30)
            let sFlag = bits(w, 29, 29) == 1
            let sh = bits(w, 22, 22) == 1
            let imm = Int(bits(w, 21, 10))
            let rn = bits(w, 9, 5)
            let rd = bits(w, 4, 0)
            let rnS = rn == 31 ? (sFlag ? "xzr" : "sp") : xzr(rn)
            let immS = sh ? "#\(imm), lsl #12" : "#\(imm)"
            if sFlag && rd == 31 {
                return ("cmp \(rnS), \(immS)", "; 比较（结果丢弃）")
            }
            let base = op == 0 ? "add" : "sub"
            let name = sFlag ? base + "s" : base
            return ("\(name) \(genreg(rd, sf: sf)), \(rnS), \(immS)", "")
        }
        return (".inst \(hx(UInt64(w)))", "")
    }

    // sbfm/ubfm 及惯用变体：lsr/lsl/asr/sxtw/sxtb/uxtw
    private static func decodeBitfield(_ w: UInt32) -> (String, String) {
        let sf = bits(w, 31, 31) == 1
        let n = bits(w, 22, 22) == 1
        let immr = Int(bits(w, 21, 16))
        let imms = Int(bits(w, 15, 10))
        let rn = bits(w, 9, 5)
        let rd = bits(w, 4, 0)
        let width = sf ? 64 : 32
        let rdS = genreg(rd, sf: sf)
        let rnS = genreg(rn, sf: sf)
        let u = !n   // N=0 → UBFM 族；N=1 → SBFM 族

        if u && imms == width - 1 {
            return ("lsr \(rdS), \(rnS), #\(immr)", "; 逻辑右移")
        }
        if u && imms == width - 2 {
            return ("lsl \(rdS), \(rnS), #\((width - immr) & (width - 1))", "; 逻辑左移")
        }
        if !u && imms == width - 1 && immr > 0 {
            return ("asr \(rdS), \(rnS), #\(immr)", "; 算术右移")
        }
        if !u && sf && immr == 0 && imms == 31 {
            return ("sxtw \(rdS), w\(rn)", "; 符号扩展 32→64")
        }
        if !u && immr == 0 && imms == 7 {
            return ("sxtb \(rdS), \(rnS)", "; 符号扩展字节")
        }
        if !u && immr == 0 && imms == 15 {
            return ("sxth \(rdS), \(rnS)", "; 符号扩展半字")
        }
        if u && immr == 0 && imms == 15 {
            return ("uxth \(rdS), \(rnS)", "; 零扩展半字")
        }
        if u && immr == 0 && imms == 7 {
            return ("uxtb \(rdS), \(rnS)", "; 零扩展字节")
        }
        return ("\(n ? "sbfm" : "ubfm") \(rdS), \(rnS), #\(immr), #\(imms)", "; 位域提取")
    }
}
