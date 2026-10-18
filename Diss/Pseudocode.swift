import Foundation

// MARK: - 伪代码近似生成器（汇编 → 类 C 片段）
// 规则引擎：跟踪寄存器赋值 + 模式翻译。输出为「可读化近似」——不是真正的反编译。

@MainActor
enum Pseudocoder {

    struct Result {
        var code: [String]          // 伪代码行
        var notes: Int = 0          // 未能翻译的指令数
    }

    static func generate(_ lines: [DisasmLine], engine: AnalysisEngine) -> Result {
        var out: [String] = []
        var regValue: [String: String] = [:]     // 寄存器 → 最近赋值（数字或符号描述）
        var stackNames: [Int: String] = [:]      // 栈偏移 → 变量名
        var unknown = 0

        out.append("// \(lines.first.map { String(format: "sub_%llX", $0.addr) } ?? "func")() {")

        for l in lines {
            let t = l.text
            let parts = t.split(separator: " ").map(String.init)
            guard let op = parts.first else { continue }
            let operands = parts.count > 1 ? parts[1] : ""

            switch op {
            case "movz", "movn", "mov":
                // mov x0, #8  →  x0 = 8;
                if let imm = immValue(t), let rd = operand(t, 1) {
                    let val = op == "movn" ? "~\(imm)" : imm
                    regValue[rd] = val
                    out.append("\(rd) = \(val);")
                }
            case "add", "sub":
                if operands.contains("sp, sp") || t.contains("sp, sp, #") {
                    // 栈帧调整，跳过
                    continue
                }
                if let rd = operand(t, 1), let rs = operand(t, 2), rs == rd {
                    // add x0, x0, #8 → x0 += 8;
                    if let imm = immValue(t) {
                        regValue[rd] = (regValue[rd] ?? rd) + (op == "add" ? "+" : "-") + "\(imm)"
                        out.append("\(rd) \(op == "add" ? "+" : "-")= \(imm);")
                    }
                } else if let rd = operand(t, 1), t.contains("#") {
                    // add x0, x1, #8 → x0 = x1 + 8;
                    if let imm = immValue(t), let rs = operand(t, 2) {
                        regValue[rd] = "\(rs) \(op == "add" ? "+" : "-") \(imm)"
                        out.append("\(rd) = \(rs) \(op == "add" ? "+" : "-") \(imm);")
                    }
                } else if let rd = operand(t, 1) {
                    let note = l.note.isEmpty ? "" : " \(l.note)"
                    out.append("// \(t)\(note)")
                }
            case "adrp", "adr":
                if let rd = operand(t, 1) {
                    if l.note.contains("\"") {
                        // 字符串页基址（后续 add 补全）——注释掉
                        out.append("// \(t) \(l.note)")
                    } else if let page = hexNum(t) {
                        regValue[rd] = String(format: "0x%llX", page)
                        out.append("\(rd) = \(String(format: "0x%llX", page)); // 数据地址")
                    }
                }
            case "ldr":
                // ldr x0, [sp, #8] / ldr x0, [x1, #off]
                if let rd = operand(t, 1) {
                    if let src = memOperand(t) {
                        if src.hasPrefix("sp") {
                            let off = memOffset(t)
                            let name = stackName(off)
                            regValue[rd] = name
                            out.append("\(rd) = \(name);")
                        } else {
                            let deref = derefWith(engine: engine, t: t, note: l.note)
                            regValue[rd] = deref
                            out.append("\(rd) = \(deref);")
                        }
                    }
                }
            case "str":
                // str x0, [sp, #8] → local_8 = x0;
                if let rs = operand(t, 1) {
                    let src = regValue[rs] ?? rs
                    if let dst = memOperand(t), dst.hasPrefix("sp") {
                        let off = memOffset(t)
                        let name = stackName(off)
                        out.append("\(name) = \(src);")
                    } else if let dst = memOperand(t) {
                        out.append("*\(dst) = \(src);")
                    }
                }
            case "bl":
                // bl 0x… → 目标符号调用
                let target = hexNum(t).map { String(format: "0x%llX", $0) } ?? "?"
                let name = l.note.hasPrefix("; → ") ? String(l.note.dropFirst(4)) : target
                let args = callArgs(regValue)
                let retAssigned = regValue["x0"] != nil
                if args.isEmpty {
                    out.append("\(name)();")
                } else {
                    out.append("\(name)(\(args.joined(separator: ", ")));")
                }
                _ = retAssigned
                // 调用后 x0 可能被覆盖（返回值）
                regValue["x0"] = "返回值"
            case "blr":
                let rn = operand(t, 1) ?? "?"
                out.append("\(rn)(\(callArgs(regValue).joined(separator: ", ")));")
            case "ret":
                let rv = regValue["x0"]
                if let rv = rv, rv != "返回值" {
                    out.append("return \(rv);")
                } else {
                    out.append("return;")
                }
            case "cbz", "cbnz", "tbz", "tbnz":
                if let target = hexNum(t), inRange(target, lines) {
                    let reg = operand(t, 1) ?? "?"
                    let cond = op == "cbz" ? "\(reg) == 0" : (op == "cbnz" ? "\(reg) != 0" : "\(reg) 位测试")
                    out.append("if (\(cond)) goto L_\(String(target, radix: 16));")
                } else {
                    out.append("// \(t)")
                }
            case "b":
                if let target = hexNum(t), inRange(target, lines) {
                    out.append("goto L_\(String(target, radix: 16));")
                } else if let target = hexNum(t) {
                    out.append("goto \(String(format: "0x%llX", target)); // 函数外")
                }
            default:
                if op.hasPrefix("b.") {
                    // b.eq 等
                    if let target = hexNum(t), inRange(target, lines) {
                        let cond = op.dropFirst(2)
                        out.append("if (\(cond)) goto L_\(String(target, radix: 16));")
                    }
                } else if op == "cmp" {
                    let a = operand(t, 1) ?? "?"
                    let b = immValue(t) ?? operand(t, 2) ?? "?"
                    out.append("cmp: \(a) vs \(b)")
                } else if op == "stp" || op == "ldp" {
                    continue // 寄存器对存取，噪音，跳过
                } else if op == "nop" {
                    continue
                } else if op == "cset" {
                    if let rd = operand(t, 1) {
                        out.append("\(rd) = (\(op)==条件成立 ? 1 : 0) // \(t)")
                    }
                } else if op == "adrp" || op == "mrs" || op == "msr" || op == "svc" {
                    out.append("// \(t)")
                } else if op.hasPrefix(".inst") {
                    unknown += 1
                    out.append("// \(t)")
                } else {
                    let note = l.note.isEmpty ? "" : " \(l.note)"
                    out.append("// \(t)\(note)")
                    unknown += 1
                }
            }

            // 标签行：若有行地址被前文 goto 引用，插入标签
        }

        // 尾部收口
        out.append("}")
        return Result(code: out, notes: unknown)
    }

    // MARK: - 工具

    private static func immValue(_ t: String) -> String? {
        // 取 # 后数字
        guard let r = t.range(of: "#(\\d+)", options: .regularExpression) else { return nil }
        return t[r].dropFirst().description
    }

    private static func hexNum(_ t: String) -> UInt64? {
        guard let r = t.range(of: "0x[0-9a-fA-F]+", options: .regularExpression) else { return nil }
        return UInt64(t[r].dropFirst(2), radix: 16)
    }

    private static func operand(_ t: String, _ idx: Int) -> String? {
        let parts = t.split(separator: " ").map(String.init)
        guard idx < parts.count else { return nil }
        return parts[idx].trimmingCharacters(in: CharacterSet(charactersIn: ","))
    }

    private static func memOperand(_ t: String) -> String? {
        // [sp, #8] → sp / [x1, #8] → x1
        guard let s = t.range(of: "\\[([^\\]]+)\\]", options: .regularExpression) else { return nil }
        let inner = String(t[s].dropFirst().dropLast())
        return inner.components(separatedBy: ",").first?.trimmingCharacters(in: .whitespaces)
    }

    private static func memOffset(_ t: String) -> Int {
        guard let r = t.range(of: "#(\\d+)", options: .regularExpression) else { return 0 }
        return Int(t[r].dropFirst()) ?? 0
    }

    private static func stackName(_ off: Int) -> String {
        return "local_\(off)"
    }

    private static func derefWith(engine: AnalysisEngine, t: String, note: String) -> String {
        // ldr x0, [x1, #off] 且 x1 = 已知地址 → 查字符串
        if note.contains("\"") {
            if let r = note.range(of: "\"[^\"]*\"", options: .regularExpression) {
                return String(note[r])
            }
        }
        if let addrS = note.range(of: "0x[0-9a-fA-F]+", options: .regularExpression) {
            if let vm = UInt64(note[addrS].dropFirst(2), radix: 16),
               let s = engine.stringAt(vm: vm) {
                return "\"\(s.prefix(40))\""
            }
        }
        let m = memOperand(t) ?? "?"
        return "*\(m)"
    }

    private static func callArgs(_ regValue: [String: String]) -> [String] {
        var args: [String] = []
        for r in ["x0", "x1", "x2", "x3"] {
            if let v = regValue[r] {
                args.append(v)
            }
        }
        return args
    }

    private static func inRange(_ addr: UInt64, _ lines: [DisasmLine]) -> Bool {
        guard let first = lines.first?.addr, let last = lines.last?.addr else { return false }
        return addr >= first && addr <= last
    }
}
