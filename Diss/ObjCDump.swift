import Foundation

// MARK: - ObjC 转储数据模型

struct ObjCMethodDump: Identifiable, Hashable {
    let id: Int
    let selector: String
    let typeEnc: String
    let readable: String
    let imp: UInt64
}

struct ObjCPropDump: Identifiable, Hashable {
    let id: Int
    let name: String
    let type: String
    let attrRaw: String
}

struct ObjCIvarDump: Identifiable, Hashable {
    let id: Int
    let name: String
    let type: String
}

struct ObjCClassDump: Identifiable, Hashable {
    let id: Int
    let name: String
    let superName: String
    let instanceMethods: [ObjCMethodDump]
    let classMethods: [ObjCMethodDump]
    let ivars: [ObjCIvarDump]
    let props: [ObjCPropDump]
    var methodCount: Int { instanceMethods.count + classMethods.count }
}

// MARK: - ObjC 类转储引擎（零依赖）
// classlist → objc_class → class_ro_t → 方法/属性/ivar 全解析
// 相对方法列表（iOS14+ 默认）精确解析；绝对指针路径 + chained fixup 启发式兜底。

final class ObjCDumper {
    private let bin: Data
    private let segments: [MachSegment]
    private let sections: [MachSection]
    private var resolveCache: [UInt64: UInt64] = [:]
    private var textVM: UInt64

    init(data: Data, segments: [MachSegment], sections: [MachSection]) {
        self.bin = data   // mmap 视图
        self.segments = segments
        self.sections = sections
        self.textVM = segments.first { $0.name == "__TEXT" }?.vmaddr ?? 0
    }

    // MARK: - VM → 文件偏移（含 chained fixup 启发式）

    private func rawMap(_ v: UInt64) -> UInt64? {
        for seg in segments where v >= seg.vmaddr && v < seg.vmaddr + seg.fileSize {
            return v - seg.vmaddr + seg.fileOff
        }
        return nil
    }

    func fileOffset(_ vm: UInt64) -> UInt64? {
        if vm == 0 { return nil }
        if let c = resolveCache[vm] { return c }
        var result: UInt64?
        // 1. 直接映射
        if let f = rawMap(vm) { result = f }
        // 2. chained fixup 启发式：rebase 条目的 target 位段提取
        if result == nil {
            for mask in [UInt64(0x7FFFFFFFFFFF), 0xFFFFFFFFFF, 0xFFFFFFFF] {
                let t = vm & mask
                if t != vm, let f = rawMap(t) { result = f; break }
                if let textVM = Optional(textVM), textVM > 0, let f = rawMap(textVM &+ t) { result = f; break }
            }
        }
        if let r = result { resolveCache[vm] = r }
        return result
    }

    private func cstr(_ off: UInt64, _ maxLen: Int = 512) -> String {
        // 微信等 iOS17+ 二进制：指针字段可能是 chained-fixup/auth-ptr raw 巨值，Int() 直接溢出 trap
        guard off <= UInt64(Int.max) else { return "" }
        let o = Int(off)
        guard o >= 0, o < bin.count else { return "" }
        var e = o
        let end = min(bin.count, o + maxLen)
        while e < end, bin[e] != 0 { e += 1 }
        return String(bytes: bin[o..<e], encoding: .utf8)
            ?? String(bytes: bin[o..<e], encoding: .isoLatin1)
            ?? ""
    }

    /// 带失败传播的安全读取（nil = 越界/巨值，调用方显式放弃该字段）
    private func u64s(_ off: UInt64) -> UInt64? {
        guard off <= UInt64(Int.max) else { return nil }
        let o = Int(off)
        guard o >= 0, o + 8 <= bin.count else { return nil }
        return u64(UInt64(o))
    }

    private func u32s(_ off: UInt64) -> UInt32? {
        guard off <= UInt64(Int.max) else { return nil }
        let o = Int(off)
        guard o >= 0, o + 4 <= bin.count else { return nil }
        return u32(UInt64(o))
    }

    private func u64(_ off: UInt64) -> UInt64 {
        guard off <= UInt64(Int.max) else { return 0 }
        let o = Int(off)
        guard o >= 0, o + 8 <= bin.count else { return 0 }
        return UInt64(bin[o]) | (UInt64(bin[o+1]) << 8) | (UInt64(bin[o+2]) << 16) | (UInt64(bin[o+3]) << 24)
            | (UInt64(bin[o+4]) << 32) | (UInt64(bin[o+5]) << 40) | (UInt64(bin[o+6]) << 48) | (UInt64(bin[o+7]) << 56)
    }

    private func u32(_ off: UInt64) -> UInt32 {
        guard off <= UInt64(Int.max) else { return 0 }
        let o = Int(off)
        guard o >= 0, o + 4 <= bin.count else { return 0 }
        return UInt32(bin[o]) | (UInt32(bin[o+1]) << 8) | (UInt32(bin[o+2]) << 16) | (UInt32(bin[o+3]) << 24)
    }

    private func i32(_ off: UInt64) -> Int32 {
        Int32(bitPattern: u32(off))
    }

    // MARK: - 主入口

    func dump() -> [ObjCClassDump] {
        guard let cl = sections.first(where: { $0.name == "__objc_classlist" }),
              cl.size >= 8 else { return [] }
        let count = Int(cl.size) / 8
        var out: [ObjCClassDump] = []
        out.reserveCapacity(min(count, 4096))
        var nextID = 0
        for i in 0..<count {
            let ptrOff = cl.fileOffset + UInt64(i * 8)
            guard Int(ptrOff) >= 0, Int(ptrOff) + 8 <= bin.count else { continue }
            let raw = u64(ptrOff)
            guard raw > 0, raw <= UInt64(Int.max), let clsOff = fileOffset(raw) else { continue }
            if let c = dumpClass(at: clsOff, id: nextID) {
                out.append(c)
                nextID += 1
                if nextID >= 4096 { break }
            }
        }
        out.sort { $0.name < $1.name }
        return out
    }

    // MARK: - objc_class → class_ro_t

    private func dumpClass(at clsOff: UInt64, id: Int) -> ObjCClassDump? {
        guard Int(clsOff) >= 0, Int(clsOff) + 40 <= bin.count else { return nil }
        let isaRaw = u64(clsOff)
        let superRaw = u64(clsOff + 8)
        let bitsRaw = u64(clsOff + 24)
        let roVM = bitsRaw & 0x00007FFFFFFFFFF8
        guard roVM > 0, let roOff = fileOffset(roVM) else { return nil }
        let flags = u32(roOff)
        _ = flags

        let name = cstrAt(roOff + 0x18)
        guard !name.isEmpty else { return nil }

        let superName = readClassName(ofVM: superRaw)

        // 实例方法（类 ro 的 baseMethods）
        let instMethods = readMethods(listVM: ptrAt(roOff + 0x20), classMethod: false)
        // 类方法（元类 ro 的 baseMethods）
        var clsMethods: [ObjCMethodDump] = []
        if let metaOff = fileOffset(isaRaw), Int(metaOff) + 32 <= bin.count {
            let metaBits = u64(metaOff + 24)
            let metaRoVM = metaBits & 0x00007FFFFFFFFFF8
            if let metaRoOff = fileOffset(metaRoVM) {
                clsMethods = readMethods(listVM: ptrAt(metaRoOff + 0x20), classMethod: true)
            }
        }

        let ivars = readIvars(listVM: ptrAt(roOff + 0x30))
        let props = readProps(listVM: ptrAt(roOff + 0x40))

        return ObjCClassDump(id: id, name: name, superName: superName,
                             instanceMethods: instMethods, classMethods: clsMethods,
                             ivars: ivars, props: props)
    }

    // ro 的 name 字段：可能绝对指针 / relative?（ro name 是 64-bit 指针）
    private func ptrAt(_ off: UInt64) -> UInt64 { u64(off) }

    private func cstrAt(_ off: UInt64) -> String {
        let vm = u64(off)
        guard let f = fileOffset(vm) else { return "" }
        return cstr(f)
    }

    private func readClassName(ofVM vm: UInt64) -> String {
        guard vm > 0, vm <= UInt64(Int.max), let clsOff = fileOffset(vm),
              Int(clsOff) + 32 <= bin.count else { return "" }
        let bits = u64(clsOff + 24)
        let roVM = bits & 0x00007FFFFFFFFFF8
        guard let roOff = fileOffset(roVM) else { return "" }
        return cstrAt(roOff + 0x18)
    }

    // MARK: - method_list_t

    private func readMethods(listVM: UInt64, classMethod: Bool) -> [ObjCMethodDump] {
        guard listVM > 0, listVM <= UInt64(Int.max), let listOff = fileOffset(listVM),
              Int(listOff) >= 0, Int(listOff) + 8 <= bin.count else { return [] }
        guard let hdr = u32s(listOff), let count = u32s(listOff + 4) else { return [] }
        guard count > 0, count < 20000 else { return [] }
        var out: [ObjCMethodDump] = []
        out.reserveCapacity(Int(count))
        let relative = (hdr & 0x80000000) != 0
        for i in 0..<count {
            var selName = ""
            var typeEnc = ""
            var imp: UInt64 = 0
            if relative {
                let entryOff = listOff + 8 + UInt64(i) * 12
                let entryVM = listVM + 8 + UInt64(i) * 12
                guard Int(entryOff) + 12 <= bin.count else { break }
                let nameOff = i32(entryOff)
                let typeOff = i32(entryOff + 4)
                let impOff = i32(entryOff + 8)
                let nameVM = UInt64(bitPattern: Int64(entryVM) + Int64(nameOff))
                let typeVM = UInt64(bitPattern: Int64(entryVM) + Int64(typeOff))
                imp = UInt64(bitPattern: Int64(entryVM) + Int64(impOff))
                if let nf = fileOffset(nameVM) { selName = cstr(nf) }
                if let tf = fileOffset(typeVM) { typeEnc = cstr(tf, 256) }
                _ = impOff
            } else {
                let entSize = Int(hdr & 0x7FFFFFFF)
                let es = entSize >= 24 ? entSize : 24
                let entryOff = listOff + 8 + UInt64(i) * UInt64(es)
                guard Int(entryOff) + 24 <= bin.count else { break }
                if let nf = fileOffset(u64(entryOff)) { selName = cstr(nf) }
                if let tf = fileOffset(u64(entryOff + 8)) { typeEnc = cstr(tf, 256) }
                imp = u64(entryOff + 16)
            }
            guard !selName.isEmpty else { continue }
            let readable = ObjCTypeEnc.methodReadable(name: selName, types: typeEnc, classMethod: classMethod)
            out.append(ObjCMethodDump(id: out.count, selector: selName, typeEnc: typeEnc,
                                      readable: readable, imp: imp))
        }
        return out
    }

    // MARK: - ivar_list_t

    private func readIvars(listVM: UInt64) -> [ObjCIvarDump] {
        guard listVM > 0, listVM <= UInt64(Int.max), let listOff = fileOffset(listVM),
              Int(listOff) >= 0, Int(listOff) + 8 <= bin.count else { return [] }
        guard let hdr = u32s(listOff), let count = u32s(listOff + 4) else { return [] }
        guard count > 0, count < 1000 else { return [] }
        var out: [ObjCIvarDump] = []
        let relative = (hdr & 0x80000000) != 0
        for i in 0..<count {
            var name = ""
            var type = ""
            if relative {
                // relative ivar entry: 4×int32（offset/name/type/...）
                let entryVM = listVM + 8 + UInt64(i) * 16
                let entryOff = listOff + 8 + UInt64(i) * 16
                guard Int(entryOff) + 16 <= bin.count else { break }
                let nameVM = UInt64(bitPattern: Int64(entryVM) + Int64(i32(entryOff + 4)))
                let typeVM = UInt64(bitPattern: Int64(entryVM) + Int64(i32(entryOff + 8)))
                if let nf = fileOffset(nameVM) { name = cstr(nf) }
                if let tf = fileOffset(typeVM) { type = cstr(tf, 128) }
            } else {
                let entryOff = listOff + 8 + UInt64(i) * 32
                guard Int(entryOff) + 32 <= bin.count else { break }
                if let nf = fileOffset(u64(entryOff + 8)) { name = cstr(nf) }
                if let tf = fileOffset(u64(entryOff + 16)) { type = cstr(tf, 128) }
            }
            guard !name.isEmpty else { continue }
            out.append(ObjCIvarDump(id: out.count, name: name,
                                    type: ObjCTypeEnc.readableType(type)))
        }
        return out
    }

    // MARK: - property_list_t

    private func readProps(listVM: UInt64) -> [ObjCPropDump] {
        guard listVM > 0, listVM <= UInt64(Int.max), let listOff = fileOffset(listVM),
              Int(listOff) >= 0, Int(listOff) + 8 <= bin.count else { return [] }
        guard let hdr = u32s(listOff), let count = u32s(listOff + 4) else { return [] }
        guard count > 0, count < 1000 else { return [] }
        var out: [ObjCPropDump] = []
        let relative = (hdr & 0x80000000) != 0
        for i in 0..<count {
            var name = ""
            var attr = ""
            if relative {
                let entryVM = listVM + 8 + UInt64(i) * 8
                let entryOff = listOff + 8 + UInt64(i) * 8
                guard Int(entryOff) + 8 <= bin.count else { break }
                let nameVM = UInt64(bitPattern: Int64(entryVM) + Int64(i32(entryOff)))
                let attrVM = UInt64(bitPattern: Int64(entryVM) + Int64(i32(entryOff + 4)))
                if let nf = fileOffset(nameVM) { name = cstr(nf) }
                if let af = fileOffset(attrVM) { attr = cstr(af, 256) }
            } else {
                let entryOff = listOff + 8 + UInt64(i) * 16
                guard Int(entryOff) + 16 <= bin.count else { break }
                if let nf = fileOffset(u64(entryOff)) { name = cstr(nf) }
                if let af = fileOffset(u64(entryOff + 8)) { attr = cstr(af, 256) }
            }
            guard !name.isEmpty else { continue }
            let parsed = ObjCTypeEnc.propAttrs(attr)
            out.append(ObjCPropDump(id: out.count, name: name,
                                    type: parsed.0, attrRaw: attr))
        }
        return out
    }

    // MARK: - class-dump 风格 .h 生成

    static func headerText(_ classes: [ObjCClassDump]) -> String {
        var lines: [String] = []
        lines.append("// 由拆解者 Dissector 自动生成")
        lines.append("// 共 \(classes.count) 个 ObjC 类的完整接口声明")
        lines.append("")
        for c in classes {
            let sup = c.superName.isEmpty ? "NSObject" : c.superName
            lines.append("@interface \(c.name) : \(sup)")
            if !c.ivars.isEmpty {
                lines.append("{")
                for iv in c.ivars {
                    lines.append("    \(iv.type) \(iv.name);")
                }
                lines.append("}")
            }
            for p in c.props {
                lines.append("@property \(p.type) \(p.name); // \(p.attrRaw)")
            }
            if !c.classMethods.isEmpty {
                lines.append("")
                for m in c.classMethods {
                    lines.append("+ \(m.readable);")
                }
            }
            if !c.instanceMethods.isEmpty {
                lines.append("")
                for m in c.instanceMethods {
                    lines.append("- \(m.readable);")
                }
            }
            lines.append("@end")
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - 类型编码解码器

enum ObjCTypeEnc {

    // "v16@0:8" + "viewDidLoad" → "- (void)viewDidLoad"
    static func methodReadable(name: String, types: String, classMethod: Bool) -> String {
        let tokens = tokenize(types)
        guard !tokens.isEmpty else {
            return "\(classMethod ? "+" : "-") (\(name.isEmpty ? "?" : name))"
        }
        // tokens[0]=返回类型 tokens[1]=@(self) tokens[2]=:(_cmd) tokens[3..]=参数
        let retType = readableType(tokens[0])
        let args = tokens.count >= 3 ? Array(tokens[3...]) : []
        let prefix = classMethod ? "+" : "-"
        let colons = name.components(separatedBy: ":").count - 1
        if colons == 0 || args.isEmpty {
            return "\(prefix) (\(retType))\(name)"
        }
        // 按冒号拆 selector：method:withArg: → ["method", "withArg", ""]
        var parts = name.components(separatedBy: ":")
        if parts.last == "_" || parts.last == "" { parts.removeLast() }
        var out = "\(prefix) (\(retType))\(parts[0]):(\(args[0]))arg1"
        var idx = 1
        while idx < parts.count {
            let a = idx < args.count ? args[idx] : "?"
            out += " \(parts[idx]):(\(a))arg\(idx + 1)"
            idx += 1
        }
        return out
    }

    // 类型编码 → 可读类型
    static func readableType(_ enc: String) -> String {
        var t = enc
        if t.isEmpty { return "?" }
        // @ 引号类名：@"NSString"
        if t.hasPrefix("@\"") && t.count >= 3 {
            let inner = String(t.dropFirst(2).dropLast())
            return inner + " *"
        }
        // ^@ 等指针
        if t.hasPrefix("^") {
            return readableType(String(t.dropFirst())) + " *"
        }
        if t.hasPrefix("^{") || t.hasPrefix("{") {
            let nm = t.trimmingCharacters(in: CharacterSet(charactersIn: "^{}"))
            let structName = nm.components(separatedBy: "=").first ?? nm
            return "struct \(structName.isEmpty ? "?" : structName)"
        }
        if t.hasPrefix("^{?}") || t == "^?" { return "void *" }
        if t.hasPrefix("@?") { return "block" }
        // 取首个类型字符
        let c = t.first!
        let map: [Character: String] = [
            "v": "void", "B": "BOOL", "c": "char", "C": "unsigned char",
            "s": "short", "S": "unsigned short", "i": "int", "I": "unsigned int",
            "l": "long", "L": "unsigned long", "q": "long long", "Q": "unsigned long long",
            "f": "float", "d": "double", "@": "id", "#": "Class", ":": "SEL",
            "*": "char *", "?": "void *"
        ]
        return map[c] ?? String(c)
    }

    // 属性 attrRaw："T@\"NSString\",C,N,V_name" → (类型, 说明)
    static func propAttrs(_ raw: String) -> (String, String) {
        var type = "?"
        var notes: [String] = []
        for seg in raw.components(separatedBy: ",") {
            if seg.hasPrefix("T") {
                type = readableType(String(seg.dropFirst()))
            } else if seg == "R" {
                notes.append("readonly")
            } else if seg == "C" {
                notes.append("copy")
            } else if seg == "&" {
                notes.append("strong")
            } else if seg == "N" {
                notes.append("nonatomic")
            } else if seg == "W" {
                notes.append("weak")
            } else if seg.hasPrefix("V") {
                notes.append("ivar=\(seg.dropFirst())")
            }
        }
        return (type, notes.joined(separator: ", "))
    }

    // MARK: - tokenizer："v16@0:8" → ["v", "@", ":"]（数字 offset 丢弃）

    private static func tokenize(_ s: String) -> [String] {
        var out: [String] = []
        let chars = Array(s)
        var pos = 0
        while pos < chars.count {
            let c = chars[pos]
            if c.isNumber || c.isWhitespace { pos += 1; continue }
            if c == "^" {
                // 指针：吃 ^ 后跟一个类型
                var t = "^"
                pos += 1
                while pos < chars.count, chars[pos].isNumber || chars[pos].isWhitespace { pos += 1 }
                if pos < chars.count {
                    t.append(chars[pos])
                    pos += 1
                }
                out.append(t)
                continue
            }
            if c == "{" || c == "(" {
                // 结构体/联合：到匹配括号
                let open: Character = c == "{" ? "{" : "("
                let close: Character = c == "{" ? "}" : ")"
                var depth = 0
                var t = ""
                while pos < chars.count {
                    t.append(chars[pos])
                    if chars[pos] == open { depth += 1 }
                    if chars[pos] == close { depth -= 1; if depth == 0 { pos += 1; break } }
                    pos += 1
                }
                out.append(t)
                continue
            }
            if c == "@" {
                // @"ClassName"
                if pos + 1 < chars.count && chars[pos + 1] == "\"" {
                    var t = "@\""
                    pos += 2
                    while pos < chars.count, chars[pos] != "\"" { t.append(chars[pos]); pos += 1 }
                    if pos < chars.count { t.append("\""); pos += 1 }
                    out.append(t)
                    continue
                }
                out.append("@")
                pos += 1
                continue
            }
            out.append(String(c))
            pos += 1
        }
        return out
    }
}
