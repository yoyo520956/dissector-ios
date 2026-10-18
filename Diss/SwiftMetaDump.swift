import Foundation

// MARK: - Swift 元数据深解：__swift5_types → 类型描述符 → 字段描述符
// 输出每个 Swift 类型（class/struct/enum）的完整字段列表（名称 + 类型），比符号还原更深一层。

struct SwiftFieldDump: Identifiable, Hashable {
    let id: Int
    let name: String
    let typeName: String
}

struct SwiftTypeDump: Identifiable, Hashable {
    let id: Int
    let name: String
    let kind: String       // class / struct / enum
    let fields: [SwiftFieldDump]
}

final class SwiftMetaDumper {
    private let bin: [UInt8]
    private let segments: [MachSegment]
    private let sections: [MachSection]

    init(data: Data, segments: [MachSegment], sections: [MachSection]) {
        self.bin = [UInt8](data)
        self.segments = segments
        self.sections = sections
    }

    // MARK: - VA ↔ file 映射

    private func fileToVM(_ fo: UInt64) -> UInt64? {
        for seg in segments where fo >= seg.fileOff && fo < seg.fileOff + seg.fileSize {
            return fo - seg.fileOff + seg.vmaddr
        }
        return nil
    }

    private func vmToFile(_ vm: UInt64) -> UInt64? {
        for seg in segments where vm >= seg.vmaddr && vm < seg.vmaddr + seg.fileSize {
            return vm - seg.vmaddr + seg.fileOff
        }
        return nil
    }

    // relative int32 @fileOff（相对自身 VA）→ 目标 fileOff
    private func rel32(_ fo: UInt64) -> UInt64? {
        guard let selfVM = fileToVM(fo) else { return nil }
        let o = Int(fo)
        guard o >= 0, o + 4 <= bin.count else { return nil }
        let v = Int32(bitPattern: UInt32(bin[o]) | (UInt32(bin[o+1]) << 8) | (UInt32(bin[o+2]) << 16) | (UInt32(bin[o+3]) << 24))
        let targetVM = UInt64(bitPattern: Int64(selfVM) + Int64(v))
        return vmToFile(targetVM)
    }

    private func cstr(_ fo: UInt64, max: Int = 256) -> String {
        let o = Int(fo)
        guard o >= 0, o < bin.count else { return "" }
        var e = o
        let end = min(bin.count, o + max)
        while e < end, bin[e] != 0 { e += 1 }
        return String(bytes: bin[o..<e], encoding: .utf8) ?? ""
    }

    private func u32(_ fo: UInt64) -> UInt32 {
        let o = Int(fo)
        guard o >= 0, o + 4 <= bin.count else { return 0 }
        return UInt32(bin[o]) | (UInt32(bin[o+1]) << 8) | (UInt32(bin[o+2]) << 16) | (UInt32(bin[o+3]) << 24)
    }

    private func u16(_ fo: UInt64) -> UInt16 {
        let o = Int(fo)
        guard o >= 0, o + 2 <= bin.count else { return 0 }
        return UInt16(bin[o]) | (UInt16(bin[o+1]) << 8)
    }

    // MARK: - 主入口

    func dump() -> [SwiftTypeDump] {
        guard let sec = sections.first(where: { $0.name == "__swift5_types" }),
              sec.size >= 4 else { return [] }
        let count = Int(sec.size) / 4
        var out: [SwiftTypeDump] = []
        out.reserveCapacity(min(count, 8192))
        var id = 0
        for i in 0..<count {
            let relOff = sec.fileOffset + UInt64(i * 4)
            guard let descOff = rel32(relOff) else { continue }
            if let t = parseDescriptor(descOff, id: id) {
                out.append(t)
                id += 1
                if id >= 8192 { break }
            }
        }
        out.sort { $0.name < $1.name }
        return out
    }

    // MARK: - TypeContextDescriptor

    private func parseDescriptor(_ off: UInt64, id: Int) -> SwiftTypeDump? {
        let flags = u32(off)
        let kindCode = flags & 0x1F
        let kind: String
        switch kindCode {
        case 8: kind = "struct"
        case 9: kind = "enum"
        case 10: kind = "class"
        default: return nil
        }
        // common: flags(4) parent(4) name(4) access(4) fieldDesc(4)
        guard let nameOff = rel32(off + 8) else { return nil }
        let name = cstr(nameOff)
        guard !name.isEmpty else { return nil }

        var fields: [SwiftFieldDump] = []
        if let fdOff = rel32(off + 16) {
            fields = parseFieldDescriptor(fdOff)
        }
        return SwiftTypeDump(id: id, name: name, kind: kind, fields: fields)
    }

    // MARK: - FieldDescriptor

    private func parseFieldDescriptor(_ off: UInt64) -> [SwiftFieldDump] {
        let numFields = u32(off + 12)
        guard numFields > 0, numFields < 512 else { return [] }
        var out: [SwiftFieldDump] = []
        for i in 0..<numFields {
            let rec = off + 16 + UInt64(i) * 12
            // record: flags(4) mangledTypeName(rel4) fieldName(rel4)
            let flags = u32(rec)
            _ = flags
            var typeName = "?"
            if let mtOff = rel32(rec + 4) {
                let raw = cstr(mtOff, max: 120)
                typeName = SwiftMangledType.readable(raw)
            }
            var fname = ""
            if let fnOff = rel32(rec + 8) {
                fname = cstr(fnOff)
            }
            guard !fname.isEmpty else { continue }
            out.append(SwiftFieldDump(id: out.count, name: fname, typeName: typeName))
        }
        return out
    }
}

// MARK: - Swift 类型 mangled 短码映射

enum SwiftMangledType {
    static func readable(_ raw: String) -> String {
        let map: [String: String] = [
            "Si": "Int", "Sb": "Bool", "SS": "String", "Sf": "Float", "Sd": "Double",
            "Su": "UInt", "Sv": "UnsafeRawPointer", "Sa": "[Any]", "SQ": "Equatable",
            "SH": "Hashable", "Sj": "Numeric", "Sg": "Optional", "SD": "Double",
            "SC": "NSCoding?", "SV": "UnsafeMutableRawPointer", "Sx": "SetAlgebra",
            "Sr": "RangeReplaceableCollection", "Sy": "FixedWidthInteger",
            "Sz": "BinaryInteger", "S0": "Self"
        ]
        if let m = map[raw] { return m }
        // $s... 完整 mangled → 简化还原
        if raw.hasPrefix("$s") || raw.hasPrefix("_$s") {
            let d = SwiftDemangle.demangle(raw)
            return d == raw ? "swift类型" : d
        }
        return raw.isEmpty ? "?" : raw
    }
}
