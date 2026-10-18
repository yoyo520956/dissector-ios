import Foundation
import Combine

// 专业功能 · 符号标注系统
// 每个 IPA（按文件名隔离）一套标注：符号重命名 + 地址备注
// 类转储 / 符号表 / 反汇编 / 伪代码 全视图生效；UserDefaults 持久化

struct SymbolNote: Codable, Identifiable, Hashable {
    var id: String { key }
    var key: String        // "0x104ABC000"（地址）或 "s:_类名_方法"（符号名）
    var name: String       // 新名字（空 = 未重命名）
    var note: String       // 备注（空 = 无）
}

final class AnnotationStore: ObservableObject {
    static let shared = AnnotationStore()

    @Published private(set) var notes: [String: SymbolNote] = [:]
    private var fileKey = ""

    private static func storageKey(_ file: String) -> String {
        "dissector.ann." + file.replacingOccurrences(of: " ", with: "_")
    }

    /// 切换到某个 IPA 的标注集
    func load(for fileName: String) {
        fileKey = fileName
        let k = Self.storageKey(fileName)
        if let d = UserDefaults.standard.data(forKey: k),
           let list = try? JSONDecoder().decode([SymbolNote].self, from: d) {
            var m: [String: SymbolNote] = [:]
            for n in list { m[n.key] = n }
            notes = m
        } else {
            notes = [:]
        }
    }

    func save() {
        guard !fileKey.isEmpty else { return }
        let list = Array(notes.values)
        if let d = try? JSONEncoder().encode(list) {
            UserDefaults.standard.set(d, forKey: Self.storageKey(fileKey))
        }
    }

    func set(key: String, name: String, note: String) {
        let trimmedName = name.trimmingCharacters(in: .whitespaces)
        let trimmedNote = note.trimmingCharacters(in: .whitespaces)
        if trimmedName.isEmpty && trimmedNote.isEmpty {
            notes.removeValue(forKey: key)
        } else {
            notes[key] = SymbolNote(key: key, name: trimmedName, note: trimmedNote)
        }
        save()
        objectWillChange.send()
    }

    func remove(key: String) {
        notes.removeValue(forKey: key)
        save()
        objectWillChange.send()
    }

    // MARK: - 查询便捷方法

    static func addrKey(_ va: UInt64) -> String {
        String(format: "0x%llX", va)
    }

    static func symKey(_ name: String) -> String { "s:" + name }

    /// 地址标注名（优先），否则给 fallback
    func displayName(for va: UInt64, fallback: String) -> String {
        if let n = notes[Self.addrKey(va)], !n.name.isEmpty { return n.name }
        return fallback
    }

    func noteText(for va: UInt64) -> String? {
        let n = notes[Self.addrKey(va)]
        if let t = n?.note, !t.isEmpty { return t }
        return nil
    }

    func hasAnnotation(for va: UInt64) -> Bool {
        notes[Self.addrKey(va)] != nil
    }

    /// 符号名标注（符号表行用）
    func displayName(forSym name: String) -> String {
        if let n = notes[Self.symKey(name)], !n.name.isEmpty { return n.name }
        return name
    }

    func allCount() -> Int { notes.count }
}
