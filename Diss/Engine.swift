import Foundation
import Combine

// 分析总引擎 v2：
// 导入三通道（Documents 扫描 / 文件选择器 / 分享打开）→ 统一拷入 Documents/ 入库
// → 本地文件直接读（无安全作用域问题）→ ZIP 目录 → 主二进制 → Mach-O 全解析
// 反汇编 / 资源预览数据源也在引擎里

// 后台分析产物包（analyzeCore → 主线程落地）
struct AnalyzePack {
    let zip: ZipReader
    let binData: Data
    let result: AnalysisResult
    let callGraph: [UInt64: [XrefSite]]
    let xrefStats: (targets: Int, sites: Int)
    let funcMap: [UInt64: String]
}

@MainActor
final class AnalysisEngine: ObservableObject {
    enum Phase: Equatable {
        case idle
        case working(String)
        case done
        case failed(String)
    }

    @Published var phase: Phase = .idle
    @Published var result = AnalysisResult()
    @Published var pickedURL: URL?
    @Published var fileName: String = ""
    @Published var importedURLs: [URL] = []       // Documents 里的 IPA 列表
    @Published var toast: String?                  // 轻提示（导入成功等）

    private var zip: ZipReader?
    private var binData: Data = Data()
    private var funcSymbolMap: [UInt64: String] = [:]

    // 专业层：交叉引用图 + 扫描统计
    @Published var callGraph: [UInt64: [XrefSite]] = [:]
    @Published var xrefStats: (targets: Int, sites: Int) = (0, 0)

    // MARK: - 导入三通道

    /// 文件选择器 / 分享打开 走这里：先入库（拷到 Documents），再分析
    func importFromURL(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let doc = Self.documentsDir()
            var dest = doc.appendingPathComponent(url.lastPathComponent)
            if FileManager.default.fileExists(atPath: dest.path) {
                let ts = Int(Date().timeIntervalSince1970)
                dest = doc.appendingPathComponent("\(ts)-\(url.lastPathComponent)")
            }
            try FileManager.default.copyItem(at: url, to: dest)
            toast = "已入库：\(dest.lastPathComponent)"
            refreshImportList()
            openLocal(dest)
        } catch {
            phase = .failed("导入失败：\(error.localizedDescription)")
        }
    }

    /// Documents 里点选已有文件直接分析（本地文件，无作用域）
    func openLocal(_ url: URL) {
        phase = .working("打开文件…")
        result = AnalysisResult()
        binData = Data()
        fileName = url.lastPathComponent
        pickedURL = url
        Task { await self.analyze(url: url) }
    }

    func deleteImported(_ url: URL) {
        try? FileManager.default.removeItem(at: url)
        refreshImportList()
        if pickedURL == url { reset() }
    }

    func refreshImportList() {
        let doc = Self.documentsDir()
        let items = (try? FileManager.default.contentsOfDirectory(
            at: doc, includingPropertiesForKeys: nil)) ?? []
        importedURLs = items
            .filter { $0.pathExtension.lowercased() == "ipa" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    nonisolated static func documentsDir() -> URL {
        let doc = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: doc, withIntermediateDirectories: true)
        return doc
    }

    func reset() {
        phase = .idle
        result = AnalysisResult()
        binData = Data()
        pickedURL = nil
        fileName = ""
        zip = nil
        funcSymbolMap = [:]
        callGraph = [:]
        xrefStats = (0, 0)
    }

    // MARK: - 主流程

    private func analyze(url: URL) async {
        do {
            phase = .working("读取 ZIP 目录…")
            // 121MB 级二进制的全链路解析全部后台跑，绝不占主线程
            let pack = try await Task.detached(priority: .userInitiated) { () -> AnalyzePack in
                try Self.analyzeCore(url: url) { msg in
                    Task { @MainActor [weak self] in self?.phase = .working(msg) }
                }
            }.value
            zip = pack.zip
            binData = pack.binData
            result = pack.result
            callGraph = pack.callGraph
            xrefStats = pack.xrefStats
            funcSymbolMap = pack.funcMap
            phase = .done
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    nonisolated private static func analyzeCore(url: URL, progress: @escaping @Sendable (String) -> Void) throws -> AnalyzePack {
        progress("读取 ZIP 目录…")
        let z = try ZipReader(url: url)
        let zr = z
        let result = AnalysisResult()
        result.entries = zr.entries
        result.totalUncompressed = zr.totalUncompressed

        // 定位 Payload/*.app/（一级 .app + Info.plist 验证；大小写兼容）
        progress("定位 App 包…")
        var appFolder = ""
        var fallback = ""
        for e in zr.entries {
            guard !e.isDirectory else { continue }
            let lower = e.path.lowercased()
            guard lower.hasPrefix("payload/") else { continue }
            let rest = e.path.dropFirst(8)
            let comps = rest.split(separator: "/", omittingEmptySubsequences: true)
            guard comps.count >= 2, comps[0].lowercased().hasSuffix(".app") else { continue }
            let candidate = "Payload/" + comps[0] + "/"
            if zr.entry(candidate + "Info.plist") != nil {
                appFolder = candidate
                break
            }
            if fallback.isEmpty { fallback = candidate }
        }
        if appFolder.isEmpty { appFolder = fallback }
        guard !appFolder.isEmpty else { throw IPAError.notZip("包内未找到 Payload/*.app 目录") }
        result.appFolder = appFolder

        progress("读取 Info.plist…")
        if let ip = zr.entry(appFolder + "Info.plist") {
            let d = try zr.data(for: ip)
            result.info = Extractors.appInfo(from: d)
        }

        progress("解压主二进制…")
        let exeName = result.info.executable.isEmpty ? "主程序" : result.info.executable
        let binPath = appFolder + exeName
        guard let binEntry = zr.entry(binPath) else {
            throw IPAError.noBinary("\(binPath)（查 Info.plist 的 CFBundleExecutable）")
        }
        let binData = try zr.data(for: binEntry, maxBytes: 512 * 1024 * 1024)
        guard binData.count == Int(binEntry.size) else {
            throw IPAError.notZip("主二进制解压不完整（\(binData.count)/\(binEntry.size)）")
        }
        result.summary.fileSize = binEntry.size

        progress("解析 Mach-O 结构…")
        let parser = MachOParser(data: binData)
        try parser.parse()
        result.segments = parser.segments
        result.allSections = parser.allSections
        result.dylibs = parser.dylibs
        result.summary.minOS = parser.summary.minOS
        result.summary.sdkVersion = parser.summary.sdkVersion
        result.summary.uuid = parser.summary.uuid
        result.summary.encrypted = parser.summary.encrypted
        result.summary.fileType = parser.summary.fileType
        result.summary.format = parser.summary.format
        result.summary.symbolCount = parser.summary.symbolCount
        result.summary.dylibCount = parser.summary.dylibCount
        result.symbols = parser.symbolsRaw

        let textSec = parser.allSections.first { $0.segment == "__TEXT" && $0.name == "__text" }
        result.textSection = textSec
        var full = parser.symbolsFull
        if let t = textSec {
            for idx in full.indices {
                let sy = full[idx]
                if sy.value >= t.addr && sy.value < t.addr + t.size {
                    full[idx] = MachSymbol(id: sy.id, name: sy.name, value: sy.value, kind: "func")
                }
            }
        }
        result.symbolsFull = full
        var funcMap: [UInt64: String] = [:]
        for sy in full where sy.kind == "func" {
            if funcMap[sy.value] == nil { funcMap[sy.value] = sy.name }
        }

        progress("构建交叉引用图…")
        var cg: [UInt64: [XrefSite]] = [:]
        var st: (targets: Int, sites: Int) = (0, 0)
        if let t = textSec {
            let (g, n) = XrefEngine.buildCallGraph(bin: binData, textSec: t)
            cg = g
            st = (g.count, n)
        }

        progress("提取类名与字符串…")
        var strings: [String] = []
        for sec in parser.allSections {
            let nm = sec.name
            guard nm == "__cstring" || nm == "__objc_classname" || nm == "__objc_methname" else { continue }
            let d = parser.sectionData(sec, from: binData, limit: 8 * 1024 * 1024)
            strings.append(contentsOf: Extractors.cStrings(from: d))
            if strings.count > 600_000 { break }   // 内存保护：超限停止收集
        }
        if result.summary.symbolCount > 0 {
            strings.append(contentsOf: parser.symbolsRaw)
        }
        if strings.count > 900_000 { strings = Array(strings.prefix(900_000)) }
        let objc = Extractors.objcNames(strings)
        result.classNames = objc.classes
        result.methodNames = objc.methods
        result.cstrings = Array(Set(strings)).sorted()
        result.summary.classCount = objc.classes.count
        result.summary.methodCount = objc.methods.count

        progress("还原 Swift 符号…")
        result.swiftSymbols = SwiftDemangle.demangleList(result.cstrings)

        progress("读取描述文件…")
        if let mp = zr.entry(appFolder + "embedded.mobileprovision") {
            let raw = try zr.data(for: mp)
            result.provision = Extractors.provision(from: raw)
        }

        return AnalyzePack(zip: z, binData: binData, result: result,
                           callGraph: cg, xrefStats: st, funcMap: funcMap)
    }

    // MARK: - 给详情页用的原始数据

    func sectionRaw(_ sec: MachSection) -> Data {
        guard !binData.isEmpty else { return Data() }
        let parser = MachOParser(data: binData)
        return parser.sectionData(sec, from: binData, limit: 4096)
    }

    // MARK: - 反汇编数据源

    var funcSymbols: [MachSymbol] {
        result.symbolsFull.filter { $0.kind == "func" }.sorted { $0.value < $1.value }
    }

    func disassembleFunction(at va: UInt64, maxInstructions: Int) -> [DisasmLine] {
        guard let t = result.textSection, !binData.isEmpty else { return [] }
        guard va >= t.addr, va < t.addr + t.size else { return [] }
        let off = Int(va - t.addr)
        guard off < binData.count else { return [] }
        let len = min(maxInstructions * 4, binData.count - off)
        guard len >= 4 else { return [] }
        let d = binData.subdata(in: off..<(off + len))
        var lines = ARM64Disassembler.disassemble(d, baseVA: va,
                                                  maxInstructions: maxInstructions,
                                                  symbols: funcSymbolMap)
        // 字符串引用标注：adrp Xd, page 后紧跟 add Xd, Xd, #imm → 拼出 VA 查字符串表
        buildStringMap()
        for i in lines.indices {
            guard lines[i].text.hasPrefix("adrp ") else { continue }
            guard let page = hexTarget(lines[i].text) else { continue }
            let parts = lines[i].text.split(separator: " ")
            guard parts.count >= 2 else { continue }
            let reg = String(parts[1])
            for j in (i + 1)..<min(i + 4, lines.count) {
                let t2 = lines[j].text
                if t2.hasPrefix("add \(reg), \(reg), #") {
                    let numPart = t2.dropFirst("add \(reg), \(reg), #".count)
                        .components(separatedBy: ", ").first ?? "0"
                    let imm = UInt64(numPart) ?? 0
                    let va2 = page &+ imm
                    if let s = stringByAddr[va2] {
                        lines[j].note = "; → \"\(s.prefix(60))\""
                    } else {
                        lines[j].note = "; → 数据地址 \(String(format: "0x%llX", va2))"
                    }
                    break
                }
            }
        }
        return lines
    }

    private func hexTarget(_ text: String) -> UInt64? {
        guard let r = text.range(of: "0x[0-9a-fA-F]+", options: .regularExpression) else { return nil }
        return UInt64(text[r].dropFirst(2), radix: 16)
    }

    // MARK: - 资源预览数据源

    func resourceData(for entry: ZipEntry, limit: Int = 4 * 1024 * 1024) -> Data? {
        guard let z = zip, let e = z.entry(entry.path) else { return nil }
        return try? z.data(for: e, maxBytes: limit)
    }

    // MARK: - ObjC 类转储（按需 + 缓存）

    private var classDumpCache: [ObjCClassDump]?

    func dumpClasses() -> [ObjCClassDump] {
        if let c = classDumpCache { return c }
        guard !binData.isEmpty else { return [] }
        let dumper = ObjCDumper(data: binData, segments: result.segments, sections: result.allSections)
        let classes = dumper.dump()
        classDumpCache = classes
        return classes
    }

    // MARK: - Swift 元数据（按需 + 缓存）

    private var swiftMetaCache: [SwiftTypeDump]?

    func swiftMeta() -> [SwiftTypeDump] {
        if let c = swiftMetaCache { return c }
        guard !binData.isEmpty else { return [] }
        let dumper = SwiftMetaDumper(data: binData, segments: result.segments, sections: result.allSections)
        let types = dumper.dump()
        swiftMetaCache = types
        return types
    }

    // MARK: - Assets.car 提取

    func assetsCarData() -> Data? {
        guard let z = zip else { return nil }
        for e in z.entries where e.path.lowercased().hasSuffix("assets.car") {
            if let d = try? z.data(for: e, maxBytes: 256 * 1024 * 1024) {
                return d
            }
        }
        return nil
    }

    // MARK: - VA → 字符串（反汇编引用标注）

    private var stringByAddr: [UInt64: String] = [:]

    private func buildStringMap() {
        guard stringByAddr.isEmpty, !binData.isEmpty else { return }
        let parser = MachOParser(data: binData)
        let names: Set<String> = ["__cstring", "__objc_classname", "__objc_methname", "__objc_methtype", "__ustring"]
        for sec in result.allSections where names.contains(sec.name) {
            let d = parser.sectionData(sec, from: binData, limit: 16 * 1024 * 1024)
            let bytes = [UInt8](d)
            var start = 0
            var i = 0
            while i < bytes.count {
                if bytes[i] == 0 {
                    if i > start {
                        let s = String(bytes: bytes[start..<i], encoding: .utf8)
                            ?? String(bytes: bytes[start..<i], encoding: .isoLatin1)
                        if let s = s, !s.isEmpty, s.count < 200 {
                            stringByAddr[sec.addr + UInt64(start)] = s
                        }
                    }
                    start = i + 1
                }
                i += 1
            }
        }
    }

    func stringAt(vm: UInt64) -> String? {
        buildStringMap()
        return stringByAddr[vm]
    }

    // MARK: - 情报分析（完整性/越狱/权限/签名）

    @Published var integrityProgress: (Int, Int) = (0, 0)

    func arm64SliceData() -> Data? {
        // thin 直接返回；fat → 定位 arm64 entry 切片
        let bytes = [UInt8](binData)
        guard bytes.count > 12 else { return nil }
        let magic = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8) | (UInt32(bytes[2]) << 16) | (UInt32(bytes[3]) << 24)
        if magic == 0xfeedfacf { return binData }
        guard magic == 0xcafebabe || magic == 0xbebafeca else { return nil }
        let nfat = Int(bytes[4]) << 24 | Int(bytes[5]) << 16 | Int(bytes[6]) << 8 | Int(bytes[7])
        for i in 0..<min(nfat, 16) {
            let o = 8 + i * 20
            guard o + 20 <= bytes.count else { break }
            let cpu = UInt32(bytes[o]) << 24 | UInt32(bytes[o+1]) << 16 | UInt32(bytes[o+2]) << 8 | UInt32(bytes[o+3])
            if cpu == 0x0100000C {
                let off = Int(bytes[o+8]) << 24 | Int(bytes[o+9]) << 16 | Int(bytes[o+10]) << 8 | Int(bytes[o+11])
                let size = Int(bytes[o+12]) << 24 | Int(bytes[o+13]) << 16 | Int(bytes[o+14]) << 8 | Int(bytes[o+15])
                guard off + size <= binData.count else { return nil }
                return binData.subdata(in: off..<(off + size))
            }
        }
        return nil
    }

    func runIntegrityCheck() async -> [IntegrityItem] {
        guard let z = zip else { return [] }
        return await withCheckedContinuation { cont in
            DispatchQueue.global().async {
                let items = IntegrityCheck.run(entries: z.entries, reader: z) { done, total in
                    Task { @MainActor in
                        self.integrityProgress = (done, total)
                    }
                }
                cont.resume(returning: items)
            }
        }
    }

    func jailbreakScan() -> [JBSignature] {
        JailbreakScan.scan(result.cstrings)
    }

    func privacyProfile() -> [PrivacyPermission] {
        var plistData: Data?
        if let ip = zip?.entry(result.appFolder + "Info.plist") {
            plistData = try? zip?.data(for: ip)
        }
        return PrivacyProfile.analyze(infoPlistData: plistData,
                                      strings: result.cstrings, info: result.info)
    }

    func codeSignature() -> CodeSigInfo {
        guard let slice = arm64SliceData() else {
            var i = CodeSigInfo()
            i.errors.append("无法定位 arm64 slice")
            return i
        }
        return CodeSigParser.parse(slice: [UInt8](slice))
    }

    // MARK: - 专业层 · Hex / VA 映射 / 标注名 / 调用者

    /// VA → 文件偏移（经 segment vmaddr/fileOff 映射）
    func fileOffset(forVA va: UInt64) -> Int? {
        for seg in result.segments {
            if va >= seg.vmaddr, va < seg.vmaddr + seg.fileSize {
                let off = seg.fileOff + (va - seg.vmaddr)
                if off < UInt64(binData.count) { return Int(off) }
            }
        }
        return nil
    }

    /// Hex 查看数据源：VA 起 count 字节
    func hexData(atVA va: UInt64, count: Int) -> Data? {
        guard let off = fileOffset(forVA: va), off < binData.count else { return nil }
        let end = min(off + count, binData.count)
        guard end > off else { return nil }
        return binData.subdata(in: off..<end)
    }

    /// 反汇编定位的函数起始符号（VA → 最近符号名）
    func nearestSymbol(va: UInt64) -> (name: String, addr: UInt64)? {
        var best: (String, UInt64)?
        for s in result.symbolsFull where s.value <= va {
            if let b = best {
                if s.value > b.1 { best = (s.name, s.value) }
            } else {
                best = (s.name, s.value)
            }
        }
        guard let b = best else { return nil }
        let disp = AnnotationStore.shared.displayName(for: b.1, fallback: b.0)
        return (disp, b.1)
    }

    /// 标注感知的符号显示名
    func symbolDisplay(_ s: MachSymbol) -> String {
        AnnotationStore.shared.displayName(for: s.value, fallback: AnnotationStore.shared.displayName(forSym: s.name))
    }

    /// 调用者列表（谁调用了这个地址）
    func callers(of va: UInt64, limit: Int = 200) -> [XrefSite] {
        let sites = callGraph[va] ?? []
        return Array(sites.sorted { $0.fromVA < $1.fromVA }.prefix(limit))
    }

    // MARK: - 导出（Documents/exports/）

    nonisolated static func exportsDir() -> URL {
        let dir = documentsDir().appendingPathComponent("exports", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// 保存导出文件，返回显示名；失败返回 nil
    @discardableResult
    func saveExport(_ data: Data, name: String) -> String? {
        let dir = Self.exportsDir()
        var dest = dir.appendingPathComponent(name)
        if FileManager.default.fileExists(atPath: dest.path) {
            dest = dir.appendingPathComponent("\(Int(Date().timeIntervalSince1970))-\(name)")
        }
        do {
            try data.write(to: dest)
            toast = "已导出到 exports：\(dest.lastPathComponent)"
            return dest.lastPathComponent
        } catch {
            toast = "导出失败：\(error.localizedDescription)"
            return nil
        }
    }

    /// 把选中的资源条目打包 zip 并导出
    @discardableResult
    func exportResourcesZip(_ entries: [ZipEntry], zipName: String) -> Bool {
        var files: [ZIPEntry] = []
        for e in entries {
            if let d = resourceData(for: e, limit: 128 * 1024 * 1024) {
                // 保留包内相对路径（去掉 appFolder 前缀，保持目录结构）
                var rel = e.path
                if rel.hasPrefix(result.appFolder) { rel = String(rel.dropFirst(result.appFolder.count)) }
                files.append(ZIPEntry(path: rel, data: d))
            }
        }
        guard !files.isEmpty, let zipData = ZIPWriter.write(files) else {
            toast = "打包失败（无有效文件）"
            return false
        }
        return saveExport(zipData, name: zipName) != nil
    }
}
