import Foundation

// MARK: - 完整性校验：ZIP 每条目 CRC32 实算 vs 目录登记值

struct IntegrityItem: Identifiable, Hashable {
    let id: Int
    let path: String
    let expected: UInt32
    let actual: UInt32
    var ok: Bool { expected == actual }
}

enum IntegrityCheck {
    static func run(entries: [ZipEntry], reader: ZipReader,
                    progress: @escaping (Int, Int) -> Void) -> [IntegrityItem] {
        var out: [IntegrityItem] = []
        let files = entries.filter { !$0.isDirectory && $0.size > 0 }
        for (i, e) in files.enumerated() {
            if let d = try? reader.data(for: e, maxBytes: 256 * 1024 * 1024) {
                let actual = ZIPWriter.crc32(d)
                out.append(IntegrityItem(id: e.id, path: e.path, expected: e.crc, actual: actual))
            }
            progress(i + 1, files.count)
        }
        return out
    }
}

// MARK: - 越狱 / 风控特征扫描

struct JBSignature: Identifiable, Hashable {
    let id: Int
    let category: String     // 越狱检测 / Hook框架 / 调试风控 / 模拟器
    let keyword: String
    let sample: String       // 命中的原始字符串
}

enum JailbreakScan {

    static let rules: [(String, [String])] = [
        ("越狱检测", ["Cydia", "cydia", "substrate", "Substrate", "MobileSubstrate",
                     "/Applications/Cydia.app", "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
                     "/private/var/lib/apt", "/var/lib/cydia", "jailbreak", "Jailbreak",
                     "jailbroken", "isJailbroken", "cydia://", "AppSync", "CheckRa1n",
                     "unc0ver", "Taurine", "palera1n", "TrollStore", "SockPuppet"]),
        ("Hook框架", ["Frida", "frida", "FRIDA", "frida-gadget", "FridaGadget",
                     "cynject", "libcycript", "Cycript", "libhooker", "ellekit",
                     "TweakInject", "/Library/MobileSubstrate/DynamicLibraries",
                     "SSLKillSwitch", "ssl-kill-switch", "libsubstitute", " objection"]),
        ("调试风控", ["ptrace", "PT_DENY_ATTACH", "sysctl", "anti-debug", "AntiDebug",
                     "antiDebug", "IsDebugged", "DebuggerPresent", "sysctl_kern",
                     "emulator", "Emulator", "isSimulator", "proxy", "Proxy", "VPN"]),
        ("模拟器检测", ["i386", "x86_64", "Simulator", "simulator"])
    ]

    static func scan(_ strings: [String]) -> [JBSignature] {
        var out: [JBSignature] = []
        var id = 0
        for (cat, keywords) in rules {
            for kw in keywords {
                // 找到包含关键字的原始字符串样本（最多 2 条）
                var shown = 0
                for s in strings where s.count < 500 {
                    if s.contains(kw) {
                        out.append(JBSignature(id: id, category: cat, keyword: kw, sample: s))
                        id += 1
                        shown += 1
                        if shown >= 2 { break }
                    }
                }
            }
        }
        return out
    }

    static func summaryText(_ hits: [JBSignature]) -> String {
        let byCat = Dictionary(grouping: hits, by: { $0.category })
        var lines: [String] = []
        if let jb = byCat["越狱检测"], !jb.isEmpty {
            lines.append("· 包含越狱检测逻辑（\(Set(jb.map { $0.keyword })).count 种特征）——App 会主动检测越狱环境")
        }
        if let hook = byCat["Hook框架"], !hook.isEmpty {
            lines.append("· 含 Hook 框架特征（\(Set(hook.map { $0.keyword })).count 种）——可能内嵌反调试/反 Hook 或为调试版")
        }
        if let dbg = byCat["调试风控"], !dbg.isEmpty {
            lines.append("· 含调试/风控对抗特征 \(Set(dbg.map { $0.keyword })).count 种")
        }
        if lines.isEmpty {
            lines.append("· 未发现明显越狱/Hook/风控特征")
        }
        return lines.joined(separator: "\n")
    }
}

// MARK: - 隐私权限画像

struct PrivacyPermission: Identifiable, Hashable {
    let id: Int
    let name: String            // 中文能力名
    let plistKey: String
    let usageText: String       // App 自己填的用途描述
    let codeEvidence: String    // 代码符号证据
}

enum PrivacyProfile {

    static let plistKeys: [(String, String)] = [
        ("NSCameraUsageDescription", "相机"),
        ("NSMicrophoneUsageDescription", "麦克风"),
        ("NSPhotoLibraryUsageDescription", "相册读取"),
        ("NSPhotoLibraryAddUsageDescription", "相册写入"),
        ("NSLocationWhenInUseUsageDescription", "前台定位"),
        ("NSLocationAlwaysAndWhenInUseUsageDescription", "持续定位"),
        ("NSLocationAlwaysUsageDescription", "后台定位"),
        ("NSMotionUsageDescription", "运动与健身"),
        ("NSContactsUsageDescription", "通讯录"),
        ("NSBluetoothAlwaysUsageDescription", "蓝牙"),
        ("NSBluetoothPeripheralUsageDescription", "蓝牙外设"),
        ("NSHealthShareUsageDescription", "健康读取"),
        ("NSHealthUpdateUsageDescription", "健康写入"),
        ("NSFaceIDUsageDescription", "Face ID"),
        ("NSUserTrackingUsageDescription", "广告追踪 ATT"),
        ("NSLocalNetworkUsageDescription", "本地网络"),
        ("NSCalendarsUsageDescription", "日历"),
        ("NSRemindersUsageDescription", "提醒事项"),
        ("NSSpeechRecognitionUsageDescription", "语音识别"),
        ("NSAppleMusicUsageDescription", "媒体资料库"),
        ("NSMediaLibraryUsageDescription", "媒体库"),
        ("NSHomeKitUsageDescription", "HomeKit"),
        ("NSDesktopFolderUsageDescription", "桌面文件夹"),
        ("NSDocumentsFolderUsageDescription", "文档文件夹"),
        ("NSDownloadsFolderUsageDescription", "下载文件夹"),
        ("NSNetworkVolumesUsageDescription", "网络卷"),
        ("NSFileProviderPresenceUsageDescription", "文件提供方")
    ]

    static let codeSymbols: [(String, String)] = [
        ("AVCaptureDevice", "相机硬件"),
        ("AVAudioRecorder", "麦克风录音"),
        ("CLLocationManager", "定位服务"),
        ("CMMotionManager", "运动传感器"),
        ("CMPedometer", "计步器"),
        ("CBCentralManager", "蓝牙低功耗"),
        ("PHPhotoLibrary", "照片库"),
        ("CNContactStore", "通讯录"),
        ("HKHealthStore", "健康数据"),
        ("LAContext", "生物识别(Face/Touch ID)"),
        ("ATTrackingManager", "广告追踪"),
        ("SFSpeechRecognizer", "语音识别"),
        ("EKEventStore", "日历/提醒"),
        ("NFCNDEFReaderSession", "NFC")
    ]

    static func analyze(infoPlistData: Data?, strings: [String], info: AppInfo) -> [PrivacyPermission] {
        var out: [PrivacyPermission] = []
        var id = 0

        // 1. Info.plist 键
        var plistDict: [String: Any] = [:]
        if let d = infoPlistData, let obj = try? PropertyListSerialization.propertyList(from: d, options: [], format: nil),
           let dict = obj as? [String: Any] {
            plistDict = dict
        }

        for (key, name) in plistKeys {
            let usage = (plistDict[key] as? String) ?? ""
            // 代码证据：能力对应符号是否出现在字符串/符号里
            var evidence = ""
            for (sym, cap) in codeSymbols where cap == name || related(cap, name) {
                if strings.contains(where: { $0.contains(sym) }) {
                    evidence = sym
                    break
                }
            }
            if !usage.isEmpty || !evidence.isEmpty {
                out.append(PrivacyPermission(id: id, name: name, plistKey: key,
                                             usageText: usage, codeEvidence: evidence))
                id += 1
            }
        }
        return out
    }

    private static func related(_ cap: String, _ name: String) -> Bool {
        // 宽松关联：定位/蓝牙等同族
        let pairs: [(String, String)] = [
            ("定位服务", "前台定位"), ("定位服务", "持续定位"), ("定位服务", "后台定位"),
            ("照片库", "相册读取"), ("照片库", "相册写入"),
            ("麦克风录音", "麦克风"), ("生物识别(Face/Touch ID)", "Face ID")
        ]
        return pairs.contains { $0.0 == cap && $0.1 == name }
    }
}

// MARK: - 代码签名深度解析（LC_CODE_SIGNATURE → SuperBlob）

struct CodeSigInfo {
    var identifier: String = ""
    var teamID: String = ""
    var version: String = ""           // CodeDirectory 版本
    var flagsText: String = ""
    var codeSlots: Int = 0             // 哈希页数
    var hashSize: Int = 0              // 20=SHA1 32=SHA256
    var specialSlots: Int = 0
    var entitlementsXML: String = ""   // 原始 entitlements
    var entitlementsKV: [(String, String)] = []
    var hasCMS: Bool = false
    var errors: [String] = []
}

enum CodeSigParser {

    // slice: arm64 thin slice 的完整字节
    static func parse(slice: [UInt8]) -> CodeSigInfo {
        var info = CodeSigInfo()
        func u32(_ o: Int) -> UInt32 {
            guard o >= 0, o + 4 <= slice.count else { return 0 }
            return UInt32(slice[o]) | (UInt32(slice[o+1]) << 8) | (UInt32(slice[o+2]) << 16) | (UInt32(slice[o+3]) << 24)
        }
        func cstr(_ o: Int, max: Int = 256) -> String {
            guard o >= 0, o < slice.count else { return "" }
            var e = o
            let end = min(slice.count, o + max)
            while e < end, slice[e] != 0 { e += 1 }
            return String(bytes: slice[o..<e], encoding: .utf8) ?? ""
        }

        guard slice.count > 64 else { return info }
        let magic = u32(0)
        guard magic == 0xfeedfacf else {
            info.errors.append("非 thin Mach-O")
            return info
        }
        let ncmds = Int(u32(16))
        var p = 32
        var sigOff = 0
        var sigSize = 0
        for _ in 0..<min(ncmds, 512) {
            let cmd = u32(p)
            let cmdsize = Int(u32(p + 4))
            guard cmdsize >= 8, p + cmdsize <= slice.count else { break }
            if cmd == 0x1d {   // LC_CODE_SIGNATURE
                sigOff = Int(u32(p + 8))
                sigSize = Int(u32(p + 12))
                break
            }
            p += cmdsize
        }
        guard sigOff > 0, sigOff + 12 <= slice.count else {
            info.errors.append("未找到 LC_CODE_SIGNATURE（可能未签名或已脱壳）")
            return info
        }

        // 2. SuperBlob: magic 0xfade0cc0, length, count, index[type(4) offset(4)]*
        guard u32(sigOff) == 0xfade0cc0 else {
            info.errors.append("签名 SuperBlob 魔数异常")
            return info
        }
        let blobCount = Int(u32(sigOff + 8))
        for i in 0..<min(blobCount, 16) {
            let idxBase = sigOff + 12 + i * 8
            let type = u32(idxBase)
            let blobOff = sigOff + Int(u32(idxBase + 4))
            switch type {
            case 0:  // CodeDirectory 0xfade0cde
                guard u32(blobOff) == 0xfade0cde else { continue }
                let version = u32(blobOff + 8)
                info.version = String(format: "0x%08X", version)
                let hashOffset = Int(u32(blobOff + 16))
                let identOffset = Int(u32(blobOff + 20))
                let nSpecial = Int(u32(blobOff + 24))
                let nCode = Int(u32(blobOff + 28))
                let hashSize = Int(slice[blobOff + 37])
                info.identifier = identOffset > 0 ? cstr(blobOff + identOffset) : ""
                info.codeSlots = nCode
                info.hashSize = hashSize
                info.specialSlots = nSpecial
                _ = hashOffset
                if version >= 0x20100 {
                    let teamOffset = Int(u32(blobOff + 56))
                    if teamOffset > 0 { info.teamID = cstr(blobOff + teamOffset) }
                }
                info.flagsText = String(format: "0x%08X", u32(blobOff + 12))
            case 2:  // entitlements 0xfade7171
                guard u32(blobOff) == 0xfade7171 else { continue }
                let plistData = Data(slice[(blobOff + 8)..<min(slice.count, blobOff + sigSize)])
                if let obj = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil),
                   let dict = obj as? [String: Any] {
                    if let pretty = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0),
                       let xml = String(data: pretty, encoding: .utf8) {
                        info.entitlementsXML = xml
                    }
                    for (k, v) in dict.sorted(by: { $0.key < $1.key }) {
                        info.entitlementsKV.append((k, "\(v)"))
                    }
                }
            case 0x10000:  // CMS 签名
                info.hasCMS = u32(blobOff) == 0xfade0b17
            default:
                break
            }
        }
        return info
    }
}
