import SwiftUI

// MARK: - 反汇编页：函数列表 → ARM64 反汇编流（带符号标注 + 点击跳转 + 字符串引用）

struct DisasmTab: View {
    @ObservedObject var engine: AnalysisEngine

    var body: some View {
        NavigationStack {
            Group {
                if engine.phase != .done {
                    placeholder
                } else if engine.funcSymbols.isEmpty {
                    emptyState
                } else {
                    FunctionListView(engine: engine)
                }
            }
            .navigationTitle("ARM64 反汇编")
            .navigationBarTitleDisplayMode(.inline)
            .background(Color(.systemGroupedBackground))
            // 反汇编内跳转（bl/b 目标）：任意 __text 地址
            .navigationDestination(for: UInt64.self) { addr in
                DisasmView(engine: engine,
                           symbol: MachSymbol(id: Int(truncatingIfNeeded: addr),
                                              name: String(format: "sub_%llX", addr),
                                              value: addr, kind: "func"))
            }
        }
    }

    private var placeholder: some View {
        VStack(spacing: 12) {
            Image(systemName: "waveform.path")
                .font(.system(size: 40))
                .foregroundStyle(.blue.gradient)
            Text("导入 IPA 后可反汇编主二进制")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "questionmark.circle")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("该二进制没有可用的函数符号表")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text("可能已被 strip（剥离符号），只能看字符串与结构")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - 函数列表

struct FunctionListView: View {
    @ObservedObject var engine: AnalysisEngine
    @State private var query = ""
    @State private var displayFuncs: [MachSymbol] = []

    private func recompute() async {
        let q = query
        try? await Task.sleep(nanoseconds: 220_000_000)
        guard !Task.isCancelled, q == query else { return }
        if q.isEmpty { displayFuncs = engine.funcSymbols; return }
        let all = engine.funcSymbols
        let q2 = q.lowercased()
        displayFuncs = await Task.detached(priority: .userInitiated) {
            all.filter { $0.name.lowercased().contains(q2) }
        }.value
    }

    var body: some View {
        List(displayFuncs) { f in
            NavigationLink {
                DisasmView(engine: engine, symbol: f)
            } label: {
                VStack(alignment: .leading, spacing: 3) {
                    Text(engine.symbolDisplay(f))
                        .font(.footnote.weight(.medium))
                        .lineLimit(1)
                    HStack(spacing: 8) {
                        Text(String(format: "0x%llX", f.value))
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                        let callers = engine.callGraph[f.value]?.count ?? 0
                        if callers > 0 {
                            Text("\(callers) 个调用点")
                                .font(.caption2)
                                .foregroundStyle(.blue)
                        }
                        if AnnotationStore.shared.hasAnnotation(for: f.value) {
                            Image(systemName: "pin.fill")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }
            .swipeActions(edge: .trailing) {
                Button {
                    annotateTarget = f
                    showAnnotate = true
                } label: {
                    Label("标注", systemImage: "pin")
                }
                .tint(.orange)
            }
        }
        .listStyle(.insetGrouped)
        .searchable(text: $query, prompt: "搜函数名 / Swift 符号")
        .task(id: query) { await recompute() }
        .overlay {
            if displayFuncs.isEmpty {
                Text("没有匹配的函数")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .sheet(isPresented: $showAnnotate) {
            if let f = annotateTarget {
                AnnotationSheet(targetVA: f.value,
                                fallbackName: f.name)
            }
        }
    }

    @State private var annotateTarget: MachSymbol?
    @State private var showAnnotate = false
}

// MARK: - 单个函数的反汇编视图

struct DisasmView: View {
    @ObservedObject var engine: AnalysisEngine
    let symbol: MachSymbol
    @State private var maxInstructions = 300
    @State private var lines: [DisasmLine] = []
    @State private var showPseudo = false

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                if showPseudo {
                    pseudoView
                } else {
                    ForEach(lines) { l in
                        rowView(l)
                    }
                    if lines.count >= maxInstructions {
                        Button {
                            maxInstructions += 400
                            reload()
                        } label: {
                            Label("加载更多指令", systemImage: "arrow.down.circle")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .padding(.top, 10)
                    }
                }
            }
            .padding(.vertical, 8)
        }
        .background(Color(.systemBackground))
        .navigationTitle(String(symbol.name.prefix(24)))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showPseudo.toggle()
                } label: {
                    Image(systemName: showPseudo ? "number.square" : "text.justify.left")
                }
            }
            if showPseudo {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        exportPseudo()
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                }
            }
            ToolbarItemGroup(placement: .bottomBar) {
                Button {
                    showXref = true
                } label: {
                    Label("调用者", systemImage: "arrow.triangle.branch")
                }
                let n = engine.callGraph[symbol.value]?.count ?? 0
                Text("\(n) 个调用点")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    showAnnotate = true
                } label: {
                    Label("标注", systemImage: "pin")
                }
            }
        }
        .sheet(isPresented: $showXref) {
            XrefSheet(engine: engine, targetVA: symbol.value)
        }
        .sheet(isPresented: $showAnnotate) {
            AnnotationSheet(targetVA: symbol.value, fallbackName: symbol.name)
                .onDisappear { reload() }
        }
        .onAppear { reload() }
    }

    @State private var showXref = false
    @State private var showAnnotate = false

    private var pseudoView: some View {
        let r = Pseudocoder.generate(lines, engine: engine)
        return VStack(alignment: .leading, spacing: 2) {
            Text("// 伪代码近似（\(r.code.count - 2) 行，\(r.notes) 条未翻译）")
                .font(.caption2)
                .foregroundStyle(.tertiary)
            ForEach(Array(r.code.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(12)
    }

    private func exportPseudo() {
        let r = Pseudocoder.generate(lines, engine: engine)
        engine.saveExport(Data(r.code.joined(separator: "\n").utf8),
                          name: "pseudo_\(symbol.name.replacingOccurrences(of: "/", with: "_")).c")
    }

    // 可跳转的指令（bl/b/条件分支）→ NavigationLink；其他行纯展示
    @ViewBuilder
    private func rowView(_ l: DisasmLine) -> some View {
        let target = jumpTarget(l)
        let content = rowContent(l)
        if let t = target {
            NavigationLink(value: t) { content }
                .buttonStyle(.plain)
        } else {
            content
        }
    }

    private func rowContent(_ l: DisasmLine) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .top, spacing: 8) {
                Text(String(format: "%08llX", l.addr))
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
                    .frame(width: 74, alignment: .leading)
                Text(l.text)
                    .font(.caption.monospaced().weight(.medium))
                    .textSelection(.enabled)
                Spacer(minLength: 0)
                if jumpTarget(l) != nil {
                    Image(systemName: "arrow.turn.down.right")
                        .font(.caption2)
                        .foregroundStyle(.blue)
                }
            }
            if !l.note.isEmpty {
                Text(l.note)
                    .font(.caption2.monospaced())
                    .foregroundStyle(l.note.contains("\"") ? Color.orange : Color.green)
                    .padding(.leading, 82)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .background(l.note.contains("→") ? Color.blue.opacity(0.04) : Color.clear)
    }

    // 解析行文本里的跳转目标（仅控制流类指令）
    private func jumpTarget(_ l: DisasmLine) -> UInt64? {
        let prefixes = ["bl ", "b ", "b.", "cbz ", "cbnz ", "tbz ", "tbnz "]
        guard prefixes.contains(where: { l.text.hasPrefix($0) }) else { return nil }
        guard let r = l.text.range(of: "0x[0-9a-fA-F]+", options: .regularExpression) else { return nil }
        return UInt64(l.text[r].dropFirst(2), radix: 16)
    }

    private func reload() {
        lines = engine.disassembleFunction(at: symbol.value, maxInstructions: maxInstructions)
    }
}
