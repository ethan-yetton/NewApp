import SwiftUI
import Darwin

// MARK: - Ports

struct PortEntry: Identifiable, Hashable {
    let id = UUID()
    let process: String
    let pid: Int
    let user: String
    let proto: String
    let address: String
    let port: Int
}

@MainActor
final class PortScanner: ObservableObject {
    @Published var entries: [PortEntry] = []
    @Published var isScanning = false
    @Published var lastError: String?

    init() {
        refresh()
    }

    func refresh() {
        isScanning = true
        lastError = nil
        Task.detached {
            let tcp = Self.runLsof(args: ["-nP", "-iTCP", "-sTCP:LISTEN"])
            let udp = Self.runLsof(args: ["-nP", "-iUDP"])
            let combined = Self.dedupe(tcp + udp).sorted {
                ($0.port, $0.proto, $0.process) < ($1.port, $1.proto, $1.process)
            }
            await MainActor.run {
                self.entries = combined
                self.isScanning = false
            }
        }
    }

    nonisolated static func runLsof(args: [String]) -> [PortEntry] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return []
        }
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return [] }
        return parse(output: output)
    }

    nonisolated static func parse(output: String) -> [PortEntry] {
        var results: [PortEntry] = []
        let lines = output.split(separator: "\n")
        guard lines.count > 1 else { return [] }
        for line in lines.dropFirst() {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard cols.count >= 9 else { continue }
            let command = cols[0]
            guard let pid = Int(cols[1]) else { continue }
            let user = cols[2]
            let proto = cols[7]
            guard proto == "TCP" || proto == "UDP" else { continue }
            var name = cols[8...].joined(separator: " ")
            if let parenIdx = name.firstIndex(of: "(") {
                name = String(name[..<parenIdx]).trimmingCharacters(in: .whitespaces)
            }
            if let arrowRange = name.range(of: "->") {
                name = String(name[..<arrowRange.lowerBound])
            }
            guard let colonIdx = name.lastIndex(of: ":") else { continue }
            let address = String(name[..<colonIdx])
            let portString = String(name[name.index(after: colonIdx)...])
            guard let port = Int(portString) else { continue }
            results.append(PortEntry(
                process: command,
                pid: pid,
                user: user,
                proto: proto,
                address: address,
                port: port
            ))
        }
        return results
    }

    nonisolated static func dedupe(_ entries: [PortEntry]) -> [PortEntry] {
        var seen = Set<String>()
        var out: [PortEntry] = []
        for entry in entries {
            let key = "\(entry.proto)|\(entry.pid)|\(entry.address)|\(entry.port)"
            if seen.insert(key).inserted {
                out.append(entry)
            }
        }
        return out
    }
}

enum ProtoFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case tcp = "TCP"
    case udp = "UDP"
    var id: String { rawValue }
}

// MARK: - Processes

struct ProcessEntry: Identifiable, Hashable {
    let id = UUID()
    let pid: Int
    let user: String
    let cpu: Double
    let mem: Double
    let command: String
    let name: String
}

@MainActor
final class ProcessScanner: ObservableObject {
    @Published var entries: [ProcessEntry] = []
    @Published var isScanning = false
    @Published var lastError: String?

    init() {
        refresh()
    }

    func refresh() {
        isScanning = true
        lastError = nil
        Task.detached {
            let entries = Self.runPs()
            await MainActor.run {
                self.entries = entries
                self.isScanning = false
            }
        }
    }

    nonisolated static func runPs() -> [ProcessEntry] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/ps")
        proc.arguments = ["-Ao", "pid,user,%cpu,%mem,comm"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        do {
            try proc.run()
        } catch {
            return []
        }
        proc.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return [] }
        return parse(output: output)
    }

    nonisolated static func parse(output: String) -> [ProcessEntry] {
        var results: [ProcessEntry] = []
        let lines = output.split(separator: "\n")
        guard lines.count > 1 else { return [] }
        for line in lines.dropFirst() {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard cols.count >= 5 else { continue }
            guard let pid = Int(cols[0]) else { continue }
            let user = cols[1]
            let cpu = Double(cols[2]) ?? 0
            let mem = Double(cols[3]) ?? 0
            let command = cols[4...].joined(separator: " ")
            let name = (command as NSString).lastPathComponent
            results.append(ProcessEntry(
                pid: pid, user: user, cpu: cpu, mem: mem, command: command, name: name
            ))
        }
        return results.sorted { $0.cpu > $1.cpu }
    }
}

// MARK: - System

struct SystemStats {
    var cpuUserPct: Double = 0
    var cpuSystemPct: Double = 0
    var cpuIdlePct: Double = 0
    var cpuNicePct: Double = 0

    var totalMem: UInt64 = 0
    var usedMem: UInt64 = 0
    var wiredMem: UInt64 = 0
    var compressedMem: UInt64 = 0
    var activeMem: UInt64 = 0
    var inactiveMem: UInt64 = 0
    var freeMem: UInt64 = 0

    var diskTotal: UInt64 = 0
    var diskUsed: UInt64 = 0
    var diskFree: UInt64 = 0
    var diskVolumeName: String = "/"

    var cpuUsedPct: Double { 1.0 - cpuIdlePct }

    var memUsedPct: Double {
        guard totalMem > 0 else { return 0 }
        return min(1.0, Double(usedMem) / Double(totalMem))
    }

    var diskUsedPct: Double {
        guard diskTotal > 0 else { return 0 }
        return min(1.0, Double(diskUsed) / Double(diskTotal))
    }
}

@MainActor
final class SystemMonitor: ObservableObject {
    @Published var stats = SystemStats()
    private var lastTicks: (user: UInt32, system: UInt32, idle: UInt32, nice: UInt32)?
    private var timer: Timer?

    init() {
        refresh()
        let t = Timer(timeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    deinit { timer?.invalidate() }

    func refresh() {
        var s = stats
        if let cpu = readCPU() {
            s.cpuUserPct = cpu.user
            s.cpuSystemPct = cpu.system
            s.cpuIdlePct = cpu.idle
            s.cpuNicePct = cpu.nice
        }
        if let mem = readMem() {
            s.totalMem = mem.total
            s.usedMem = mem.used
            s.wiredMem = mem.wired
            s.compressedMem = mem.compressed
            s.activeMem = mem.active
            s.inactiveMem = mem.inactive
            s.freeMem = mem.free
        }
        if let disk = readDisk() {
            s.diskTotal = disk.total
            s.diskUsed = disk.used
            s.diskFree = disk.free
            s.diskVolumeName = disk.name
        }
        stats = s
    }

    private func readDisk() -> (total: UInt64, used: UInt64, free: UInt64, name: String)? {
        let url = URL(fileURLWithPath: "/")
        let keys: Set<URLResourceKey> = [.volumeTotalCapacityKey, .volumeAvailableCapacityKey, .volumeNameKey]
        guard let values = try? url.resourceValues(forKeys: keys),
              let total = values.volumeTotalCapacity,
              let avail = values.volumeAvailableCapacity else { return nil }
        let t = UInt64(total)
        let a = UInt64(avail)
        let used = t > a ? t - a : 0
        return (total: t, used: used, free: a, name: values.volumeName ?? "/")
    }

    private func readCPU() -> (user: Double, system: Double, idle: Double, nice: Double)? {
        var info = host_cpu_load_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { ptr in
                host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, ptr, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }
        let user = info.cpu_ticks.0
        let system = info.cpu_ticks.1
        let idle = info.cpu_ticks.2
        let nice = info.cpu_ticks.3
        defer { lastTicks = (user, system, idle, nice) }
        guard let last = lastTicks else { return nil }
        let dUser = Double(user &- last.user)
        let dSystem = Double(system &- last.system)
        let dIdle = Double(idle &- last.idle)
        let dNice = Double(nice &- last.nice)
        let total = dUser + dSystem + dIdle + dNice
        guard total > 0 else { return nil }
        return (dUser / total, dSystem / total, dIdle / total, dNice / total)
    }

    private func readMem() -> (total: UInt64, used: UInt64, wired: UInt64, compressed: UInt64, active: UInt64, inactive: UInt64, free: UInt64)? {
        var vm = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &vm) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { ptr in
                host_statistics64(mach_host_self(), HOST_VM_INFO64, ptr, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }
        let pageSize = UInt64(vm_kernel_page_size)
        var total: UInt64 = 0
        var sz = MemoryLayout<UInt64>.size
        sysctlbyname("hw.memsize", &total, &sz, nil, 0)
        let active = UInt64(vm.active_count) * pageSize
        let wired = UInt64(vm.wire_count) * pageSize
        let compressed = UInt64(vm.compressor_page_count) * pageSize
        let inactive = UInt64(vm.inactive_count) * pageSize
        let free = UInt64(vm.free_count) * pageSize
        let used = active + wired + compressed
        return (total: total, used: used, wired: wired, compressed: compressed, active: active, inactive: inactive, free: free)
    }
}

private func formatBytes(_ bytes: UInt64) -> String {
    let f = ByteCountFormatter()
    f.allowedUnits = [.useGB, .useMB]
    f.countStyle = .memory
    return f.string(fromByteCount: Int64(bytes))
}

private func formatDiskBytes(_ bytes: UInt64) -> String {
    let f = ByteCountFormatter()
    f.allowedUnits = [.useGB, .useMB, .useTB]
    f.countStyle = .file
    return f.string(fromByteCount: Int64(bytes))
}

// MARK: - System view

struct SystemView: View {
    @EnvironmentObject var monitor: SystemMonitor

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                cpuSection
                memSection
                diskSection
                Spacer(minLength: 0)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var cpuSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("CPU").font(.headline)
            HStack {
                Text("Usage").frame(width: 90, alignment: .leading)
                ProgressView(value: monitor.stats.cpuUsedPct)
                Text(String(format: "%.1f%%", monitor.stats.cpuUsedPct * 100))
                    .font(.system(.body, design: .monospaced))
                    .frame(width: 70, alignment: .trailing)
            }
            HStack(spacing: 20) {
                cpuStat("User", monitor.stats.cpuUserPct)
                cpuStat("System", monitor.stats.cpuSystemPct)
                cpuStat("Nice", monitor.stats.cpuNicePct)
                cpuStat("Idle", monitor.stats.cpuIdlePct)
            }
            .font(.caption)
            .foregroundColor(.secondary)
        }
    }

    private func cpuStat(_ name: String, _ value: Double) -> some View {
        HStack(spacing: 4) {
            Text("\(name):")
            Text(String(format: "%.1f%%", value * 100))
                .font(.system(.caption, design: .monospaced))
        }
    }

    private var memSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Memory").font(.headline)
            HStack {
                Text("Used").frame(width: 90, alignment: .leading)
                ProgressView(value: monitor.stats.memUsedPct)
                Text(String(format: "%.1f%%", monitor.stats.memUsedPct * 100))
                    .font(.system(.body, design: .monospaced))
                    .frame(width: 70, alignment: .trailing)
            }
            VStack(alignment: .leading, spacing: 3) {
                memRow("Total", monitor.stats.totalMem)
                memRow("Used", monitor.stats.usedMem)
                memRow("Wired", monitor.stats.wiredMem)
                memRow("Active", monitor.stats.activeMem)
                memRow("Compressed", monitor.stats.compressedMem)
                memRow("Inactive", monitor.stats.inactiveMem)
                memRow("Free", monitor.stats.freeMem)
            }
            .font(.system(.caption, design: .monospaced))
            .foregroundColor(.secondary)
        }
    }

    private func memRow(_ name: String, _ bytes: UInt64) -> some View {
        HStack {
            Text(name).frame(width: 110, alignment: .leading)
            Text(formatBytes(bytes)).frame(width: 110, alignment: .trailing)
            Spacer()
        }
    }

    private var diskSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Text("Disk").font(.headline)
                Text("(\(monitor.stats.diskVolumeName))")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            HStack {
                Text("Used").frame(width: 90, alignment: .leading)
                ProgressView(value: monitor.stats.diskUsedPct)
                Text(String(format: "%.1f%%", monitor.stats.diskUsedPct * 100))
                    .font(.system(.body, design: .monospaced))
                    .frame(width: 70, alignment: .trailing)
            }
            VStack(alignment: .leading, spacing: 3) {
                diskRow("Total", monitor.stats.diskTotal)
                diskRow("Used", monitor.stats.diskUsed)
                diskRow("Free", monitor.stats.diskFree)
            }
            .font(.system(.caption, design: .monospaced))
            .foregroundColor(.secondary)
        }
    }

    private func diskRow(_ name: String, _ bytes: UInt64) -> some View {
        HStack {
            Text(name).frame(width: 110, alignment: .leading)
            Text(formatDiskBytes(bytes)).frame(width: 110, alignment: .trailing)
            Spacer()
        }
    }
}

// MARK: - Apps

struct AppEntry: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let version: String
    let bundleID: String
    let path: String
    let modified: Date?
}

@MainActor
final class AppScanner: ObservableObject {
    @Published var entries: [AppEntry] = []
    @Published var isScanning = false

    init() { refresh() }

    func refresh() {
        isScanning = true
        Task.detached {
            let entries = Self.scan()
            await MainActor.run {
                self.entries = entries
                self.isScanning = false
            }
        }
    }

    nonisolated static func scan() -> [AppEntry] {
        let home = NSHomeDirectory()
        let roots = [
            "/Applications",
            "/Applications/Utilities",
            "/System/Applications",
            "/System/Applications/Utilities",
            "\(home)/Applications"
        ]
        let fm = FileManager.default
        var results: [AppEntry] = []
        var seen = Set<String>()
        for root in roots {
            guard let items = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for item in items where item.hasSuffix(".app") {
                let path = "\(root)/\(item)"
                guard seen.insert(path).inserted else { continue }
                if let entry = readApp(at: path) {
                    results.append(entry)
                }
            }
        }
        return results.sorted {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    nonisolated static func readApp(at path: String) -> AppEntry? {
        let info = Bundle(path: path)?.infoDictionary ?? [:]
        let fallbackName = (path as NSString).lastPathComponent.replacingOccurrences(of: ".app", with: "")
        let name = (info["CFBundleDisplayName"] as? String)
            ?? (info["CFBundleName"] as? String)
            ?? fallbackName
        let version = (info["CFBundleShortVersionString"] as? String)
            ?? (info["CFBundleVersion"] as? String)
            ?? ""
        let bundleID = (info["CFBundleIdentifier"] as? String) ?? ""
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        let modified = attrs?[.modificationDate] as? Date
        return AppEntry(
            name: name,
            version: version,
            bundleID: bundleID,
            path: path,
            modified: modified
        )
    }
}

// MARK: - Apps view

struct AppsView: View {
    @EnvironmentObject var scanner: AppScanner
    @State private var filter = ""

    var filtered: [AppEntry] {
        guard !filter.isEmpty else { return scanner.entries }
        return scanner.entries.filter {
            $0.name.localizedCaseInsensitiveContains(filter)
                || $0.bundleID.localizedCaseInsensitiveContains(filter)
        }
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        return f
    }()

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Filter by name or bundle ID", text: $filter)
                    .textFieldStyle(.roundedBorder)

                Button(action: { scanner.refresh() }) {
                    if scanner.isScanning {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(scanner.isScanning)
            }
            .padding()

            Table(filtered) {
                TableColumn("Name") { Text($0.name) }
                TableColumn("Version") { Text($0.version) }.width(80)
                TableColumn("Bundle ID") { entry in
                    Text(entry.bundleID)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                TableColumn("Modified") { entry in
                    Text(entry.modified.map { Self.dateFormatter.string(from: $0) } ?? "")
                        .foregroundColor(.secondary)
                }.width(110)
                TableColumn("Path") { entry in
                    Text(entry.path)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }
            .contextMenu(forSelectionType: AppEntry.ID.self) { ids in
                if let id = ids.first, let app = scanner.entries.first(where: { $0.id == id }) {
                    Button("Reveal in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: app.path)])
                    }
                    Button("Open") {
                        NSWorkspace.shared.open(URL(fileURLWithPath: app.path))
                    }
                }
            }

            HStack {
                Text("\(filtered.count) of \(scanner.entries.count) apps")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
        }
    }
}

// MARK: - Ports view

struct PortsView: View {
    @EnvironmentObject var scanner: PortScanner
    @State private var filter = ""
    @State private var protoFilter: ProtoFilter = .all

    var filtered: [PortEntry] {
        scanner.entries.filter { entry in
            let protoOK = protoFilter == .all || entry.proto == protoFilter.rawValue
            let textOK = filter.isEmpty
                || entry.process.localizedCaseInsensitiveContains(filter)
                || String(entry.port).contains(filter)
                || entry.address.localizedCaseInsensitiveContains(filter)
            return protoOK && textOK
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Filter by process, port, or address", text: $filter)
                    .textFieldStyle(.roundedBorder)

                Picker("", selection: $protoFilter) {
                    ForEach(ProtoFilter.allCases) { p in
                        Text(p.rawValue).tag(p)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 180)

                Button(action: { scanner.refresh() }) {
                    if scanner.isScanning {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(scanner.isScanning)
            }
            .padding()

            Table(filtered) {
                TableColumn("Proto") { Text($0.proto) }.width(60)
                TableColumn("Port") { Text(String($0.port)) }.width(70)
                TableColumn("Address") { Text($0.address) }.width(180)
                TableColumn("Process") { Text($0.process) }
                TableColumn("PID") { Text(String($0.pid)) }.width(70)
                TableColumn("User") { Text($0.user) }.width(100)
            }

            HStack {
                Text("\(filtered.count) of \(scanner.entries.count) entries")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                if let err = scanner.lastError {
                    Text(err).font(.caption).foregroundColor(.red)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
        }
    }
}

// MARK: - Processes view

struct ProcessesView: View {
    @EnvironmentObject var scanner: ProcessScanner
    @State private var filter = ""

    var filtered: [ProcessEntry] {
        guard !filter.isEmpty else { return scanner.entries }
        return scanner.entries.filter {
            $0.name.localizedCaseInsensitiveContains(filter)
                || String($0.pid).contains(filter)
                || $0.user.localizedCaseInsensitiveContains(filter)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Filter by name, PID, or user", text: $filter)
                    .textFieldStyle(.roundedBorder)

                Button(action: { scanner.refresh() }) {
                    if scanner.isScanning {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                .disabled(scanner.isScanning)
            }
            .padding()

            Table(filtered) {
                TableColumn("PID") { Text(String($0.pid)) }.width(70)
                TableColumn("CPU %") { Text(String(format: "%.1f", $0.cpu)) }.width(60)
                TableColumn("MEM %") { Text(String(format: "%.1f", $0.mem)) }.width(60)
                TableColumn("User") { Text($0.user) }.width(100)
                TableColumn("Name") { Text($0.name) }
            }

            HStack {
                Text("\(filtered.count) of \(scanner.entries.count) processes")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                if let err = scanner.lastError {
                    Text(err).font(.caption).foregroundColor(.red)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 6)
        }
    }
}

// MARK: - Main window

struct ContentView: View {
    var body: some View {
        TabView {
            PortsView()
                .tabItem { Label("Ports", systemImage: "network") }
            ProcessesView()
                .tabItem { Label("Processes", systemImage: "cpu") }
            SystemView()
                .tabItem { Label("System", systemImage: "gauge") }
            AppsView()
                .tabItem { Label("Apps", systemImage: "app.badge") }
        }
        .padding(.top, 6)
        .frame(minWidth: 760, minHeight: 460)
    }
}

// MARK: - Menu bar popover

struct MenuBarPopover: View {
    enum Section: String, CaseIterable, Identifiable {
        case ports = "Ports"
        case processes = "Processes"
        case system = "System"
        case apps = "Apps"
        var id: String { rawValue }
    }

    @EnvironmentObject var portScanner: PortScanner
    @EnvironmentObject var processScanner: ProcessScanner
    @EnvironmentObject var systemMonitor: SystemMonitor
    @EnvironmentObject var appScanner: AppScanner
    @Environment(\.openWindow) private var openWindow
    @State private var section: Section = .ports
    @State private var protoFilter: ProtoFilter = .all
    @State private var appFilter: String = ""

    var visiblePorts: [PortEntry] {
        protoFilter == .all
            ? portScanner.entries
            : portScanner.entries.filter { $0.proto == protoFilter.rawValue }
    }

    var isScanning: Bool {
        switch section {
        case .ports: return portScanner.isScanning
        case .processes: return processScanner.isScanning
        case .system: return false
        case .apps: return appScanner.isScanning
        }
    }

    func refresh() {
        switch section {
        case .ports: portScanner.refresh()
        case .processes: processScanner.refresh()
        case .system: systemMonitor.refresh()
        case .apps: appScanner.refresh()
        }
    }

    var visibleApps: [AppEntry] {
        guard !appFilter.isEmpty else { return appScanner.entries }
        return appScanner.entries.filter {
            $0.name.localizedCaseInsensitiveContains(appFilter)
                || $0.bundleID.localizedCaseInsensitiveContains(appFilter)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $section) {
                    ForEach(Section.allCases) { s in Text(s.rawValue).tag(s) }
                }
                .pickerStyle(.segmented)

                Button(action: refresh) {
                    if isScanning {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .buttonStyle(.borderless)
                .disabled(isScanning)
            }
            .padding(.horizontal, 12)
            .padding(.top, 10)
            .padding(.bottom, 6)

            if section == .ports {
                Picker("", selection: $protoFilter) {
                    ForEach(ProtoFilter.allCases) { p in
                        Text(p.rawValue).tag(p)
                    }
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 12)
            } else if section == .apps {
                TextField("Filter apps", text: $appFilter)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal, 12)
            }

            Divider().padding(.top, 8)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    switch section {
                    case .ports: portsList
                    case .processes: processesList
                    case .system: systemList
                    case .apps: appsList
                    }
                }
                .padding(.vertical, 4)
            }
            .frame(height: 320)

            Divider()

            HStack {
                Button("Show Window") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                Spacer()
                Button("Quit") {
                    NSApp.terminate(nil)
                }
                .keyboardShortcut("q")
            }
            .padding(10)
        }
        .frame(width: 380)
    }

    @ViewBuilder
    var portsList: some View {
        ForEach(visiblePorts) { entry in
            HStack(spacing: 8) {
                Text(entry.proto)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
                    .frame(width: 32, alignment: .leading)
                Text(String(entry.port))
                    .font(.system(.body, design: .monospaced))
                    .frame(width: 60, alignment: .leading)
                Text(entry.process)
                    .lineLimit(1)
                Spacer()
                Text(String(entry.pid))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 3)
        }
        if visiblePorts.isEmpty {
            Text("No ports found")
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(maxWidth: .infinity)
                .padding()
        }
    }

    @ViewBuilder
    var processesList: some View {
        ForEach(processScanner.entries.prefix(100)) { entry in
            HStack(spacing: 8) {
                Text(String(entry.pid))
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
                    .frame(width: 55, alignment: .leading)
                Text(String(format: "%.1f", entry.cpu))
                    .font(.system(.caption, design: .monospaced))
                    .frame(width: 38, alignment: .trailing)
                Text(entry.name)
                    .lineLimit(1)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 3)
        }
        if processScanner.entries.count > 100 {
            Text("+ \(processScanner.entries.count - 100) more")
                .font(.caption)
                .foregroundColor(.secondary)
                .padding()
        }
    }

    @ViewBuilder
    var systemList: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("CPU").font(.headline)
                    Spacer()
                    Text(String(format: "%.1f%%", systemMonitor.stats.cpuUsedPct * 100))
                        .font(.system(.body, design: .monospaced))
                }
                ProgressView(value: systemMonitor.stats.cpuUsedPct)
                HStack(spacing: 12) {
                    popoverStat("User", systemMonitor.stats.cpuUserPct)
                    popoverStat("Sys", systemMonitor.stats.cpuSystemPct)
                    popoverStat("Idle", systemMonitor.stats.cpuIdlePct)
                }
                .font(.caption)
                .foregroundColor(.secondary)
            }

            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Memory").font(.headline)
                    Spacer()
                    Text(String(format: "%.1f%%", systemMonitor.stats.memUsedPct * 100))
                        .font(.system(.body, design: .monospaced))
                }
                ProgressView(value: systemMonitor.stats.memUsedPct)
                HStack {
                    Text("\(formatBytes(systemMonitor.stats.usedMem)) used")
                    Spacer()
                    Text("of \(formatBytes(systemMonitor.stats.totalMem))")
                }
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    popoverMemRow("Wired", systemMonitor.stats.wiredMem)
                    popoverMemRow("Active", systemMonitor.stats.activeMem)
                    popoverMemRow("Compressed", systemMonitor.stats.compressedMem)
                    popoverMemRow("Inactive", systemMonitor.stats.inactiveMem)
                    popoverMemRow("Free", systemMonitor.stats.freeMem)
                }
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
            }

            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Disk").font(.headline)
                    Text("(\(systemMonitor.stats.diskVolumeName))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                    Text(String(format: "%.1f%%", systemMonitor.stats.diskUsedPct * 100))
                        .font(.system(.body, design: .monospaced))
                }
                ProgressView(value: systemMonitor.stats.diskUsedPct)
                HStack {
                    Text("\(formatDiskBytes(systemMonitor.stats.diskUsed)) used")
                    Spacer()
                    Text("of \(formatDiskBytes(systemMonitor.stats.diskTotal))")
                }
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private func popoverStat(_ name: String, _ value: Double) -> some View {
        HStack(spacing: 3) {
            Text("\(name):")
            Text(String(format: "%.1f%%", value * 100))
                .font(.system(.caption, design: .monospaced))
        }
    }

    private func popoverMemRow(_ name: String, _ bytes: UInt64) -> some View {
        HStack {
            Text(name).frame(width: 90, alignment: .leading)
            Text(formatBytes(bytes))
            Spacer()
        }
    }

    @ViewBuilder
    var appsList: some View {
        ForEach(visibleApps) { app in
            Button {
                NSWorkspace.shared.open(URL(fileURLWithPath: app.path))
            } label: {
                HStack(spacing: 8) {
                    Text(app.name)
                        .lineLimit(1)
                    Spacer()
                    Text(app.version)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                .contentShape(Rectangle())
                .padding(.horizontal, 12)
                .padding(.vertical, 4)
            }
            .buttonStyle(.plain)
        }
        if visibleApps.isEmpty {
            Text(appScanner.isScanning ? "Scanning…" : "No apps found")
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(maxWidth: .infinity)
                .padding()
        }
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct PortsApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var portScanner = PortScanner()
    @StateObject private var processScanner = ProcessScanner()
    @StateObject private var systemMonitor = SystemMonitor()
    @StateObject private var appScanner = AppScanner()

    var body: some Scene {
        WindowGroup("NewApp", id: "main") {
            ContentView()
                .environmentObject(portScanner)
                .environmentObject(processScanner)
                .environmentObject(systemMonitor)
                .environmentObject(appScanner)
        }
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("Scan") {
                Button("Refresh") {
                    portScanner.refresh()
                    processScanner.refresh()
                }
                .keyboardShortcut("r")
            }
        }

        MenuBarExtra("NewApp", systemImage: "network") {
            MenuBarPopover()
                .environmentObject(portScanner)
                .environmentObject(processScanner)
                .environmentObject(systemMonitor)
                .environmentObject(appScanner)
        }
        .menuBarExtraStyle(.window)
    }
}
