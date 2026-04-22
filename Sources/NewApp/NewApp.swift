import SwiftUI

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

struct ContentView: View {
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
        .frame(minWidth: 760, minHeight: 420)
    }
}

struct MenuBarPopover: View {
    @EnvironmentObject var scanner: PortScanner
    @Environment(\.openWindow) private var openWindow
    @State private var protoFilter: ProtoFilter = .all

    var visible: [PortEntry] {
        protoFilter == .all
            ? scanner.entries
            : scanner.entries.filter { $0.proto == protoFilter.rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Open Ports").font(.headline)
                Spacer()
                Text("\(visible.count)")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Button(action: { scanner.refresh() }) {
                    if scanner.isScanning {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .buttonStyle(.borderless)
                .disabled(scanner.isScanning)
            }
            .padding(.horizontal, 12)
            .padding(.top, 10)
            .padding(.bottom, 6)

            Picker("", selection: $protoFilter) {
                ForEach(ProtoFilter.allCases) { p in
                    Text(p.rawValue).tag(p)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 12)

            Divider().padding(.top, 8)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(visible) { entry in
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
                    if visible.isEmpty {
                        Text("No ports found")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .frame(maxWidth: .infinity)
                            .padding()
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
        .frame(width: 360)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct PortsApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var scanner = PortScanner()

    var body: some Scene {
        WindowGroup("Open Ports", id: "main") {
            ContentView().environmentObject(scanner)
        }
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("Ports") {
                Button("Refresh") { scanner.refresh() }
                    .keyboardShortcut("r")
            }
        }

        MenuBarExtra("Open Ports", systemImage: "network") {
            MenuBarPopover().environmentObject(scanner)
        }
        .menuBarExtraStyle(.window)
    }
}
