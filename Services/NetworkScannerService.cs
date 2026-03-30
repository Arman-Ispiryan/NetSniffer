using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using NetSniffer.Models;

namespace NetSniffer.Services;

public class NetworkScannerService
{
    // Well-known safe processes
    private static readonly HashSet<string> SafeProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "lsass", "services", "wininit", "winlogon", "csrss",
        "system", "smss", "msmpeng", "searchindexer", "spoolsv",
        "chrome", "firefox", "msedge", "opera", "brave",
        "onedrive", "dropbox", "teams", "slack", "discord",
        "outlook", "thunderbird", "skype", "zoom", "msteams"
    };

    // Well-known suspicious ports
    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999,
        12345, 54321, 1234, 4321
    };

    // Known safe remote ports
    private static readonly HashSet<int> SafePorts = new()
    {
        80, 443, 8080, 8443, 53, 123, 25, 587, 993, 995, 143, 110
    };

    public List<NetworkConnection> ScanConnections()
    {
        var connections = new List<NetworkConnection>();

        try
        {
            // Use netstat to get all connections including process info
            var netstatOutput = RunNetstat();
            connections = ParseNetstatOutput(netstatOutput);

            // Enrich with process info
            foreach (var conn in connections)
            {
                EnrichWithProcessInfo(conn);
                AssessRisk(conn);
            }
        }
        catch
        {
            // If netstat fails, try using .NET's NetworkInformation
            connections = GetFromDotNetApi();
        }

        return connections;
    }

    private string RunNetstat()
    {
        var psi = new ProcessStartInfo("netstat", "-ano")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        var output = proc?.StandardOutput.ReadToEnd() ?? string.Empty;
        proc?.WaitForExit();
        return output;
    }

    private List<NetworkConnection> ParseNetstatOutput(string output)
    {
        var connections = new List<NetworkConnection>();
        var lines = output.Split('\n');

        // Regex: Protocol  LocalAddress  RemoteAddress  State  PID
        var regex = new Regex(
            @"^\s*(TCP|UDP)\s+([\d\.\[\]:]+):(\d+)\s+([\d\.\[\]:]+|\*):(\d+|\*)\s*([A-Z_]+)?\s+(\d+)",
            RegexOptions.IgnoreCase);

        foreach (var line in lines)
        {
            var match = regex.Match(line);
            if (!match.Success) continue;

            var protocol = match.Groups[1].Value.ToUpper();
            var localAddr = match.Groups[2].Value;
            var localPort = int.TryParse(match.Groups[3].Value, out var lp) ? lp : 0;
            var remoteAddr = match.Groups[4].Value;
            var remotePortStr = match.Groups[5].Value;
            var state = match.Groups[6].Value;
            var pid = int.TryParse(match.Groups[7].Value, out var p) ? p : 0;

            // Normalise state
            if (protocol == "UDP") state = "Listening";
            state = NormaliseState(state);

            var remotePort = remotePortStr == "*" ? 0 : (int.TryParse(remotePortStr, out var rp) ? rp : 0);

            connections.Add(new NetworkConnection
            {
                Protocol = protocol,
                LocalAddress = NormaliseAddress(localAddr),
                LocalPort = localPort,
                RemoteAddress = NormaliseAddress(remoteAddr),
                RemotePort = remotePort,
                State = state,
                Pid = pid
            });
        }

        return connections;
    }

    private List<NetworkConnection> GetFromDotNetApi()
    {
        var connections = new List<NetworkConnection>();
        var props = IPGlobalProperties.GetIPGlobalProperties();

        foreach (var tcp in props.GetActiveTcpConnections())
        {
            connections.Add(new NetworkConnection
            {
                Protocol = "TCP",
                LocalAddress = tcp.LocalEndPoint.Address.ToString(),
                LocalPort = tcp.LocalEndPoint.Port,
                RemoteAddress = tcp.RemoteEndPoint.Address.ToString(),
                RemotePort = tcp.RemoteEndPoint.Port,
                State = tcp.State.ToString()
            });
        }

        foreach (var udp in props.GetActiveUdpListeners())
        {
            connections.Add(new NetworkConnection
            {
                Protocol = "UDP",
                LocalAddress = udp.Address.ToString(),
                LocalPort = udp.Port,
                RemoteAddress = "*",
                RemotePort = 0,
                State = "Listening"
            });
        }

        foreach (var tcp in props.GetActiveTcpListeners())
        {
            connections.Add(new NetworkConnection
            {
                Protocol = "TCP",
                LocalAddress = tcp.Address.ToString(),
                LocalPort = tcp.Port,
                RemoteAddress = "0.0.0.0",
                RemotePort = 0,
                State = "Listening"
            });
        }

        return connections;
    }

    private void EnrichWithProcessInfo(NetworkConnection conn)
    {
        if (conn.Pid <= 0) return;

        try
        {
            var proc = Process.GetProcessById(conn.Pid);
            conn.ProcessName = proc.ProcessName;

            try
            {
                conn.ProcessPath = proc.MainModule?.FileName ?? string.Empty;
                conn.Description = FileVersionInfo.GetVersionInfo(conn.ProcessPath).FileDescription ?? string.Empty;
            }
            catch { /* elevated access needed */ }
        }
        catch
        {
            conn.ProcessName = $"PID {conn.Pid}";
        }

        if (string.IsNullOrEmpty(conn.ProcessName))
            conn.ProcessName = "Unknown";

        // Guess location for well-known remote ports
        conn.RemoteLocation = GuessLocation(conn.RemoteAddress, conn.RemotePort);
    }

    private void AssessRisk(NetworkConnection conn)
    {
        // Safe: loopback or no remote
        if (conn.RemoteAddress is "127.0.0.1" or "::1" or "0.0.0.0" or "*" or "")
        {
            conn.RiskLevel = RiskLevel.Safe;
            return;
        }

        // High: known suspicious ports
        if (SuspiciousPorts.Contains(conn.RemotePort) || SuspiciousPorts.Contains(conn.LocalPort))
        {
            conn.RiskLevel = RiskLevel.Suspicious;
            return;
        }

        // Safe: known process on safe port
        if (SafeProcesses.Contains(conn.ProcessName) && SafePorts.Contains(conn.RemotePort))
        {
            conn.RiskLevel = RiskLevel.Safe;
            return;
        }

        // Safe ports
        if (SafePorts.Contains(conn.RemotePort))
        {
            conn.RiskLevel = RiskLevel.Low;
            return;
        }

        // Unknown process
        if (string.IsNullOrEmpty(conn.ProcessName) || conn.ProcessName.StartsWith("PID "))
        {
            conn.RiskLevel = RiskLevel.High;
            return;
        }

        // Listening on non-standard high ports
        if (conn.State == "Listening" && conn.LocalPort > 1024 && !SafePorts.Contains(conn.LocalPort))
        {
            conn.RiskLevel = RiskLevel.Medium;
            return;
        }

        conn.RiskLevel = RiskLevel.Unknown;
    }

    private static string NormaliseState(string state) => state.Trim().ToUpper() switch
    {
        "ESTABLISHED" => "Established",
        "LISTENING" or "LISTEN" => "Listening",
        "TIME_WAIT" => "Time Wait",
        "CLOSE_WAIT" => "Close Wait",
        "SYN_SENT" => "SYN Sent",
        "SYN_RECEIVED" or "SYN_RECV" => "SYN Recv",
        "CLOSED" or "CLOSE" => "Closed",
        _ => string.IsNullOrWhiteSpace(state) ? "Unknown" : state
    };

    private static string NormaliseAddress(string addr)
    {
        if (addr == "0.0.0.0" || addr == "[::]") return "0.0.0.0";
        if (addr == "127.0.0.1" || addr == "[::1]") return "127.0.0.1";
        if (addr.StartsWith("[")) addr = addr.Trim('[', ']');
        return addr;
    }

    private static string GuessLocation(string ip, int port)
    {
        if (ip is "0.0.0.0" or "127.0.0.1" or "*" or "") return "Local";
        if (ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172.")) return "LAN";
        return port switch
        {
            443 or 80 => "Internet (Web)",
            53 => "DNS Server",
            123 => "NTP Server",
            _ => "Internet"
        };
    }
}
