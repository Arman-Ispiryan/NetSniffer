namespace NetSniffer.Models;

public enum RiskLevel
{
    Safe,
    Low,
    Medium,
    High,
    Suspicious,
    Unknown
}

public enum ConnectionState
{
    Established,
    Listening,
    TimeWait,
    CloseWait,
    SynSent,
    SynReceived,
    Closed,
    Unknown
}

public class NetworkConnection
{
    public string ProcessName { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Unknown;
    public string ProcessPath { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string RemoteLocation { get; set; } = string.Empty;

    public string LocalEndpoint => LocalPort > 0
        ? $"{LocalAddress}:{LocalPort}"
        : LocalAddress;

    public string RemoteEndpoint => RemotePort > 0
        ? $"{RemoteAddress}:{RemotePort}"
        : RemoteAddress;
}
