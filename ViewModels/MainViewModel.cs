using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using NetSniffer.Models;
using NetSniffer.Services;

namespace NetSniffer.ViewModels;

public class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

public class MainViewModel : INotifyPropertyChanged
{
    private readonly NetworkScannerService _scanner = new();
    private List<NetworkConnection> _allConnections = new();
    private ObservableCollection<NetworkConnection> _filteredConnections = new();
    private NetworkConnection? _selectedConnection;
    private string _searchText = string.Empty;
    private string _activeFilter = "All";
    private string _statusText = "Ready — click Refresh to scan";
    private bool _showingSuspicious;

    public ObservableCollection<NetworkConnection> FilteredConnections
    {
        get => _filteredConnections;
        set { _filteredConnections = value; OnPropertyChanged(); }
    }

    public NetworkConnection? SelectedConnection
    {
        get => _selectedConnection;
        set { _selectedConnection = value; OnPropertyChanged(); }
    }

    public string SearchText
    {
        get => _searchText;
        set { _searchText = value; OnPropertyChanged(); ApplyFilters(); }
    }

    public string StatusText
    {
        get => _statusText;
        set { _statusText = value; OnPropertyChanged(); }
    }

    public int TotalCount => _allConnections.Count;
    public int EstablishedCount => _allConnections.Count(c => c.State == "Established");
    public int ListeningCount => _allConnections.Count(c => c.State == "Listening");
    public int SuspiciousCount => _allConnections.Count(c =>
        c.RiskLevel is RiskLevel.Suspicious or RiskLevel.High);

    public ICommand ScanCommand { get; }
    public ICommand FilterCommand { get; }
    public ICommand ShowSuspiciousCommand { get; }
    public ICommand TerminateCommand { get; }
    public ICommand OpenLocationCommand { get; }
    public ICommand CopyAddressCommand { get; }

    public MainViewModel()
    {
        ScanCommand = new RelayCommand(_ => Scan());
        FilterCommand = new RelayCommand(p => SetFilter(p as string ?? "All"));
        ShowSuspiciousCommand = new RelayCommand(_ => ToggleSuspicious());
        TerminateCommand = new RelayCommand(_ => TerminateProcess(),
            _ => SelectedConnection != null);
        OpenLocationCommand = new RelayCommand(_ => OpenLocation(),
            _ => SelectedConnection != null);
        CopyAddressCommand = new RelayCommand(_ => CopyAddress(),
            _ => SelectedConnection != null);

        Scan();
    }

    private void Scan()
    {
        StatusText = "Scanning network connections...";

        try
        {
            _allConnections = _scanner.ScanConnections();
            OnPropertyChanged(nameof(TotalCount));
            OnPropertyChanged(nameof(EstablishedCount));
            OnPropertyChanged(nameof(ListeningCount));
            OnPropertyChanged(nameof(SuspiciousCount));

            ApplyFilters();
            StatusText = $"Scan complete — {_allConnections.Count} connections found";
        }
        catch (Exception ex)
        {
            StatusText = $"Scan failed: {ex.Message}";
        }
    }

    private void SetFilter(string filter)
    {
        _activeFilter = filter;
        _showingSuspicious = false;
        ApplyFilters();
    }

    private void ToggleSuspicious()
    {
        _showingSuspicious = !_showingSuspicious;
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        var query = _allConnections.AsEnumerable();

        // Protocol/state filter
        if (_showingSuspicious)
        {
            query = query.Where(c => c.RiskLevel is RiskLevel.Suspicious or RiskLevel.High);
        }
        else
        {
            query = _activeFilter switch
            {
                "TCP" => query.Where(c => c.Protocol == "TCP"),
                "UDP" => query.Where(c => c.Protocol == "UDP"),
                "Established" => query.Where(c => c.State == "Established"),
                "Listening" => query.Where(c => c.State == "Listening"),
                _ => query
            };
        }

        // Search filter
        if (!string.IsNullOrWhiteSpace(_searchText))
        {
            var term = _searchText.Trim().ToLower();
            query = query.Where(c =>
                c.ProcessName.ToLower().Contains(term) ||
                c.LocalAddress.Contains(term) ||
                c.RemoteAddress.Contains(term) ||
                c.LocalPort.ToString().Contains(term) ||
                c.RemotePort.ToString().Contains(term) ||
                c.State.ToLower().Contains(term) ||
                c.Protocol.ToLower().Contains(term));
        }

        var results = query
            .OrderByDescending(c => c.RiskLevel)
            .ThenBy(c => c.ProcessName)
            .ToList();

        FilteredConnections = new ObservableCollection<NetworkConnection>(results);
    }

    private void TerminateProcess()
    {
        if (SelectedConnection == null) return;

        var result = MessageBox.Show(
            $"Terminate process '{SelectedConnection.ProcessName}' (PID {SelectedConnection.Pid})?\n\nThis will kill all connections from this process.",
            "Confirm Termination",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        try
        {
            var proc = Process.GetProcessById(SelectedConnection.Pid);
            proc.Kill();
            Scan();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not terminate process: {ex.Message}", "Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OpenLocation()
    {
        if (SelectedConnection == null) return;
        var path = SelectedConnection.ProcessPath;
        if (File.Exists(path))
            Process.Start("explorer.exe", $"/select,\"{path}\"");
        else
            MessageBox.Show("Process path not available.", "Not Found",
                MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void CopyAddress()
    {
        if (SelectedConnection == null) return;
        var addr = SelectedConnection.RemoteAddress;
        if (!string.IsNullOrEmpty(addr) && addr != "*")
            Clipboard.SetText(addr);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
