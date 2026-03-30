using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using NetSniffer.Models;

namespace NetSniffer.Converters;

public class StateColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var state = value as string ?? string.Empty;
        var hex = state switch
        {
            "Established" => "#3DCC6A",
            "Listening"   => "#4A9EFF",
            "Time Wait"   => "#FFAA33",
            "Close Wait"  => "#FF7A33",
            "SYN Sent"    => "#CC88FF",
            "SYN Recv"    => "#AA66FF",
            "Closed"      => "#555570",
            _             => "#44445A"
        };
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}

public class ProtocolColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return (value as string) switch
        {
            "TCP" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1A3A6A")),
            "UDP" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3A2A5A")),
            _     => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1A2A2A"))
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}

public class RiskColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var hex = value is RiskLevel risk ? risk switch
        {
            RiskLevel.Safe       => "#3DCC6A",
            RiskLevel.Low        => "#88CC44",
            RiskLevel.Medium     => "#FFAA33",
            RiskLevel.High       => "#FF6633",
            RiskLevel.Suspicious => "#FF3333",
            _                    => "#888899"
        } : "#888899";

        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}

public class RiskBadgeColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var hex = value is RiskLevel risk ? risk switch
        {
            RiskLevel.Safe       => "#0D2A1A",
            RiskLevel.Low        => "#182A0A",
            RiskLevel.Medium     => "#2A1E00",
            RiskLevel.High       => "#2A0E00",
            RiskLevel.Suspicious => "#2A0000",
            _                    => "#16162A"
        } : "#16162A";

        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}

public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is Visibility.Visible;
}

public class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool isNull = value == null;
        // ConverterParameter="Inverse" → show when NOT null
        bool inverse = parameter as string == "Inverse";
        if (inverse) return isNull ? Visibility.Collapsed : Visibility.Visible;
        return isNull ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}

public class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is false ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => Binding.DoNothing;
}
