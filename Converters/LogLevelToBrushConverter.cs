using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using CsirtParser.WPF.ViewModels;

// Explicit aliases to avoid ambiguity with System.Drawing and System.Windows.Forms
using Color = System.Windows.Media.Color;
using Binding = System.Windows.Data.Binding;

namespace CsirtParser.WPF.Converters;

public class LogLevelToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value is LogLevel level ? level switch
        {
            LogLevel.Success => new SolidColorBrush(Color.FromRgb(15, 110, 86)),   // green
            LogLevel.Warning => new SolidColorBrush(Color.FromRgb(186, 117, 23)),   // amber
            LogLevel.Error => new SolidColorBrush(Color.FromRgb(163, 45, 45)),   // red
            _ => new SolidColorBrush(Color.FromRgb(102, 102, 102)),  // grey
        } : Binding.DoNothing;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
