using System.Collections.Specialized;
using System.Windows.Controls;

using UserControl = System.Windows.Controls.UserControl;

namespace CsirtParser.WPF.Views;

public partial class OutputView : UserControl
{
    public OutputView()
    {
        InitializeComponent();
        Loaded += (_, _) => HookLogScroll();
    }

    private void HookLogScroll()
    {
        if (DataContext is ViewModels.MainViewModel vm)
            vm.LogEntries.CollectionChanged += LogEntries_Changed;
    }

    private void LogEntries_Changed(object? sender, NotifyCollectionChangedEventArgs e)
    {
        // Auto-scroll to the newest log entry
        Dispatcher.BeginInvoke(() => LogScroll.ScrollToBottom());
    }
}
