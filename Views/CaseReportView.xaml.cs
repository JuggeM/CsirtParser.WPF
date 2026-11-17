using System.Windows;
using System.Windows.Controls.Primitives;

using Button = System.Windows.Controls.Button;
using UserControl = System.Windows.Controls.UserControl;

namespace CsirtParser.WPF.Views;

public partial class CaseReportView : UserControl
{
    public CaseReportView() => InitializeComponent();

    // Left click opens the format menu under the button (a ContextMenu is
    // outside the visual tree, so hand it the button's DataContext first).
    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button b || b.ContextMenu is null) return;
        b.ContextMenu.DataContext = b.DataContext;
        b.ContextMenu.PlacementTarget = b;
        b.ContextMenu.Placement = PlacementMode.Bottom;
        b.ContextMenu.IsOpen = true;
    }
}
