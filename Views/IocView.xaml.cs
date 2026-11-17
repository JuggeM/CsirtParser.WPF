using System.Windows;
using CsirtParser.WPF.ViewModels;

using DataFormats = System.Windows.DataFormats;
using DragDropEffects = System.Windows.DragDropEffects;
using DragEventArgs = System.Windows.DragEventArgs;
using UserControl = System.Windows.Controls.UserControl;

namespace CsirtParser.WPF.Views;

public partial class IocView : UserControl
{
    public IocView() => InitializeComponent();

    // A TextBox swallows file drops by default; Preview* handlers let files through.
    private void IocBox_PreviewDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
        }
    }

    private void IocBox_PreviewDrop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop) || DataContext is not MainViewModel vm) return;
        foreach (var file in (string[])e.Data.GetData(DataFormats.FileDrop))
            vm.ImportIocFile(file);
        e.Handled = true;
    }
}
