using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

using UserControl    = System.Windows.Controls.UserControl;
using Color          = System.Windows.Media.Color;
using ColorConverter = System.Windows.Media.ColorConverter;
using Button         = System.Windows.Controls.Button;
using TextBox        = System.Windows.Controls.TextBox;
using KeyEventArgs   = System.Windows.Input.KeyEventArgs;
using Orientation    = System.Windows.Controls.Orientation;
using Cursors        = System.Windows.Input.Cursors;
using Brushes        = System.Windows.Media.Brushes;

namespace CsirtParser.WPF.Views;

public class KeywordTagEditor : UserControl
{
    public static readonly DependencyProperty ItemsSourceProperty =
        DependencyProperty.Register(nameof(ItemsSource),
            typeof(ObservableCollection<string>), typeof(KeywordTagEditor),
            new PropertyMetadata(null, OnItemsSourceChanged));

    public static readonly DependencyProperty TagBackgroundProperty =
        DependencyProperty.Register(nameof(TagBackground), typeof(string),
            typeof(KeywordTagEditor), new PropertyMetadata("#EEEDFE"));

    public static readonly DependencyProperty TagForegroundProperty =
        DependencyProperty.Register(nameof(TagForeground), typeof(string),
            typeof(KeywordTagEditor), new PropertyMetadata("#3C3489"));

    public ObservableCollection<string>? ItemsSource
    {
        get => (ObservableCollection<string>?)GetValue(ItemsSourceProperty);
        set => SetValue(ItemsSourceProperty, value);
    }

    public string TagBackground
    {
        get => (string)GetValue(TagBackgroundProperty);
        set => SetValue(TagBackgroundProperty, value);
    }

    public string TagForeground
    {
        get => (string)GetValue(TagForegroundProperty);
        set => SetValue(TagForegroundProperty, value);
    }

    private readonly WrapPanel _tagPanel;
    private readonly TextBox   _inputBox;

    public KeywordTagEditor()
    {
        _tagPanel = new WrapPanel { Orientation = Orientation.Horizontal };

        _inputBox = new TextBox
        {
            Height   = 32,
            MinWidth = 180,
            Padding  = new Thickness(8, 4, 8, 4),
            VerticalContentAlignment = VerticalAlignment.Center
        };
        _inputBox.KeyDown += (_, e) => { if (e.Key == Key.Enter) TryAdd(); };

        var addBtn = new Button
        {
            Content         = "Add",
            Height          = 32,
            Padding         = new Thickness(14, 0, 14, 0),
            Margin          = new Thickness(8, 0, 0, 0),
            Cursor          = Cursors.Hand,
            Background      = System.Windows.Media.Brushes.White,
            BorderThickness = new Thickness(1)
        };
        addBtn.Click += (_, _) => TryAdd();

        var inputRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin      = new Thickness(0, 8, 0, 0)
        };
        inputRow.Children.Add(_inputBox);
        inputRow.Children.Add(addBtn);

        var root = new StackPanel();
        root.Children.Add(_tagPanel);
        root.Children.Add(inputRow);

        Content = root;
    }

    private static void OnItemsSourceChanged(DependencyObject d,
        DependencyPropertyChangedEventArgs e)
    {
        var editor = (KeywordTagEditor)d;
        if (e.OldValue is ObservableCollection<string> old)
            old.CollectionChanged -= editor.OnCollectionChanged;
        if (e.NewValue is ObservableCollection<string> fresh)
            fresh.CollectionChanged += editor.OnCollectionChanged;
        editor.RebuildTags();
    }

    private void OnCollectionChanged(object? sender,
        NotifyCollectionChangedEventArgs e) => RebuildTags();

    private void RebuildTags()
    {
        _tagPanel.Children.Clear();
        if (ItemsSource == null) return;

        Color bg = ParseColor(TagBackground, "#EEEDFE");
        Color fg = ParseColor(TagForeground, "#3C3489");

        foreach (var keyword in ItemsSource)
        {
            var label = new TextBlock
            {
                Text              = keyword,
                FontSize          = 12,
                Foreground        = new SolidColorBrush(fg),
                VerticalAlignment = VerticalAlignment.Center
            };

            var removeBtn = new Button
            {
                Content         = "×",
                FontSize        = 14,
                Width           = 16,
                Height          = 16,
                Padding         = new Thickness(0),
                Margin          = new Thickness(5, 0, 0, 0),
                Background      = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Foreground      = new SolidColorBrush(fg),
                Cursor          = Cursors.Hand,
                Tag             = keyword
            };
            removeBtn.Click += RemoveBtn_Click;

            var row = new StackPanel { Orientation = Orientation.Horizontal };
            row.Children.Add(label);
            row.Children.Add(removeBtn);

            _tagPanel.Children.Add(new Border
            {
                Background   = new SolidColorBrush(bg),
                CornerRadius = new CornerRadius(12),
                Padding      = new Thickness(10, 4, 10, 4),
                Margin       = new Thickness(0, 2, 6, 2),
                Child        = row
            });
        }
    }

    private void TryAdd()
    {
        var text = _inputBox.Text.Trim();
        if (string.IsNullOrEmpty(text) || ItemsSource == null) return;
        if (!ItemsSource.Contains(text, StringComparer.OrdinalIgnoreCase))
            ItemsSource.Add(text);
        _inputBox.Clear();
    }

    private void RemoveBtn_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string keyword)
            ItemsSource?.Remove(keyword);
    }

    private static Color ParseColor(string hex, string fallback)
    {
        try   { return (Color)ColorConverter.ConvertFromString(hex)!; }
        catch { return (Color)ColorConverter.ConvertFromString(fallback)!; }
    }
}