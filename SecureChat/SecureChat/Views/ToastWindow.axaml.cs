using Avalonia.Controls;
using Avalonia.Interactivity;

namespace SecureChat.Views;

public partial class ToastWindow : Window
{
    public string Message { get; set; }
    
    public ToastWindow(string message)
    {
        InitializeComponent();
        Title = "Message";
        Message = message;
        DataContext = this;
    }

    public void OnClose(object? sender, RoutedEventArgs e)
    {
        Close();
    }
}