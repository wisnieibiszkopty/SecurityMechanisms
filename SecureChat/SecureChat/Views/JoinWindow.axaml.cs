using System;
using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Cryptography.PKI.Services;
using SecureChat.Context;
using AppContext = SecureChat.Context.AppContext;

namespace SecureChat.Views;

public partial class JoinWindow : Window
{
    public JoinWindow()
    {
        InitializeComponent();
    }

    private void OnClick(object? sender, RoutedEventArgs e)
    {
        string? usernameText = Username.Text;
        if (!String.IsNullOrEmpty(usernameText))
        {
            JoinToChat(usernameText);
            Username.Text = "";
        }
    }

    private void JoinToChat(string username)
    {
        var encryptionKeys = AppContext.CryptoService.GenerateAsymmetricKeyPair();
        var signingKeys = AppContext.PkiService.GenerateSigningKeyPair();
        var certificate = AppContext.CA.GenerateCertificate(username, signingKeys.PublicKey);

        var user = new UserContext
        {
            Username = username,
            EncryptionKeys = encryptionKeys,
            SigningKeys = signingKeys,
            Certificate = certificate
        };
        
        AppContext.RegisterUser(user);

        var chatWindow = new ChatWindow(user);
        chatWindow.Show();
    }
}