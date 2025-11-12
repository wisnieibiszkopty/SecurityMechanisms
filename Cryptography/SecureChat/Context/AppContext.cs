using System;
using System.Collections.Generic;
using Cryptography.Crypto;
using Cryptography.PKI.Interfaces;
using Cryptography.PKI.Services;
using SecureChat.Models;

namespace SecureChat.Context;

internal static class AppContext
{
    public static ICryptoService CryptoService { get; } = new CryptoService(); 
    public static IPKIService PkiService { get; } = new PKIService();
    public static CertificateAuthorityService CA { get; } = new CertificateAuthorityService(PkiService);
    
    public static List<UserContext> Users { get; } = [];
    
    public static event Action<ChatMessage> OnMessageReceived;
    public static event Action<UserContext> OnUserRegistered;
    
    public static void RegisterUser(UserContext user)
    {
        Users.Add(user);
        OnUserRegistered?.Invoke(user);
    }
    
    public static void SendMessage(ChatMessage msg)
    {
        OnMessageReceived?.Invoke(msg);
    }
}