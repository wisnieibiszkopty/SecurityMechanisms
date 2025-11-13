namespace SecureChat.Models;

public class ChatMessage
{
    public string Sender { get; set; }
    public string Recipient { get; set; }
    public byte[] Ciphertext { get; set; }
    public byte[] Signature { get; set; }
}