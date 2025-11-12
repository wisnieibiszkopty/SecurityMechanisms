using System.Text;
using Cryptography.Crypto;
using Cryptography.PKI.Services;

void WriteTitle(string text)
{
    Console.ForegroundColor = ConsoleColor.DarkGreen;
    Console.WriteLine($"=== {text} ===");
    Console.ForegroundColor = ConsoleColor.White;
}

ICryptoService cryptoService = new CryptoService();

string message = "Hello Bob!";

//SYMMETRIC CRYPTOGRAPHY
using var key = cryptoService.GenerateSymmetricKey();

var encryptedSymmetric = cryptoService.EncryptSymmetric(message, key);
var decryptedSymmetric = cryptoService.DecryptSymmetric(encryptedSymmetric, key);

WriteTitle("Symmetric encryption");

Console.WriteLine("Text to be encrypted: " + message);
Console.WriteLine("Encrypted data (base64): " + Convert.ToBase64String(encryptedSymmetric));
Console.WriteLine("Decrypted data: " + decryptedSymmetric);

//ASYMMETRIC CRYPTOGRAPHY
using var aliceKeyPair = cryptoService.GenerateAsymmetricKeyPair();
using var bobKeyPair = cryptoService.GenerateAsymmetricKeyPair();

string messageToBob = "Message to Bob";
string messageToAlice = "Message to Alice";

var encryptedAsymmetricToBob = cryptoService
    .EncryptAsymmetric(messageToBob, bobKeyPair.PublicKey, aliceKeyPair.PrivateKey);
var decryptedAsymmetricToBob = cryptoService
    .DecryptAsymmetric(encryptedAsymmetricToBob, aliceKeyPair.PublicKey, bobKeyPair.PrivateKey);

WriteTitle("Asymmetric encryption");

Console.WriteLine($"Text to be encrypted: {messageToBob}");
Console.WriteLine($"Encrypted data (base64): {Convert.ToBase64String(encryptedAsymmetricToBob)}");
Console.WriteLine($"Decrypted data: {decryptedAsymmetricToBob}");

var encryptedAsymmetricToAlice = cryptoService
    .EncryptAsymmetric(messageToAlice, aliceKeyPair.PublicKey, bobKeyPair.PrivateKey);
var decryptedAsymmetricToAlice = cryptoService
    .DecryptAsymmetric(encryptedAsymmetricToAlice, bobKeyPair.PublicKey, aliceKeyPair.PrivateKey);
    
Console.WriteLine($"Text to be encrypted: {messageToAlice}");
Console.WriteLine($"Encrypted data (base64): {Convert.ToBase64String(encryptedAsymmetricToAlice)}");
Console.WriteLine($"Decrypted data: {decryptedAsymmetricToAlice}");

//HYBRID CRYPTOGRAPHY
string filepath = "Crypto/Resources/message.txt";
Console.WriteLine("Filepath to be encrypted: " + filepath);

var encryptedFilePath = cryptoService.EncryptFileSecretStream(filepath, bobKeyPair.PublicKey, aliceKeyPair.PrivateKey);
Console.WriteLine("Encrypted file path: " + encryptedFilePath);

var decryptedFilePath = cryptoService.DecryptFileSecretStream(encryptedFilePath, aliceKeyPair.PublicKey, bobKeyPair.PrivateKey);
Console.WriteLine("Decrypted file path: " + decryptedFilePath);

// PKI SIGNATURE
WriteTitle("PKI Signature");

var pkiService = new PKIService();
using var keyPair = pkiService.GenerateSigningKeyPair();

var pkiMessage = "Test PKI message";
var messageBytes = Encoding.UTF8.GetBytes(pkiMessage);

Console.WriteLine($"Message: {pkiMessage}");

var signature = pkiService.SignData(messageBytes, keyPair.PrivateKey);

Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");

var isValid = pkiService.VerifySignature(messageBytes, signature, keyPair.PublicKey);

Console.WriteLine($"Is signature valid? {isValid}");

// PKI Simulation
WriteTitle("PKI Simulation");

using var certificateAuthority = new CertificateAuthorityService(pkiService);

Console.WriteLine(certificateAuthority.RootCertificate);

var certificate = certificateAuthority.GenerateCertificate("Alice", keyPair.PublicKey);

Console.WriteLine("Issued Certificate");
Console.WriteLine(certificate);

isValid = certificateAuthority.VerifyCertificate(certificate);
Console.WriteLine($"Is signature valid? {isValid}");

certificateAuthority.ExportCertificate("certificate", certificate);
var importedCert = certificateAuthority.ImportCertificate("certificate.pem");
Console.WriteLine(importedCert);

certificateAuthority.AddCertificateToRevocationList(importedCert);

var isValidAfterRevocation = certificateAuthority.VerifyCertificate(importedCert); 
Console.WriteLine($"Is signature valid? {isValidAfterRevocation}");