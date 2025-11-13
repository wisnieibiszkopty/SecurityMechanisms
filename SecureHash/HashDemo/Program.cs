// See https://aka.ms/new-console-template for more information

using System.Diagnostics;
using ConsoleTables;
using HashDemo;
using MFAWebApp.Services.Authentication;
using Microsoft.Extensions.Configuration;

var pepper = PepperAndSaltGenerator.GeneratePepper();
var salt = PepperAndSaltGenerator.GenerateSalt();

Console.WriteLine($"Pepper: {pepper}");
Console.WriteLine($"Salt: {salt}");

var memoryConfig = new Dictionary<string, string>
{
    { "Security:PasswordPepper", pepper },
    { "Security:PasswordSalt", salt }
};

var inMemoryConfig = new ConfigurationBuilder()
    .AddInMemoryCollection(memoryConfig)
    .Build();

string retrievedPepper = inMemoryConfig["Security:PasswordPepper"];
Console.WriteLine($"Retrieved Pepper: {retrievedPepper}");

var stopwatch = new Stopwatch();

var password = "Password123Test";

var sha256Hasher = new Sha256Hasher(inMemoryConfig);
var bcryptHasher = new PasswordHasherBcrypt(inMemoryConfig);
var scryptHasher = new PasswordHasherScrypt(inMemoryConfig);

var sha256TestResult = PerformanceTest(sha256Hasher, "SHA256");
var bcryptTestResult = PerformanceTest(bcryptHasher, "Bcrypt");
var scryptTestResult = PerformanceTest(scryptHasher, "Scrypt");

var testsResults = new List<HashingTestResult>
{
    sha256TestResult,
    bcryptTestResult,
    scryptTestResult
};

PrintResultsAsTable(testsResults);
// Time in ms
// + ------------- + ----------- + ---------------- + ---------- +
// | AlgorithmName | HashingTime | VerificationTime | IsVerified |
// + ------------- + ----------- + ---------------- + ---------- +
// | SHA256        | 00.002711   | 00.0002879       | True       |
// + ------------- + ----------- + ---------------- + ---------- +
// | Bcrypt        | 00.585103   | 00.4764247       | True       |
// + ------------- + ----------- + ---------------- + ---------- +
// | Scrypt        | 00.252355   | 00.0786659       | True       |
// + ------------- + ----------- + ---------------- + ---------- +


HashingTestResult PerformanceTest(IPasswordHasher hasher, string algorithmName)
{
    stopwatch.Restart();
    stopwatch.Start();
    
    var hash = hasher.Hash(password);
    
    stopwatch.Stop();
    var hashingTime = stopwatch.Elapsed;
    
    stopwatch.Restart();
    stopwatch.Start();
    
    var isVerified = hasher.Verify(password, hash);
    
    stopwatch.Stop();
    var verificationTime = stopwatch.Elapsed;

    return new HashingTestResult
    {
        AlgorithmName = algorithmName,
        HashingTime = hashingTime.ToString(@"ss\.ffffff"),
        VerificationTime = verificationTime.ToString(@"ss\.fffffff"),
        IsVerified = isVerified
    };
}

void PrintResultsAsTable(List<HashingTestResult> rows)
{
    ConsoleTable.From(rows)
        .Write(Format.Alternative);
}