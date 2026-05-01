using System.Security.Cryptography;
using System.Text;

namespace VulnerableApi.Services;

public class WeakCryptoService
{
    public string HashWithMd5(string input)
    {
        using var md5 = MD5.Create();
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = md5.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
