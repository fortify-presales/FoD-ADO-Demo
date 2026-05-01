namespace VulnerableApi.Services;

public class InsecureTokenService
{
    public string CreateWeakToken(string username, string password, string role)
    {
        var tokenPayload = $"{username}:{password}:{role}:{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(tokenPayload));
    }

    public bool IsAdminByContainsCheck(string token)
    {
        return token.Contains("admin", StringComparison.OrdinalIgnoreCase);
    }
}
