namespace VulnerableApi.Models;

public class UserRecord
{
    public long Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string Ssn { get; set; } = string.Empty;
}
