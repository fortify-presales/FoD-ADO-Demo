using Microsoft.Data.Sqlite;
using VulnerableApi.Models;

namespace VulnerableApi.Services;

public class VulnerableDbService
{
    private readonly string _connectionString;

    public VulnerableDbService(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=vulnerable-demo.db";
    }

    public void Initialize()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var create = connection.CreateCommand();
        create.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                Password TEXT NOT NULL,
                Role TEXT NOT NULL,
                Ssn TEXT NOT NULL
            );";
        create.ExecuteNonQuery();

        var count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM Users;";
        var existing = Convert.ToInt32(count.ExecuteScalar());

        if (existing == 0)
        {
            var seed = connection.CreateCommand();
            seed.CommandText = @"
                INSERT INTO Users (Username, Password, Role, Ssn) VALUES
                ('alice', 'Password123!', 'user', '111-22-3333'),
                ('bob', 'AdminPass123!', 'admin', '222-33-4444');";
            seed.ExecuteNonQuery();
        }
    }

    public string BuildUnsafeUserSearchQuery(string username)
    {
        return $"SELECT Id, Username, Password, Role, Ssn FROM Users WHERE Username LIKE '%{username}%';";
    }

    public string BuildUnsafeLoginQuery(string username, string password)
    {
        return $"SELECT Id, Username, Password, Role, Ssn FROM Users WHERE Username = '{username}' AND Password = '{password}' LIMIT 1;";
    }

    public string BuildUnsafeProfileQuery(string userIdExpression)
    {
        return $"SELECT Id, Username, Password, Role, Ssn FROM Users WHERE Id = {userIdExpression};";
    }

    public List<UserRecord> SearchUsersUnsafe(string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = BuildUnsafeUserSearchQuery(username);

        using var reader = command.ExecuteReader();
        var results = new List<UserRecord>();

        while (reader.Read())
        {
            results.Add(ReadUser(reader));
        }

        return results;
    }

    public UserRecord? LoginUnsafe(string username, string password)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = BuildUnsafeLoginQuery(username, password);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    public List<UserRecord> GetProfilesUnsafe(string userIdExpression)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = BuildUnsafeProfileQuery(userIdExpression);

        using var reader = command.ExecuteReader();
        var results = new List<UserRecord>();

        while (reader.Read())
        {
            results.Add(ReadUser(reader));
        }

        return results;
    }

    private static UserRecord ReadUser(SqliteDataReader reader)
    {
        return new UserRecord
        {
            Id = reader.GetInt64(0),
            Username = reader.GetString(1),
            Password = reader.GetString(2),
            Role = reader.GetString(3),
            Ssn = reader.GetString(4)
        };
    }
}
