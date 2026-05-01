using Microsoft.AspNetCore.Mvc;
using VulnerableApi.Services;

namespace VulnerableApi.Controllers;

/// <summary>Data access endpoints — contains intentional SQL injection and sensitive data exposure vulnerabilities (CWE-89, CWE-200).</summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class DataController : ControllerBase
{
    private readonly VulnerableDbService _db;

    public DataController(VulnerableDbService db)
    {
        _db = db;
    }

    /// <summary>Search users by username using unsafe string interpolation — vulnerable to SQL injection (CWE-89).</summary>
    /// <remarks>Example injection payload: username = <c>' OR '1'='1</c></remarks>
    /// <response code="200">Returns matching user records including plaintext passwords and SSNs (CWE-200).</response>
    [HttpGet("search")]
    [ProducesResponseType(typeof(IEnumerable<object>), StatusCodes.Status200OK)]
    public IActionResult Search([FromQuery] string username)
    {
        var results = _db.SearchUsersUnsafe(username);
        return Ok(results);
    }

    /// <summary>Fetch user profile by ID expression embedded directly into SQL — vulnerable to SQL injection (CWE-89) and sensitive data exposure (CWE-200).</summary>
    /// <remarks>Example injection payload: idExpression = <c>1 OR 1=1</c></remarks>
    /// <response code="200">Returns user record(s) including plaintext passwords and SSNs.</response>
    [HttpGet("profile/{idExpression}")]
    [ProducesResponseType(typeof(IEnumerable<object>), StatusCodes.Status200OK)]
    public IActionResult Profile(string idExpression)
    {
        var results = _db.GetProfilesUnsafe(idExpression);
        return Ok(results);
    }
}
