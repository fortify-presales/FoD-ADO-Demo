using Microsoft.AspNetCore.Mvc;
using VulnerableApi.Models;
using VulnerableApi.Services;

namespace VulnerableApi.Controllers;

/// <summary>Authentication endpoints — contains intentional SQL injection and broken auth vulnerabilities (CWE-89, CWE-287, CWE-863).</summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly VulnerableDbService _db;
    private readonly InsecureTokenService _tokenService;

    public AuthController(VulnerableDbService db, InsecureTokenService tokenService)
    {
        _db = db;
        _tokenService = tokenService;
    }

    /// <summary>Authenticate a user. Username and password are embedded directly into raw SQL — vulnerable to SQL injection (CWE-89).</summary>
    /// <remarks>Example injection payload: username = <c>' OR 1=1 --</c></remarks>
    /// <response code="200">Returns a weak base64 token that embeds the plaintext password.</response>
    /// <response code="401">Invalid credentials.</response>
    [HttpPost("login")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        var user = _db.LoginUnsafe(request.Username, request.Password);
        if (user is null)
        {
            return Unauthorized(new { message = "Invalid credentials" });
        }

        var token = _tokenService.CreateWeakToken(user.Username, user.Password, user.Role);
        return Ok(new { token, role = user.Role });
    }

    /// <summary>Admin-only portal protected by a trivial string-contains check — vulnerable to broken authorization (CWE-863).</summary>
    /// <remarks>Any token containing the word <c>admin</c> (case-insensitive) is accepted, regardless of signature or validity.</remarks>
    /// <response code="200">Access granted.</response>
    /// <response code="403">Access denied.</response>
    [HttpGet("admin")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public IActionResult AdminPortal([FromQuery] string token)
    {
        if (_tokenService.IsAdminByContainsCheck(token))
        {
            return Ok(new { message = "Admin data returned without proper token validation." });
        }

        return Forbid();
    }
}
