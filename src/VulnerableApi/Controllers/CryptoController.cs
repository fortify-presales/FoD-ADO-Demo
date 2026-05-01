using Microsoft.AspNetCore.Mvc;
using VulnerableApi.Models;
using VulnerableApi.Services;

namespace VulnerableApi.Controllers;

/// <summary>Cryptography endpoints — contains intentional use of a broken hash algorithm (CWE-327).</summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class CryptoController : ControllerBase
{
    private readonly WeakCryptoService _cryptoService;

    public CryptoController(WeakCryptoService cryptoService)
    {
        _cryptoService = cryptoService;
    }

    /// <summary>Hash a string using MD5 — intentionally uses a broken/weak algorithm (CWE-327).</summary>
    /// <response code="200">Returns the MD5 hex digest of the input.</response>
    [HttpPost("md5")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    public IActionResult Md5([FromBody] HashRequest request)
    {
        var hash = _cryptoService.HashWithMd5(request.PlainText);
        return Ok(new { algorithm = "MD5", hash });
    }
}
