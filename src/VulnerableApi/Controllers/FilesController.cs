using Microsoft.AspNetCore.Mvc;
using VulnerableApi.Services;

namespace VulnerableApi.Controllers;

/// <summary>File access endpoints — contains intentional path traversal vulnerability (CWE-22).</summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class FilesController : ControllerBase
{
    private readonly InsecureFileService _fileService;

    public FilesController(InsecureFileService fileService)
    {
        _fileService = fileService;
    }

    /// <summary>Read a file from the server's public directory — vulnerable to path traversal (CWE-22).</summary>
    /// <remarks>Example traversal payload: path = <c>..\..\..\Windows\System32\drivers\etc\hosts</c></remarks>
    /// <response code="200">Returns file contents.</response>
    /// <response code="400">File not found or access error (with exception message exposed).</response>
    [HttpGet("read")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status400BadRequest)]
    public IActionResult Read([FromQuery] string path)
    {
        try
        {
            var content = _fileService.ReadWithoutPathValidation(path);
            return Ok(new { path, content });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message, requestedPath = path });
        }
    }
}
