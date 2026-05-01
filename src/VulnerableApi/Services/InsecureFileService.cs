namespace VulnerableApi.Services;

public class InsecureFileService
{
    private readonly string _baseDirectory;

    public InsecureFileService(IWebHostEnvironment environment)
    {
        _baseDirectory = Path.Combine(environment.ContentRootPath, "public");
        Directory.CreateDirectory(_baseDirectory);

        var sampleFile = Path.Combine(_baseDirectory, "hello.txt");
        if (!File.Exists(sampleFile))
        {
            File.WriteAllText(sampleFile, "Hello from intentionally vulnerable demo API.");
        }
    }

    public string ReadWithoutPathValidation(string userProvidedPath)
    {
        var combinedPath = Path.Combine(_baseDirectory, userProvidedPath);
        return File.ReadAllText(combinedPath);
    }
}
