using Microsoft.OpenApi.Models;
using VulnerableApi.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "VulnerableApi — FoD Demo",
        Version = "v1",
        Description = """
            ⚠️  WARNING: This API is intentionally insecure and exists only for security
            testing and Fortify on Demand demonstration purposes.
            DO NOT deploy to production.

            Intentional vulnerability categories:
            • SQL Injection (CWE-89)
            • Broken Authentication / Authorization (CWE-287, CWE-863)
            • Sensitive Data Exposure (CWE-200)
            • Path Traversal (CWE-22)
            • Weak Cryptography (CWE-327)
            """
    });

    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    options.IncludeXmlComments(xmlPath);
});
builder.Services.AddSingleton<VulnerableDbService>();
builder.Services.AddSingleton<InsecureTokenService>();
builder.Services.AddSingleton<WeakCryptoService>();
builder.Services.AddSingleton<InsecureFileService>();

var app = builder.Build();

var db = app.Services.GetRequiredService<VulnerableDbService>();
db.Initialize();

app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "VulnerableApi v1");
    options.RoutePrefix = "swagger";
});

app.MapControllers();

app.Run();

public partial class Program;
