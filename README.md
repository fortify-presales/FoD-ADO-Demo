# FoD ADO Demo - Vulnerable .NET 9 REST API

WARNING: This project is intentionally insecure and exists only for security testing demonstrations.
Do not deploy this code to production.

## Overview

This repository contains a simple ASP.NET Core .NET 9 REST API with intentionally vulnerable patterns that static and dynamic security testing tools can detect, including Fortify on Demand.

Included vulnerability categories:
1. SQL Injection
2. Broken authentication and authorization
3. Sensitive data exposure
4. Path traversal
5. Weak cryptography

For endpoint details and CWE mapping, see docs/VULNERABILITIES.md.

## Prerequisites

1. .NET SDK 9.x
2. PowerShell (Windows)

## Project Structure

1. src/VulnerableApi: REST API with intentionally vulnerable endpoints
2. tests/VulnerableApi.Tests: xUnit tests
3. .azuredevops/pipeline.yml: Azure DevOps build/test pipeline with FoD scan stub

## Build and Test

Run from repository root:

```powershell
dotnet restore FoD-ADO-Demo.sln
dotnet build FoD-ADO-Demo.sln -c Debug
dotnet test tests/VulnerableApi.Tests/VulnerableApi.Tests.csproj -c Debug
```

## Run the API

```powershell
dotnet run --project src/VulnerableApi/VulnerableApi.csproj
```

Swagger UI is available at http://localhost:<port>/swagger.

## Example Endpoints

1. POST /api/auth/login
2. GET /api/auth/admin?token=example
3. GET /api/data/search?username=alice
4. GET /api/data/profile/1
5. GET /api/files/read?path=hello.txt
6. POST /api/crypto/md5

## Azure DevOps Pipeline

Pipeline file: .azuredevops/pipeline.yml

It includes:
1. .NET 9 SDK setup
2. Restore, build, and test steps
3. FoD scan placeholder step with variables to customize

## Notes for Fortify on Demand

1. Configure FoD credentials as secure pipeline variables.
2. Replace the fcli command in the FoD step with your organization-approved fcli or Azure DevOps marketplace task.
3. Keep this code isolated from production repositories.