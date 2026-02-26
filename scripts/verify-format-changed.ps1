param(
    [string]$Workspace = ".",
    [string]$Solution = "ISP_Audit.sln"
)

$ErrorActionPreference = "Stop"

function Write-Info([string]$message) {
    Write-Host "[verify-format-changed] $message"
}

Push-Location $Workspace
try {
    $allowedExtensions = @(
        ".cs",
        ".csproj",
        ".props",
        ".targets",
        ".xaml"
    )

    $changedTracked = git diff --name-only --diff-filter=ACMRTUXB HEAD
    $changedUntracked = git ls-files --others --exclude-standard

    $allChanged = @($changedTracked + $changedUntracked) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique

    $formatCandidates = $allChanged |
        Where-Object {
            $ext = [System.IO.Path]::GetExtension($_)
            $allowedExtensions -contains $ext
        } |
        Where-Object { Test-Path $_ }

    if ($formatCandidates.Count -eq 0) {
        Write-Info "No changed files require dotnet format."
        exit 0
    }

    Write-Info "Checking format for changed files ($($formatCandidates.Count)):"
    $formatCandidates | ForEach-Object { Write-Host "  - $_" }

    $dotnetCmd = Join-Path $env:USERPROFILE ".dotnet\dotnet.exe"
    if (-not (Test-Path $dotnetCmd)) {
        $dotnetCmd = "dotnet"
    }

    $args = @("format", $Solution, "--verify-no-changes", "--include") + $formatCandidates

    & $dotnetCmd @args
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-Info "dotnet format found formatting issues in changed files (ExitCode=$exitCode)."
        exit $exitCode
    }

    Write-Info "Changed files formatting is OK."
    exit 0
}
finally {
    Pop-Location
}
