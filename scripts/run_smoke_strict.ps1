#requires -Version 7.0

<
.SYNOPSIS
  Автоматический строгий прогон smoke-тестов (без SKIP) с UAC elevation.

.DESCRIPTION
  Скрипт сам поднимается в Admin (через UAC), запускает smoke runner,
  сохраняет JSON-отчёт и возвращает exit-code процесса dotnet.

  Важно: запуск WinDivert/TrafficEngine требует прав администратора.
>

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$csproj = Join-Path $repoRoot 'TestNetworkApp\TestNetworkApp.csproj'

if (-not (Test-Path $csproj)) {
    throw "Не найден проект TestNetworkApp: $csproj"
}

# Куда писать отчёт.
$reportDir = Join-Path $repoRoot 'artifacts'
$null = New-Item -ItemType Directory -Force -Path $reportDir
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$jsonPath = Join-Path $reportDir ("smoke_strict_{0}.json" -f $timestamp)

# Аргументы для dotnet run (ВАЖНО: после -- идут аргументы приложения)
$dotnetArgs = @(
    'run',
    '-c', 'Debug',
    '--project', $csproj,
    '--',
    '--smoke', 'all',
    '--no-skip',
    '--json', $jsonPath
)

if (-not (Test-IsAdmin)) {
    Write-Host "Требуются права администратора. Запрашиваю UAC..." -ForegroundColor Yellow

    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath
    )

    $p = Start-Process -FilePath 'pwsh.exe' -Verb RunAs -ArgumentList $argList -PassThru -Wait
    exit $p.ExitCode
}

Write-Host "Запуск smoke runner (strict)" -ForegroundColor Cyan
Write-Host "Проект: $csproj"
Write-Host "JSON:   $jsonPath"

& dotnet @dotnetArgs
$exitCode = $LASTEXITCODE

Write-Host "ExitCode: $exitCode" -ForegroundColor Cyan
Write-Host "Готово. Отчёт: $jsonPath" -ForegroundColor Green

exit $exitCode
