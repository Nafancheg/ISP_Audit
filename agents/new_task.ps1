param(
    [string]$Title,
    [string]$Id,
    [switch]$NoUpdateCurrentTask
)

$ErrorActionPreference = 'Stop'

function New-Slug([string]$text) {
    if (-not $text) { return "task" }
    $lower = $text.ToLowerInvariant()
    $slug  = $lower -replace "[^a-z0-9\p{IsCyrillic}]+", "-" -replace "^-+|-+$", ""
    if ([string]::IsNullOrWhiteSpace($slug)) { return "task" }
    return $slug
}

function Replace-Placeholders([string]$filePath, [hashtable]$map) {
    $content = Get-Content -Raw -Encoding UTF8 -Path $filePath
    foreach ($k in $map.Keys) {
        $content = $content -replace [regex]::Escape($k), [string]$map[$k]
    }
    Set-Content -Encoding UTF8 -NoNewline -Path $filePath -Value $content
}

$agentsRoot   = $PSScriptRoot
$templateDir  = Join-Path $agentsRoot "_template"
$runsDir      = Join-Path $agentsRoot "runs"
$taskOwnerDir = Join-Path $agentsRoot "task_owner"

if (-not (Test-Path $templateDir)) { throw "Не найден шаблон: $templateDir" }
if (-not (Test-Path $runsDir))     { New-Item -Type Directory -Force -Path $runsDir | Out-Null }

if (-not $Title) { $Title = Read-Host "Введите заголовок задачи (Title)" }
$slug = New-Slug $Title
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
if (-not $Id) { $Id = "$stamp-$slug" }

$runDir = Join-Path $runsDir $Id
if (Test-Path $runDir) {
    $i = 2
    do {
        $candidate = "$runDir-$i"
        $i += 1
    } while (Test-Path $candidate)
    $runDir = $candidate
}

Copy-Item -Recurse -Force -LiteralPath $templateDir -Destination $runDir

$today = Get-Date -Format 'yyyy-MM-dd'
$map = @{
    '{{TITLE}}' = $Title
    '{{ID}}'    = Split-Path -Leaf $runDir
    '{{DATE}}'  = $today
}

Get-ChildItem -Path $runDir -Recurse -File | ForEach-Object { Replace-Placeholders $_.FullName $map }

# meta.json
$meta = [ordered]@{
    id        = (Split-Path -Leaf $runDir)
    title     = $Title
    createdAt = (Get-Date).ToUniversalTime().ToString('o')
    files     = [ordered]@{
        task           = 'task.md'
        research       = 'research.md'
        plan           = 'plan.md'
        implementation = 'implementation.md'
        review         = 'review.md'
        qa_plan        = 'qa_test_plan.md'
        qa_report      = 'qa_report.md'
        changelog      = 'changelog.md'
        delivery       = 'delivery.md'
        decisions      = 'decisions.md'
        checklist      = 'checklist.md'
    }
}

$meta | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 -FilePath (Join-Path $runDir 'meta.json')

if (-not $NoUpdateCurrentTask) {
    if (-not (Test-Path $taskOwnerDir)) { New-Item -Type Directory -Force -Path $taskOwnerDir | Out-Null }
    $currentTaskPath = Join-Path $taskOwnerDir 'current_task.md'
    if (Test-Path $currentTaskPath) {
        $backupDir = Join-Path $taskOwnerDir 'backups'
        if (-not (Test-Path $backupDir)) { New-Item -Type Directory -Force -Path $backupDir | Out-Null }
        $backupPath = Join-Path $backupDir ("current_task_" + $stamp + '.md')
        Copy-Item -LiteralPath $currentTaskPath -Destination $backupPath -Force
    }

    $relRun = (Resolve-Path -LiteralPath $runDir).Path
    $relRun = (New-Object System.Uri (Join-Path $agentsRoot '.')).MakeRelativeUri((New-Object System.Uri $relRun)).ToString().Replace('/', '\\')

    @(
        "# Текущая задача",
        "",
        "- ID: ``$((Split-Path -Leaf $runDir))``",
        "- Title: $Title",
        "- Папка итерации: ``$relRun``",
        "",
        "Основной документ: `$relRun\task.md`",
        "Чек‑лист: `$relRun\checklist.md`"
    ) -join "`r`n" | Set-Content -Encoding UTF8 -Path $currentTaskPath
}

Write-Host "Создана новая итерация:" -ForegroundColor Green
Write-Host "  $runDir"
Write-Host "Откройте task.md и заполните детали."

