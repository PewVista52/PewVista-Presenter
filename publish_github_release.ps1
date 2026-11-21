param(
    [string]$ReleaseNotes = "PewVista Presenter release update.",
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDirectory

if (-not $SkipBuild) {
    Write-Host "[1/3] Building customer installation and update packages..."
    & cmd.exe /c (Join-Path $scriptDirectory "update_windows_app.bat") --no-pause
    if ($LASTEXITCODE -ne 0) {
        throw "Release build failed."
    }
}

$latestDir = Join-Path $scriptDirectory "dist\releases\latest"
$setupSpaces = Join-Path $latestDir "PewVista Presenter Setup.exe"
$setupAsset = Join-Path $latestDir "PewVista-Presenter-Setup.exe"
$updateAsset = Join-Path $latestDir "PewVista-Presenter-Update-Windows-x64.zip"
$latestJson = Join-Path $latestDir "latest.json"
$pricingJson = Join-Path $scriptDirectory "Resourses\pricing.json"

if ((Test-Path -LiteralPath $setupSpaces -PathType Leaf) -and -not (Test-Path -LiteralPath $setupAsset -PathType Leaf)) {
    Move-Item -LiteralPath $setupSpaces -Destination $setupAsset -Force
}

foreach ($required in @($setupAsset, $updateAsset, $latestJson, $pricingJson)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Missing required release asset: $required"
    }
}

if (-not $env:GH_TOKEN) {
    $creds = "protocol=https`nhost=github.com`n`n" | git credential fill
    $tokenLine = ($creds -split "`n") | Where-Object { $_ -like "password=*" }
    $env:GH_TOKEN = ($tokenLine -replace "^password=", "").Trim()
}
if (-not $env:GH_TOKEN) {
    throw "GitHub authentication token not found."
}

$tag = "v" + (Get-Date -Format "yyyy.MM.dd-HHmm")
Write-Host "[2/3] Publishing release $tag to GitHub (exact 4 custom assets -> 6 total with source archives)..."
gh release create $tag `
    $setupAsset `
    $updateAsset `
    $latestJson `
    $pricingJson `
    --repo PewVista52/PewVista-Presenter `
    --title "PewVista Presenter $tag" `
    --notes $ReleaseNotes `
    --latest

if ($LASTEXITCODE -ne 0) {
    throw "GitHub release upload failed."
}

Write-Host "[3/3] Cleaning up local release and build staging folders to save disk space..."
Remove-Item (Join-Path $scriptDirectory "dist\releases") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $scriptDirectory "build\desktop-staging") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $scriptDirectory "build\release-package") -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Release $tag published and local staging cleaned up."
