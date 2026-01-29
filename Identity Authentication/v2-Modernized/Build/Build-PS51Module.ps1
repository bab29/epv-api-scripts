#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for PowerShell 5.1 IdentityAuth module

.DESCRIPTION
    Combines all PS5.1 source files into a single distributable module.
    Creates Distribution/IdentityAuth folder with compiled .psm1 and .psd1 files.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Write-Host "="*80
Write-Host "Building IdentityAuth Module (PowerShell 5.1)"
Write-Host "="*80

# Paths
$ScriptRoot = Split-Path -Parent $PSCommandPath
$ModuleRoot = Split-Path -Parent $ScriptRoot
$SourcePath = Join-Path $ModuleRoot 'PS5.1'
$DistPath = Join-Path $ModuleRoot 'Distribution\IdentityAuth'

Write-Host "Source: $SourcePath"
Write-Host "Destination: $DistPath"

# Clean distribution folder
if (Test-Path $DistPath) {
    Write-Host "Cleaning existing distribution..."
    Remove-Item $DistPath -Recurse -Force
}
$null = New-Item -Path $DistPath -ItemType Directory -Force

# Copy module files
Write-Host "Copying module files..."
Copy-Item "$SourcePath\IdentityAuth.psm1" -Destination $DistPath
Copy-Item "$SourcePath\IdentityAuth.psd1" -Destination $DistPath

# Copy Private and Public folders
if (Test-Path "$SourcePath\Private") {
    Copy-Item "$SourcePath\Private" -Destination $DistPath -Recurse
}
if (Test-Path "$SourcePath\Public") {
    Copy-Item "$SourcePath\Public" -Destination $DistPath -Recurse
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "Module location: $DistPath"
Write-Host "="*80
