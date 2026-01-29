#Requires -Version 7.0
<#
.SYNOPSIS
    Build script for PowerShell 7+ IdentityAuth module

.DESCRIPTION
    Combines all PS7 source files into a single distributable module.
    Creates Distribution/IdentityAuth-PS7 folder with compiled .psm1 and .psd1 files.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Write-Host "="*80
Write-Host "Building IdentityAuth Module (PowerShell 7+)"
Write-Host "="*80

# Paths
$ScriptRoot = Split-Path -Parent $PSCommandPath
$ModuleRoot = Split-Path -Parent $ScriptRoot
$SourcePath = Join-Path $ModuleRoot 'PS7'
$DistPath = Join-Path $ModuleRoot 'Distribution\IdentityAuth-PS7'

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

# Copy Classes, Enums, Private, and Public folders
foreach ($folder in @('Classes', 'Enums', 'Private', 'Public')) {
    if (Test-Path "$SourcePath\$folder") {
        Copy-Item "$SourcePath\$folder" -Destination $DistPath -Recurse
    }
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "Module location: $DistPath"
Write-Host "="*80
