#Requires -Version 5.1
<#
.SYNOPSIS
    Automated deployment script for IdentityAuth module

.DESCRIPTION
    Deploys IdentityAuth module to PowerShell module directories.
    Supports user and system-wide installation with validation.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateSet('User', 'System', 'Both')]
    [string]$Scope = 'User',

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$RemoveExisting
)

$ErrorActionPreference = 'Stop'

Write-Host @"
================================================================================
IdentityAuth Module Deployment
================================================================================

Scope: $Scope
Force: $Force
Remove Existing: $RemoveExisting

"@

# Paths
$ScriptRoot = $PSScriptRoot
$ModuleRoot = Split-Path -Parent $ScriptRoot
$DistPath = Join-Path $ModuleRoot 'Distribution\IdentityAuth'

# Validate distribution exists
if (-not (Test-Path $DistPath)) {
    throw "Distribution not found at: $DistPath. Run Build-PS51Module.ps1 first."
}

# Module paths
$userModulePath = Join-Path $env:USERPROFILE 'Documents\PowerShell\Modules\IdentityAuth'
$systemModulePath = Join-Path $env:ProgramFiles 'PowerShell\Modules\IdentityAuth'

# Check admin for system install
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (($Scope -eq 'System' -or $Scope -eq 'Both') -and -not $isAdmin) {
    throw "System-wide installation requires Administrator privileges. Run PowerShell as Administrator."
}

function Deploy-Module {
    param(
        [string]$DestinationPath,
        [string]$ScopeName
    )

    Write-Host "Deploying to $ScopeName scope..."
    Write-Host "  Destination: $DestinationPath"

    # Remove existing if requested
    if ($RemoveExisting -and (Test-Path $DestinationPath)) {
        if ($PSCmdlet.ShouldProcess($DestinationPath, "Remove existing module")) {
            Write-Host "  Removing existing module..." -ForegroundColor Yellow
            Remove-Item $DestinationPath -Recurse -Force
        }
    }

    # Check for existing module
    if ((Test-Path $DestinationPath) -and -not $Force) {
        Write-Warning "Module already exists at: $DestinationPath"
        Write-Warning "Use -Force to overwrite or -RemoveExisting to remove first"
        return $false
    }

    # Copy module
    if ($PSCmdlet.ShouldProcess($DestinationPath, "Deploy module")) {
        Write-Host "  Copying module files..."
        Copy-Item -Path $DistPath -Destination $DestinationPath -Recurse -Force

        # Verify installation
        if (Test-Path $DestinationPath) {
            $manifest = Join-Path $DestinationPath 'IdentityAuth.psd1'
            if (Test-Path $manifest) {
                $moduleInfo = Import-PowerShellDataFile -Path $manifest
                Write-Host "  SUCCESS: IdentityAuth v$($moduleInfo.ModuleVersion) deployed" -ForegroundColor Green
                return $true
            } else {
                Write-Error "Module manifest not found after deployment"
                return $false
            }
        } else {
            Write-Error "Module directory not created"
            return $false
        }
    }

    return $false
}

# Deploy based on scope
$deployed = @()

if ($Scope -eq 'User' -or $Scope -eq 'Both') {
    if (Deploy-Module -DestinationPath $userModulePath -ScopeName 'User') {
        $deployed += 'User'
    }
}

if ($Scope -eq 'System' -or $Scope -eq 'Both') {
    if (Deploy-Module -DestinationPath $systemModulePath -ScopeName 'System') {
        $deployed += 'System'
    }
}

# Test import
if ($deployed.Count -gt 0) {
    Write-Host @"

Testing module import...
"@

    try {
        Import-Module IdentityAuth -Force -ErrorAction Stop
        $module = Get-Module IdentityAuth

        Write-Host @"

Module loaded successfully!
  Name: $($module.Name)
  Version: $($module.Version)
  Path: $($module.Path)
  Exported Commands: $($module.ExportedCommands.Count)

"@ -ForegroundColor Green

    } catch {
        Write-Warning "Module deployed but failed to import: $_"
    }
}

Write-Host @"
================================================================================
Deployment Complete!
================================================================================

Deployed to: $($deployed -join ', ')

To use the module:
  Import-Module IdentityAuth
  Get-Help Get-IdentityHeader -Full

To uninstall:
  Remove-Item '$userModulePath' -Recurse -Force
$(if ($isAdmin) { "  Remove-Item '$systemModulePath' -Recurse -Force" })

================================================================================

"@
