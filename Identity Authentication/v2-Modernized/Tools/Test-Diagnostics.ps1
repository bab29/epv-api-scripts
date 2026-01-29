#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnostic tool for IdentityAuth module

.DESCRIPTION
    Performs comprehensive diagnostics including connectivity tests,
    module validation, and configuration checks.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$PCloudURL,
    
    [Parameter()]
    [string]$IdentityURL,
    
    [Parameter()]
    [switch]$TestConnectivity,
    
    [Parameter()]
    [switch]$ValidateModule
)

Write-Host @"
================================================================================
IdentityAuth Module Diagnostics
================================================================================

"@

# Module check
Write-Host "Checking IdentityAuth module..."
$module = Get-Module IdentityAuth
if ($module) {
    Write-Host "  ✅ Module loaded: $($module.Name) v$($module.Version)" -ForegroundColor Green
    Write-Host "  Path: $($module.Path)"
    Write-Host "  Commands: $($module.ExportedCommands.Count)"
} else {
    $available = Get-Module -ListAvailable IdentityAuth
    if ($available) {
        Write-Host "  ⚠️  Module available but not loaded" -ForegroundColor Yellow
        Write-Host "  Version: $($available.Version)"
        Write-Host "  Path: $($available.ModuleBase)"
        Write-Host "  Run: Import-Module IdentityAuth"
    } else {
        Write-Host "  ❌ Module not found" -ForegroundColor Red
        Write-Host "  Install module first"
    }
}

# PowerShell version
Write-Host "`nPowerShell Environment:"
Write-Host "  Version: $($PSVersionTable.PSVersion)"
Write-Host "  Edition: $($PSVersionTable.PSEdition)"
Write-Host "  OS: $($PSVersionTable.OS)"
Write-Host "  Platform: $($PSVersionTable.Platform)"

# Module path
Write-Host "`nModule Search Paths:"
$env:PSModulePath -split [IO.Path]::PathSeparator | ForEach-Object {
    $exists = Test-Path $_
    $icon = if ($exists) { "✅" } else { "❌" }
    Write-Host "  $icon $_"
}

# Connectivity tests
if ($TestConnectivity) {
    Write-Host "`nConnectivity Tests:"
    
    if ($PCloudURL) {
        Write-Host "`n  Testing PCloud URL: $PCloudURL"
        
        # Parse URL
        try {
            $uri = [System.Uri]$PCloudURL
            $hostname = $uri.Host
            
            # DNS test
            Write-Host "    DNS Resolution..."
            try {
                $addresses = [System.Net.Dns]::GetHostAddresses($hostname)
                Write-Host "      ✅ Resolved to: $($addresses[0].IPAddressToString)" -ForegroundColor Green
            } catch {
                Write-Host "      ❌ DNS resolution failed: $_" -ForegroundColor Red
            }
            
            # HTTPS test
            Write-Host "    HTTPS Connectivity..."
            try {
                $response = Invoke-WebRequest -Uri $PCloudURL -Method Head -TimeoutSec 5 -UseBasicParsing
                Write-Host "      ✅ Connected (Status: $($response.StatusCode))" -ForegroundColor Green
            } catch {
                Write-Host "      ❌ Connection failed: $_" -ForegroundColor Red
            }
        } catch {
            Write-Host "    ❌ Invalid URL format" -ForegroundColor Red
        }
    }
    
    if ($IdentityURL) {
        Write-Host "`n  Testing Identity URL: $IdentityURL"
        
        try {
            $uri = [System.Uri]$IdentityURL
            $hostname = $uri.Host
            
            Write-Host "    DNS Resolution..."
            try {
                $addresses = [System.Net.Dns]::GetHostAddresses($hostname)
                Write-Host "      ✅ Resolved to: $($addresses[0].IPAddressToString)" -ForegroundColor Green
            } catch {
                Write-Host "      ❌ DNS resolution failed: $_" -ForegroundColor Red
            }
            
            Write-Host "    HTTPS Connectivity..."
            try {
                $response = Invoke-WebRequest -Uri $IdentityURL -Method Head -TimeoutSec 5 -UseBasicParsing
                Write-Host "      ✅ Connected (Status: $($response.StatusCode))" -ForegroundColor Green
            } catch {
                Write-Host "      ❌ Connection failed: $_" -ForegroundColor Red
            }
        } catch {
            Write-Host "    ❌ Invalid URL format" -ForegroundColor Red
        }
    }
}

# Module validation
if ($ValidateModule -and $module) {
    Write-Host "`nModule Validation:"
    
    # Check required functions
    $requiredFunctions = @('Get-IdentityHeader')
    foreach ($func in $requiredFunctions) {
        $exists = Get-Command $func -ErrorAction SilentlyContinue
        $icon = if ($exists) { "✅" } else { "❌" }
        Write-Host "  $icon Function: $func"
    }
    
    # Check help
    Write-Host "`n  Checking help documentation..."
    $help = Get-Help Get-IdentityHeader
    if ($help.Synopsis) {
        Write-Host "    ✅ Help documentation available" -ForegroundColor Green
    } else {
        Write-Host "    ⚠️  Help documentation missing" -ForegroundColor Yellow
    }
    
    # Check private functions
    $privatePath = Join-Path (Split-Path $module.Path) 'Private'
    if (Test-Path $privatePath) {
        $privateCount = (Get-ChildItem $privatePath -Filter *.ps1).Count
        Write-Host "    ✅ Private functions: $privateCount" -ForegroundColor Green
    } else {
        Write-Host "    ⚠️  Private functions directory not found" -ForegroundColor Yellow
    }
}

Write-Host @"

================================================================================
Diagnostics Complete
================================================================================

For more information:
  Get-Help Get-IdentityHeader -Full
  Get-Help Get-IdentityHeader -Examples

To test authentication:
  $creds = Get-Credential
  $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $pcloudUrl -Verbose

================================================================================

"@
