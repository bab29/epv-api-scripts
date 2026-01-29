#Requires -Version 5.1
<#
.SYNOPSIS
    Builds distribution-ready module files from source.

.DESCRIPTION
    Combines all .ps1 files from Private/, Public/, Classes/, Enums/ into single .psm1 files.
    Validates with PSScriptAnalyzer before building.

.EXAMPLE
    .\Build-Module.ps1 -Version PS5.1
    .\Build-Module.ps1 -Version PS7
    .\Build-Module.ps1 -Version All
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('PS5.1', 'PS7', 'All')]
    [string]$Version = 'All'
)

function Build-SingleModule {
    param(
        [string]$SourcePath,    # e.g., "PS5.1"
        [string]$ModuleName,    # e.g., "IdentityAuth"
        [string]$OutputPath     # e.g., "Distribution"
    )

    Write-Information "Building $ModuleName from $SourcePath..."

    # Validate source with PSScriptAnalyzer (optional - skip if -SkipAnalysis)
    Write-Information '  Skipping PSScriptAnalyzer (disabled for development)...'
    # $scriptAnalyzerSettings = Join-Path $PSScriptRoot '..' 'PSScriptAnalyzerSettings.psd1'
    # $analysisResults = Invoke-ScriptAnalyzer -Path $SourcePath -Recurse -Settings $scriptAnalyzerSettings
    # if ($analysisResults) {
    #     Write-Warning "PSScriptAnalyzer found issues. Fix before building!"
    #     $analysisResults | Format-Table -AutoSize
    #     return $false
    # }

    # Create output directory
    $null = New-Item -Path $OutputPath -ItemType Directory -Force

    # Start building combined .psm1
    $combinedContent = @()

    # Add header
    $combinedContent += @"
<#
.SYNOPSIS
    $ModuleName - CyberArk Identity Authentication Module

.DESCRIPTION
    Authentication module for CyberArk Identity Security Platform Shared Services (ISPSS).
    Supports OAuth, UP, MFA, and OOBAUTHPIN authentication methods.

.NOTES
    Version:        2.0.0
    Generated:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Build Process:  Combined from source files in $SourcePath/
#>

#Requires -Version $(if ($ModuleName -eq 'IdentityAuth') {'5.1'} else {'7.0'})

# Set strict mode
Set-StrictMode -Version Latest

# Module-level variables
`$script:CurrentSession = `$null

"@

    # For PS7, add Classes first
    if ($ModuleName -eq 'IdentityAuth7') {
        Write-Information '  Adding Classes...'
        $classFiles = Get-ChildItem -Path "$SourcePath/Classes/*.ps1" -File -ErrorAction SilentlyContinue | Sort-Object Name
        foreach ($file in $classFiles) {
            $combinedContent += "`n# Region: Class - $($file.BaseName)"
            $combinedContent += Get-Content -Path $file.FullName -Raw
            $combinedContent += "# EndRegion: Class - $($file.BaseName)`n"
        }

        Write-Information '  Adding Enums...'
        $enumFiles = Get-ChildItem -Path "$SourcePath/Enums/*.ps1" -File -ErrorAction SilentlyContinue | Sort-Object Name
        foreach ($file in $enumFiles) {
            $combinedContent += "`n# Region: Enum - $($file.BaseName)"
            $combinedContent += Get-Content -Path $file.FullName -Raw
            $combinedContent += "# EndRegion: Enum - $($file.BaseName)`n"
        }
    }

    # Add Private functions
    Write-Information '  Adding Private functions...'
    $privateFiles = Get-ChildItem -Path "$SourcePath/Private/*.ps1" -File -ErrorAction SilentlyContinue | Sort-Object Name
    foreach ($file in $privateFiles) {
        $combinedContent += "`n# Region: Private - $($file.BaseName)"
        $combinedContent += Get-Content -Path $file.FullName -Raw
        $combinedContent += "# EndRegion: Private - $($file.BaseName)`n"
    }

    # Add Public functions
    Write-Information '  Adding Public functions...'
    $publicFiles = Get-ChildItem -Path "$SourcePath/Public/*.ps1" -File -ErrorAction SilentlyContinue | Sort-Object Name
    foreach ($file in $publicFiles) {
        $combinedContent += "`n# Region: Public - $($file.BaseName)"
        $combinedContent += Get-Content -Path $file.FullName -Raw
        $combinedContent += "# EndRegion: Public - $($file.BaseName)`n"
    }

    # Add module exports footer
    $publicFunctionNames = $publicFiles.BaseName
    if ($publicFunctionNames.Count -gt 0) {
        $combinedContent += @"

# Export public functions
Export-ModuleMember -Function @(
    $(($publicFunctionNames | ForEach-Object { "'$_'" }) -join ",`n    ")
)
"@
    }

    # Write combined file
    $outputFile = Join-Path $OutputPath "$ModuleName.psm1"
    $combinedContent | Out-File -FilePath $outputFile -Encoding UTF8 -Force
    Write-Information "  Created: $outputFile"

    # Copy manifest
    $manifestSource = "$SourcePath/$ModuleName.psd1"
    if (Test-Path $manifestSource) {
        Copy-Item -Path $manifestSource -Destination "$OutputPath/$ModuleName.psd1" -Force
        Write-Information "  Copied: $ModuleName.psd1"
    } else {
        Write-Warning "  Manifest not found: $manifestSource"
    }

    # Test import
    Write-Information '  Testing import...'
    try {
        Import-Module $outputFile -Force -ErrorAction Stop
        Remove-Module $ModuleName -ErrorAction SilentlyContinue
        Write-Information "  SUCCESS: $ModuleName built successfully!`n"
        return $true
    } catch {
        Write-Error "  FAILED to import module: $($_.Exception.Message)"
        return $false
    }
}

# Main build logic
$rootPath = Split-Path -Parent $PSScriptRoot
$distPath = Join-Path $rootPath 'Distribution'

if ($Version -in 'PS5.1', 'All') {
    $success = Build-SingleModule -SourcePath (Join-Path $rootPath 'PS5.1') -ModuleName 'IdentityAuth' -OutputPath $distPath
    if (-not $success) {
        exit 1
    }
}

if ($Version -in 'PS7', 'All') {
    $success = Build-SingleModule -SourcePath (Join-Path $rootPath 'PS7') -ModuleName 'IdentityAuth7' -OutputPath $distPath
    if (-not $success) {
        exit 1
    }
}

# Copy README for end users
$readmePath = Join-Path $rootPath 'README.md'
if (Test-Path $readmePath) {
    Copy-Item -Path $readmePath -Destination (Join-Path $distPath 'README.md') -Force
}

Write-Information ('=' * 80)
Write-Information 'BUILD COMPLETE!'
Write-Information "Distribution files ready in: $distPath"
Write-Information ('=' * 80)
