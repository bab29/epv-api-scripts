<#
.SYNOPSIS
    Captures output from current IdentityAuth module for compatibility testing.

.DESCRIPTION
    Runs the EXISTING IdentityAuth.psm1 module against a live environment and captures:
    - Return value structure
    - Output format
    - Session data
    - API responses

    This baseline is used to ensure the v2 module maintains compatibility.

.PARAMETER TestType
    Type of authentication to test and capture.
    Valid values: 'OAuth', 'UP', 'MFA', 'OOBAUTHPIN', 'All'

.PARAMETER OutputPath
    Path to save captured baseline data. Defaults to Baselines\ folder.

.EXAMPLE
    .\Capture-CurrentModuleOutput.ps1 -TestType OAuth

    Captures OAuth authentication flow from current module.

.EXAMPLE
    .\Capture-CurrentModuleOutput.ps1 -TestType All -OutputPath "C:\Baselines"

    Captures all authentication flows and saves to specified path.

.NOTES
    Run this BEFORE starting v2 implementation to establish baseline behavior.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('OAuth', 'UP', 'MFA', 'OOBAUTHPIN', 'All')]
    [string]$TestType,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$PSScriptRoot\Baselines"
)

#Requires -Version 5.1

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    $null = New-Item -Path $OutputPath -ItemType Directory -Force
    Write-Output "Created baseline directory: $OutputPath"
}

# Import CURRENT module (v1)
$currentModulePath = "$PSScriptRoot\..\IdentityAuth.psm1"
if (-not (Test-Path -Path $currentModulePath)) {
    throw "Current module not found at: $currentModulePath"
}

Write-Output "="*80
Write-Output "Baseline Capture for IdentityAuth Module v1"
Write-Output "="*80
Write-Output "Module Path: $currentModulePath"
Write-Output "Test Type: $TestType"
Write-Output "Output Path: $OutputPath"
Write-Output "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "="*80
Write-Output ""

try {
    Import-Module $currentModulePath -Force -ErrorAction Stop
    Write-Output "Current module imported successfully"
    Write-Output ""
} catch {
    throw "Failed to import current module: $($_.Exception.Message)"
}

# Function to capture and serialize output
function Save-BaselineOutput {
    param(
        [string]$Name,
        [object]$Result,
        [string]$Description
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $filename = "baseline_${Name}_${timestamp}.json"
    $filepath = Join-Path -Path $OutputPath -ChildPath $filename

    $baselineData = @{
        TestType = $Name
        Description = $Description
        Timestamp = (Get-Date -Format 'o')
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        Result = $Result
        ResultType = $Result.GetType().FullName
        ResultProperties = $Result.PSObject.Properties.Name
    }

    $baselineData | ConvertTo-Json -Depth 10 | Set-Content -Path $filepath -Encoding UTF8
    Write-Output "Baseline saved: $filename"

    return $filepath
}

# Test functions
function Test-OAuth {
    Write-Output "Testing OAuth Authentication Flow"
    Write-Output "-"*80

    $pcloudUrl = Read-Host "Enter PCloud URL (e.g., https://tenant.cyberark.cloud)"
    $creds = Get-Credential -Message "OAuth Credentials (ClientID as Username, ClientSecret as Password)"

    Write-Output "Calling Get-IdentityHeader with OAuth credentials..."
    $startTime = Get-Date

    try {
        $result = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $pcloudUrl
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds

        Write-Output "SUCCESS - Duration: $duration seconds"
        Write-Output ""
        Write-Output "Result Type: $($result.GetType().FullName)"
        Write-Output "Result Value:"
        $result | Format-List | Out-String | Write-Output

        # Save baseline
        $filepath = Save-BaselineOutput -Name 'OAuth' -Result $result -Description 'OAuth Client Credentials authentication'

        Write-Output ""
        Write-Output "Baseline captured successfully!"
        return $filepath

    } catch {
        Write-Error "OAuth test failed: $($_.Exception.Message)"
        return $null
    }
}

function Test-UP {
    Write-Output "Testing Username/Password Authentication Flow"
    Write-Output "-"*80

    $identityUrl = Read-Host "Enter Identity URL (e.g., https://tenant.id.cyberark.cloud)"
    $username = Read-Host "Enter username"
    $creds = Get-Credential -Message "Enter password for $username"

    Write-Output "Calling Get-IdentityHeader with UP credentials..."
    $startTime = Get-Date

    try {
        $result = Get-IdentityHeader -UPCreds $creds -IdentityTenantURL $identityUrl
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds

        Write-Output "SUCCESS - Duration: $duration seconds"
        Write-Output ""
        Write-Output "Result Type: $($result.GetType().FullName)"
        Write-Output "Result Value:"
        $result | Format-List | Out-String | Write-Output

        # Save baseline
        $filepath = Save-BaselineOutput -Name 'UP' -Result $result -Description 'Username/Password authentication'

        Write-Output ""
        Write-Output "Baseline captured successfully!"
        return $filepath

    } catch {
        Write-Error "UP test failed: $($_.Exception.Message)"
        return $null
    }
}

function Test-MFA {
    Write-Output "Testing MFA (Push/OTP) Authentication Flow"
    Write-Output "-"*80

    $identityUrl = Read-Host "Enter Identity URL (e.g., https://tenant.id.cyberark.cloud)"
    $username = Read-Host "Enter username (will trigger MFA)"

    Write-Output "Calling Get-IdentityHeader (will prompt for MFA)..."
    $startTime = Get-Date

    try {
        $result = Get-IdentityHeader -IdentityUserName $username -IdentityTenantURL $identityUrl
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds

        Write-Output "SUCCESS - Duration: $duration seconds"
        Write-Output ""
        Write-Output "Result Type: $($result.GetType().FullName)"
        Write-Output "Result Value:"
        $result | Format-List | Out-String | Write-Output

        # Save baseline
        $filepath = Save-BaselineOutput -Name 'MFA' -Result $result -Description 'MFA (Push/OTP) authentication'

        Write-Output ""
        Write-Output "Baseline captured successfully!"
        return $filepath

    } catch {
        Write-Error "MFA test failed: $($_.Exception.Message)"
        return $null
    }
}

function Test-OOBAUTHPIN {
    Write-Output "Testing OOBAUTHPIN Authentication Flow"
    Write-Output "-"*80
    Write-Output "NOTE: Current module may use deprecated SAML. This captures existing behavior."
    Write-Output ""

    $pcloudUrl = Read-Host "Enter PCloud URL (e.g., https://tenant.cyberark.cloud)"
    $username = Read-Host "Enter username"

    Write-Output "Calling Get-IdentityHeader (will display SAML URL or prompt)..."
    $startTime = Get-Date

    try {
        $result = Get-IdentityHeader -IdentityUserName $username -PCloudURL $pcloudUrl
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds

        Write-Output "SUCCESS - Duration: $duration seconds"
        Write-Output ""
        Write-Output "Result Type: $($result.GetType().FullName)"
        Write-Output "Result Value:"
        $result | Format-List | Out-String | Write-Output

        # Save baseline
        $filepath = Save-BaselineOutput -Name 'OOBAUTHPIN' -Result $result -Description 'OOBAUTHPIN/SAML authentication'

        Write-Output ""
        Write-Output "Baseline captured successfully!"
        return $filepath

    } catch {
        Write-Error "OOBAUTHPIN test failed: $($_.Exception.Message)"
        return $null
    }
}

# Main execution
$capturedFiles = @()

Write-Output "Starting baseline capture..."
Write-Output ""

if ($TestType -eq 'All') {
    Write-Output "Capturing ALL authentication flows"
    Write-Output "You will be prompted for credentials for each flow"
    Write-Output ""

    $flows = @('OAuth', 'UP', 'MFA', 'OOBAUTHPIN')
    foreach ($flow in $flows) {
        Write-Output ""
        Write-Output "="*80
        $result = Read-Host "Capture $flow flow? (Y/N)"
        if ($result -eq 'Y') {
            switch ($flow) {
                'OAuth' { $file = Test-OAuth }
                'UP' { $file = Test-UP }
                'MFA' { $file = Test-MFA }
                'OOBAUTHPIN' { $file = Test-OOBAUTHPIN }
            }
            if ($file) { $capturedFiles += $file }
        }
        Write-Output ""
    }
} else {
    switch ($TestType) {
        'OAuth' { $file = Test-OAuth }
        'UP' { $file = Test-UP }
        'MFA' { $file = Test-MFA }
        'OOBAUTHPIN' { $file = Test-OOBAUTHPIN }
    }
    if ($file) { $capturedFiles += $file }
}

# Summary
Write-Output ""
Write-Output "="*80
Write-Output "BASELINE CAPTURE COMPLETE"
Write-Output "="*80
Write-Output "Files captured: $($capturedFiles.Count)"
foreach ($file in $capturedFiles) {
    Write-Output "  - $file"
}
Write-Output ""
Write-Output "These baseline files will be used to:"
Write-Output "  1. Verify v2 module returns identical structure"
Write-Output "  2. Test backward compatibility"
Write-Output "  3. Document current behavior"
Write-Output ""
Write-Output "Next Steps:"
Write-Output "  1. Review captured JSON files"
Write-Output "  2. Begin v2 implementation (Step 1)"
Write-Output "  3. Compare v2 output against these baselines"
Write-Output "="*80
