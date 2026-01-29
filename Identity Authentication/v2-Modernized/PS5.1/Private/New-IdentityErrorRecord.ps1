#Requires -Version 5.1
<#
.SYNOPSIS
    Enhanced error handling with detailed context

.DESCRIPTION
    Creates detailed error records with context, troubleshooting hints, and categorization.
#>

function New-IdentityErrorRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter(Mandatory)]
        [string]$ErrorId,

        [Parameter()]
        [System.Management.Automation.ErrorCategory]$Category = [System.Management.Automation.ErrorCategory]::NotSpecified,

        [Parameter()]
        [object]$TargetObject,

        [Parameter()]
        [string]$RecommendedAction,

        [Parameter()]
        [Exception]$InnerException
    )

    # Create exception
    if ($InnerException) {
        $exception = New-Object System.Exception($Message, $InnerException)
    } else {
        $exception = New-Object System.Exception($Message)
    }

    # Create error record
    $errorRecord = New-Object System.Management.Automation.ErrorRecord(
        $exception,
        $ErrorId,
        $Category,
        $TargetObject
    )

    # Add recommended action
    if ($RecommendedAction) {
        $errorRecord.ErrorDetails = New-Object System.Management.Automation.ErrorDetails($Message)
        $errorRecord.ErrorDetails.RecommendedAction = $RecommendedAction
    }

    return $errorRecord
}

function Get-ErrorContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    return @{
        Message         = $ErrorRecord.Exception.Message
        ErrorId         = $ErrorRecord.FullyQualifiedErrorId
        Category        = $ErrorRecord.CategoryInfo.Category
        TargetName      = $ErrorRecord.TargetObject
        ScriptStackTrace = $ErrorRecord.ScriptStackTrace
        InnerException  = if ($ErrorRecord.Exception.InnerException) {
            $ErrorRecord.Exception.InnerException.Message
        } else {
            $null
        }
    }
}

function Test-NetworkConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$URL
    )

    try {
        $uri = [System.Uri]$URL
        $hostname = $uri.Host

        Write-Verbose "Testing connectivity to $hostname..."

        # Test DNS resolution
        $null = [System.Net.Dns]::GetHostAddresses($hostname)

        # Test HTTPS connectivity
        $response = Invoke-WebRequest -Uri $URL -Method Head -TimeoutSec 5 -ErrorAction Stop

        Write-Verbose "Connectivity test passed: $hostname"
        return $true
    } catch {
        Write-Warning "Connectivity test failed: $($_.Exception.Message)"
        return $false
    }
}
