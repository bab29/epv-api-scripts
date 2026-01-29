#Requires -Version 5.1
<#
.SYNOPSIS
    Internal logging function for IdentityAuth module

.DESCRIPTION
    Provides structured logging with levels, timestamps, and optional file output.
    Supports Verbose, Warning, Error, and Debug streams.

.NOTES
    This is an internal function. Use Set-IdentityLogFile and Disable-IdentityLogFile
    to control logging behavior.
#>

# Module-level variables for logging
if (-not (Get-Variable -Name LogFile -Scope Script -ErrorAction SilentlyContinue)) {
    $script:LogFile = $null
}
if (-not (Get-Variable -Name LogToFile -Scope Script -ErrorAction SilentlyContinue)) {
    $script:LogToFile = $false
}

function Write-IdentityLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Verbose', 'Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info',

        [Parameter()]
        [string]$Component = 'IdentityAuth',

        [Parameter()]
        [hashtable]$AdditionalData
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] [$Component] $Message"

    # Add additional data if provided
    if ($AdditionalData) {
        $dataString = ($AdditionalData.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
        $logEntry += " | Data: $dataString"
    }

    # Write to appropriate stream
    switch ($Level) {
        'Verbose' { Write-Verbose $Message }
        'Info'    { Write-Verbose $Message }
        'Warning' { Write-Warning $Message }
        'Error'   { Write-Error $Message }
        'Debug'   { Write-Debug $Message }
    }

    # Write to file if enabled
    if ($script:LogToFile -and $script:LogFile) {
        try {
            Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }
}
