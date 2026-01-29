#Requires -Version 5.1
<#
.SYNOPSIS
    Enable file logging for IdentityAuth module

.DESCRIPTION
    Configures the module to write structured logs to a file.
    All subsequent authentication operations will be logged.

.PARAMETER Path
    The path to the log file. Directory will be created if it doesn't exist.

.PARAMETER Append
    If specified, appends to existing log file. Otherwise, creates new file.

.EXAMPLE
    Set-IdentityLogFile -Path "C:\Logs\identity-auth.log"

.EXAMPLE
    Set-IdentityLogFile -Path "C:\Logs\auth.log" -Append

.NOTES
    Use Disable-IdentityLogFile to turn off file logging.
#>

function Set-IdentityLogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [switch]$Append
    )

    try {
        # Create directory if it doesn't exist
        $directory = Split-Path -Path $Path -Parent
        if ($directory -and -not (Test-Path $directory)) {
            $null = New-Item -Path $directory -ItemType Directory -Force
        }

        # Create or clear file
        if (-not $Append) {
            $null = New-Item -Path $Path -ItemType File -Force
        }

        $script:LogFile = $Path
        $script:LogToFile = $true

        Write-Verbose "File logging enabled: $Path"
    } catch {
        Write-Warning "Failed to initialize log file: $_"
    }
}

Export-ModuleMember -Function Set-IdentityLogFile
