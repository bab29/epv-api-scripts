#Requires -Version 5.1
<#
.SYNOPSIS
    Logging infrastructure for IdentityAuth module

.DESCRIPTION
    Provides structured logging with levels, timestamps, and optional file output.
    Supports Verbose, Warning, Error, and Debug streams.
#>

$script:LogFile = $null
$script:LogToFile = $false

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
        
        Write-IdentityLog -Message "Logging initialized: $Path" -Level Info
    } catch {
        Write-Warning "Failed to initialize log file: $_"
    }
}

function Disable-IdentityLogFile {
    [CmdletBinding()]
    param()
    
    $script:LogToFile = $false
    $script:LogFile = $null
    Write-Verbose "File logging disabled"
}
