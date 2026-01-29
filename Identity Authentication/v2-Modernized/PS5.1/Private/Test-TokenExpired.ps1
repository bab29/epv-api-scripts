#Requires -Version 5.1
<#
.SYNOPSIS
    Checks if OAuth token needs refresh

.DESCRIPTION
    Determines if cached OAuth token is expired or will expire soon.
    Uses 5-minute buffer to prevent token expiry during API calls.
#>

function Test-TokenExpired {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$ExpiresAt,
        
        [Parameter()]
        [int]$BufferSeconds = 300
    )
    
    $now = Get-Date
    $expiryWithBuffer = $ExpiresAt.AddSeconds(-$BufferSeconds)
    
    $isExpired = $now -ge $expiryWithBuffer
    
    if ($isExpired) {
        Write-Verbose "Token is expired or expires within $BufferSeconds seconds"
    } else {
        $remainingSeconds = ($expiryWithBuffer - $now).TotalSeconds
        Write-Verbose "Token valid for $([Math]::Round($remainingSeconds)) more seconds"
    }
    
    return $isExpired
}
