#Requires -Version 5.1
<#
.SYNOPSIS
    Masks sensitive data in logs and error messages

.DESCRIPTION
    Redacts tokens, passwords, and other sensitive information for safe logging.
#>

function Hide-SensitiveData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text,
        
        [Parameter()]
        [ValidateSet('Token', 'Password', 'ClientSecret', 'PIN', 'OTP')]
        [string]$DataType = 'Token'
    )
    
    switch ($DataType) {
        'Token' {
            # Mask bearer tokens (show first 10 chars only)
            if ($Text -match '^Bearer\s+(.+)$') {
                $token = $Matches[1]
                if ($token.Length -gt 20) {
                    return "Bearer $($token.Substring(0, 10))...$($token.Substring($token.Length - 4))"
                }
            }
            return $Text
        }
        'Password' {
            return '***REDACTED***'
        }
        'ClientSecret' {
            return '***REDACTED***'
        }
        'PIN' {
            if ($Text.Length -gt 2) {
                return "$($Text.Substring(0, 1))***$($Text.Substring($Text.Length - 1))"
            }
            return '***'
        }
        'OTP' {
            if ($Text.Length -gt 2) {
                return "$($Text.Substring(0, 1))***$($Text.Substring($Text.Length - 1))"
            }
            return '***'
        }
    }
    
    return $Text
}

function Get-SafeErrorMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    
    $message = $ErrorRecord.Exception.Message
    
    # Mask common sensitive patterns
    $message = $message -replace 'Bearer\s+[A-Za-z0-9\-._~+/]+', 'Bearer ***REDACTED***'
    $message = $message -replace 'password["\s:=]+[^"\s,}]+', 'password ***REDACTED***'
    $message = $message -replace 'client_secret["\s:=]+[^"\s,}]+', 'client_secret ***REDACTED***'
    
    return $message
}
