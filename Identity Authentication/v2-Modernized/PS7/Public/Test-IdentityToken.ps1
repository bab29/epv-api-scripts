#Requires -Version 7.0
<#
.SYNOPSIS
    Validates Identity token

.DESCRIPTION
    Validates token format and checks if token is expired.
    Optionally decodes JWT claims using TokenValidator class.

.PARAMETER Token
    Bearer token to validate

.PARAMETER IdentityURL
    Identity tenant URL (optional, for additional validation)

.OUTPUTS
    Boolean - True if token is valid and not expired

.EXAMPLE
    $isValid = Test-IdentityToken -Token $token

.NOTES
    Public function - Exported
#>
function Test-IdentityToken {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter()]
        [string]$IdentityURL
    )

    Write-Verbose "Validating token"

    # Basic format check - JWT should have 3 parts separated by dots
    if ($Token -notmatch '^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$') {
        Write-Verbose "Token format invalid"
        return $false
    }

    try {
        # Decode the payload (second part)
        $tokenParts = $Token.Split('.')
        $payload = $tokenParts[1]

        # Add padding if needed
        $padding = '=' * ((4 - ($payload.Length % 4)) % 4)
        $payload = $payload.Replace('-', '+').Replace('_', '/') + $padding

        # Decode from Base64
        $payloadBytes = [System.Convert]::FromBase64String($payload)
        $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
        $claims = $payloadJson | ConvertFrom-Json

        # Check expiration
        if ($claims.exp) {
            $expiryDate = [DateTimeOffset]::FromUnixTimeSeconds($claims.exp).LocalDateTime
            Write-Verbose "Token expires: $expiryDate"

            if ((Get-Date) -gt $expiryDate) {
                Write-Verbose "Token has expired"
                return $false
            }
        }

        Write-Verbose "Token is valid"
        return $true
    }
    catch {
        Write-Verbose "Token validation error: $($_.Exception.Message)"
        return $false
    }
}
