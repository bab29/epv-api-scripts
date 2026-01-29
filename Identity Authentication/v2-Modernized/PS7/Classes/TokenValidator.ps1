#Requires -Version 7.0
<#
.SYNOPSIS
    Token validator class

.DESCRIPTION
    Validates Identity tokens and extracts claims
#>

class TokenValidator {
    # Validate token format (basic JWT structure check)
    static [bool] ValidateFormat([string]$Token) {
        if ([string]::IsNullOrEmpty($Token)) {
            return $false
        }

        # JWT tokens have 3 parts separated by dots
        $parts = $Token.Split('.')
        return $parts.Count -eq 3
    }

    # Validate token expiry
    static [bool] ValidateExpiry([datetime]$Expiry) {
        return (Get-Date) -lt $Expiry
    }

    # Get token claims (simplified - basic Base64 decode of payload)
    static [hashtable] GetTokenClaims([string]$Token) {
        try {
            $parts = $Token.Split('.')
            if ($parts.Count -ne 3) {
                return @{ Error = 'Invalid token format' }
            }

            # Decode payload (second part)
            $payload = $parts[1]
            # Add padding if needed
            while ($payload.Length % 4 -ne 0) {
                $payload += '='
            }

            $payloadBytes = [Convert]::FromBase64String($payload)
            $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
            $claims = $payloadJson | ConvertFrom-Json

            return @{
                Subject = $claims.sub
                Issuer = $claims.iss
                Audience = $claims.aud
                IssuedAt = $claims.iat
                Expiry = $claims.exp
            }
        } catch {
            return @{ Error = $_.Exception.Message }
        }
    }
}
