#Requires -Version 5.1
<#
.SYNOPSIS
    Initiates OOBAUTHPIN authentication flow

.DESCRIPTION
    Starts OOBAUTHPIN (Out-of-Band Authentication PIN) authentication.
    This sends a PIN to the user's registered device/email for verification.
    Returns session ID and available authentication mechanisms.
#>

function Start-OOBAUTHPINAuthentication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [string]$IdentityTenantURL
    )

    Write-Verbose "Starting OOBAUTHPIN authentication for user: $Username"

    $startAuthURL = "$IdentityTenantURL/Security/StartAuthentication"
    $body = @{
        User    = $Username
        Version = '1.0'
    } | ConvertTo-Json -Compress

    try {
        Write-Verbose "Sending StartAuthentication request..."
        $response = Invoke-RestMethod -Uri $startAuthURL -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop

        if ($response.success -and $response.Result.SessionId) {
            Write-Verbose "Authentication session started. SessionId: $($response.Result.SessionId)"

            return @{
                SessionId  = $response.Result.SessionId
                Challenges = $response.Result.Challenges
                TenantId   = $response.Result.TenantId
            }
        } else {
            throw "StartAuthentication failed or returned no SessionId"
        }
    } catch {
        Write-Error "Failed to start OOBAUTHPIN authentication: $($_.Exception.Message)"
        throw
    }
}
