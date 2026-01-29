#Requires -Version 5.1
<#
.SYNOPSIS
    Submits OTP (One-Time Password) code

.DESCRIPTION
    Handles Email OTP, SMS OTP, or other text-based OTP verification.
    Returns authentication token on successful verification.
#>

function Submit-OTPCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter(Mandatory)]
        [string]$MechanismId,

        [Parameter(Mandatory)]
        [string]$OTPCode,

        [Parameter(Mandatory)]
        [string]$IdentityTenantURL
    )

    Write-Verbose "Submitting OTP code for verification"

    $advanceAuthURL = "$IdentityTenantURL/Security/AdvanceAuthentication"
    $body = @{
        SessionId   = $SessionId
        MechanismId = $MechanismId
        Action      = 'Answer'
        Answer      = $OTPCode
    } | ConvertTo-Json -Compress

    try {
        Write-Verbose "Verifying OTP..."
        $response = Invoke-RestMethod -Uri $advanceAuthURL -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop

        if ($response.success) {
            if ($response.Result.Auth) {
                Write-Verbose "OTP verification successful"
                return $response.Result.Auth
            } else {
                throw "OTP verification succeeded but no authentication token returned"
            }
        } else {
            throw "OTP verification failed: $($response.Message)"
        }
    } catch {
        Write-Error "OTP verification error: $($_.Exception.Message)"
        throw
    }
}
