#Requires -Version 5.1
<#
.SYNOPSIS
    Sends OOBAUTHPIN request to user's registered device

.DESCRIPTION
    Initiates PIN delivery via SMS or Email to user.
    User receives PIN on their registered device/email.
#>

function Send-OOBAUTHPIN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter(Mandatory)]
        [string]$MechanismId,

        [Parameter(Mandatory)]
        [string]$IdentityTenantURL
    )

    Write-Verbose "Sending OOBAUTHPIN to user (MechanismId: $MechanismId)"

    $advanceAuthURL = "$IdentityTenantURL/Security/AdvanceAuthentication"
    $body = @{
        SessionId   = $SessionId
        MechanismId = $MechanismId
        Action      = 'StartOOB'
    } | ConvertTo-Json -Compress

    try {
        Write-Verbose "Requesting PIN delivery..."
        $response = Invoke-RestMethod -Uri $advanceAuthURL -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop

        if ($response.success) {
            Write-Verbose "PIN sent successfully. Summary: $($response.Result.Summary)"
            return $response
        } else {
            throw "Failed to send OOBAUTHPIN: $($response.Message)"
        }
    } catch {
        Write-Error "Failed to send OOBAUTHPIN: $($_.Exception.Message)"
        throw
    }
}
