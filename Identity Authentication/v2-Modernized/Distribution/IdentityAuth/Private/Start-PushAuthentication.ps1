#Requires -Version 5.1
<#
.SYNOPSIS
    Sends Push notification for authentication

.DESCRIPTION
    Initiates push notification to user's mobile device.
    User approves/denies on their device.
#>

function Start-PushAuthentication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter(Mandatory)]
        [string]$MechanismId,

        [Parameter(Mandatory)]
        [string]$IdentityTenantURL,

        [Parameter()]
        [int]$MaxWaitSeconds = 120
    )

    Write-Verbose "Initiating Push authentication"

    $advanceAuthURL = "$IdentityTenantURL/Security/AdvanceAuthentication"

    # Start push
    $startBody = @{
        SessionId   = $SessionId
        MechanismId = $MechanismId
        Action      = 'StartOOB'
    } | ConvertTo-Json -Compress

    try {
        Write-Verbose "Sending push notification..."
        $response = Invoke-RestMethod -Uri $advanceAuthURL -Method Post -Body $startBody -ContentType 'application/json' -ErrorAction Stop

        if ($response.success) {
            Write-Verbose "Push notification sent. Waiting for user approval..."

            Write-Host @"

Push Notification Sent!
========================
Please check your mobile device and approve the authentication request.
Waiting for approval...

"@

            # Poll for response
            $pollBody = @{
                SessionId   = $SessionId
                MechanismId = $MechanismId
                Action      = 'Poll'
            } | ConvertTo-Json -Compress

            $startTime = Get-Date
            $pollResponse = $null

            while (((Get-Date) - $startTime).TotalSeconds -lt $MaxWaitSeconds) {
                Start-Sleep -Seconds 2

                $pollResponse = Invoke-RestMethod -Uri $advanceAuthURL -Method Post -Body $pollBody -ContentType 'application/json' -ErrorAction Stop

                if ($pollResponse.Result.Summary -ne 'OobPending') {
                    break
                }
            }

            if ($pollResponse.Result.Summary -eq 'OobPending') {
                throw "Push authentication timed out after $MaxWaitSeconds seconds"
            }

            if ($pollResponse.success -and $pollResponse.Result.Auth) {
                Write-Verbose "Push authentication approved"
                Write-Host "Push approved!" -ForegroundColor Green
                return $pollResponse.Result.Auth
            } else {
                throw "Push authentication failed: $($pollResponse.Result.Summary)"
            }
        } else {
            throw "Failed to send push notification: $($response.Message)"
        }
    } catch {
        Write-Error "Push authentication error: $($_.Exception.Message)"
        throw
    }
}
