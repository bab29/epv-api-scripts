#Requires -Version 7.0
<#
.SYNOPSIS
    Handles AdvanceAuthentication API calls

.DESCRIPTION
    Processes authentication mechanism and submits answer via AdvanceAuthentication endpoint.
    Handles text answers, push notifications with polling, and other challenge types.

.PARAMETER SessionId
    Identity session ID from StartAuthentication

.PARAMETER Mechanism
    Authentication mechanism object containing MechanismId, Name, AnswerType

.PARAMETER IdentityURL
    Identity tenant base URL

.PARAMETER UPCreds
    Optional PSCredential for Username/Password mechanism

.OUTPUTS
    API response object with authentication result

.EXAMPLE
    $response = Invoke-AdvancedAuthBody -SessionId $sessionId -Mechanism $mech -IdentityURL $url

.NOTES
    Private function - Internal use only
    Used by: Invoke-Challenge, OOBAUTHPIN flow
#>
function Invoke-AdvancedAuthBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter(Mandatory)]
        [PSCustomObject]$Mechanism,

        [Parameter(Mandatory)]
        [string]$IdentityURL,

        [Parameter()]
        [PSCredential]$UPCreds
    )

    $mechanismId = $Mechanism.MechanismId
    $advanceAuthUrl = "$IdentityURL/Security/AdvanceAuthentication"

    Write-Verbose "Processing mechanism: $($Mechanism.Name) (Type: $($Mechanism.AnswerType))"

    if ($Mechanism.AnswerType -eq 'StartTextOob') {
        # Push notification flow
        $body = @{
            SessionId   = $SessionId
            MechanismId = $mechanismId
            Action      = 'StartOOB'
        }

        Write-Information 'Waiting for push notification approval...'
        $response = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $body

        # Poll for push approval
        while ($response.Result.Summary -eq 'OobPending') {
            Start-Sleep -Seconds 2
            Write-Information 'Polling for push approval...'

            $pollBody = @{
                SessionId   = $SessionId
                MechanismId = $mechanismId
                Action      = 'Poll'
            }

            $response = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $pollBody
            Write-Verbose "Poll status: $($response.Result.Summary)"
        }

        return $response
    } elseif ($Mechanism.AnswerType -eq 'Text') {
        # Text answer (password, OTP, etc.)
        $action = 'Answer'

        if ($Mechanism.Name -eq 'UP' -and $UPCreds) {
            Write-Information 'Using stored UP credentials'
            $answer = $UPCreds.Password
        } else {
            $promptText = $Mechanism.Name -eq 'UP' ? 'Password' :
            ($Mechanism.Name -eq 'OTP' ? 'OTP code' : 'Answer')
            $answer = Read-Host "Enter $promptText" -AsSecureString
        }

        # Convert SecureString to plain text
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($answer)
        $plainAnswer = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        $body = @{
            SessionId   = $SessionId
            MechanismId = $mechanismId
            Action      = $action
            Answer      = $plainAnswer
        }

        $response = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $body

        # Clear sensitive data
        $plainAnswer = $null
        $body = $null

        return $response
    } else {
        throw "Unsupported AnswerType: $($Mechanism.AnswerType)"
    }
}
