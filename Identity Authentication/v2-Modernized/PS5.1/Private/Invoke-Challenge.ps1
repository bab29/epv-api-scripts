#Requires -Version 5.1
<#
.SYNOPSIS
    Processes authentication challenges from Identity API

.DESCRIPTION
    Iterates through challenges array, presents mechanism options to user,
    and submits answers via AdvanceAuthentication. Handles recursive challenges
    until token is received.

.PARAMETER IdaptiveResponse
    StartAuthentication response containing challenges array

.PARAMETER IdentityURL
    Identity tenant base URL

.PARAMETER UPCreds
    Optional PSCredential for Username/Password authentication

.OUTPUTS
    API response object containing authentication token

.EXAMPLE
    $response = Invoke-Challenge -IdaptiveResponse $startAuthResponse -IdentityURL $url

.NOTES
    Private function - Internal use only
    Used by: Get-IdentityHeader (standard flow)
#>
function Invoke-Challenge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$IdaptiveResponse,

        [Parameter(Mandatory)]
        [string]$IdentityURL,

        [Parameter()]
        [PSCredential]$UPCreds
    )

    $sessionId = $IdaptiveResponse.Result.SessionId
    Write-Verbose "Processing challenges for session: $sessionId"

    $challengeNumber = 1
    $finalResponse = $null

    foreach ($challenge in $IdaptiveResponse.Result.Challenges) {
        Write-Host "Challenge $challengeNumber"
        $mechanisms = $challenge.mechanisms
        $mechanismCount = $mechanisms.Count

        # Select mechanism
        if ($mechanismCount -gt 1) {
            Write-Host "There are $mechanismCount options to choose from:"

            $i = 1
            foreach ($mech in $mechanisms) {
                Write-Host "$i - $($mech.Name) - $($mech.PromptMechChosen)"
                $i++
            }

            $option = $null
            while ($option -gt $mechanismCount -or $option -lt 1 -or $null -eq $option) {
                $userInput = Read-Host "Please enter option number (1-$mechanismCount)"
                try {
                    $option = [int]$userInput
                }
                catch {
                    Write-Host "Invalid input. Please enter a number."
                }
            }

            $selectedMechanism = $mechanisms[$option - 1]
        }
        else {
            $selectedMechanism = $mechanisms[0]
            Write-Host "$($selectedMechanism.Name) - $($selectedMechanism.PromptMechChosen)"
        }

        # Process the selected mechanism
        $advanceAuthParams = @{
            SessionId   = $sessionId
            Mechanism   = $selectedMechanism
            IdentityURL = $IdentityURL
            UPCreds     = $UPCreds
        }
        $finalResponse = Invoke-AdvancedAuthBody @advanceAuthParams

        Write-Verbose "Challenge response: $($finalResponse | ConvertTo-Json -Depth 5 -Compress)"

        # Check if we have a token (successful authentication)
        if ($finalResponse.PSObject.Properties['success'] -and
            $finalResponse.success -and
            $finalResponse.Result.Token) {
            Write-Verbose "Token received successfully"
            return $finalResponse
        }

        $challengeNumber++
    }

    # If we get here, no token was received
    if (-not $finalResponse.success) {
        throw "Authentication failed: $($finalResponse.Message)"
    }

    return $finalResponse
}
