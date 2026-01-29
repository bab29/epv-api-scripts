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
        [string]$IdentityURL
    )

    # TODO: Implementation
    throw "Not yet implemented"
}
