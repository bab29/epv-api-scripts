#Requires -Version 7.0
<#
.SYNOPSIS
    Discovers Identity URL from Privilege Cloud URL

.DESCRIPTION
    Uses HTTP redirect discovery to find Identity tenant URL from Privilege Cloud URL.
    Makes a request to PCloud and follows redirect to extract Identity subdomain.

.PARAMETER PCloudURL
    Privilege Cloud URL (e.g., https://subdomain.cyberark.cloud)

.OUTPUTS
    String - Identity URL (e.g., https://abc123.id.cyberark.cloud)

.EXAMPLE
    $identityUrl = Get-IdentityURL -PCloudURL 'https://subdomain.cyberark.cloud'

.NOTES
    Public function - Exported
#>
function Get-IdentityURL {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$PCloudURL
    )

    Write-Verbose "Discovering Identity URL from: $PCloudURL"

    $PCloudURL.ToLower() -match '^(?:https|http):\/\/(?<sub>.*)(.privilegecloud).cyberark.(?<top>cloud|com)\/(privilegecloud|passwordvault)(\/?)$' | Out-Null
    $pcloudBase = "https://$($matches['sub']).cyberark.$($matches['top'])"

    Write-Verbose "PCloud base URL: $pcloudBase"

    try {
        $response = Invoke-WebRequest -Uri $pcloudBase -ErrorAction SilentlyContinue
    } catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
        } else {
            throw "Failed to connect to PCloud URL: $($_.Exception.Message)"
        }
    }

    $identityHost = $response.BaseResponse.RequestMessage.RequestUri.Host

    Write-Verbose "Discovered Identity host: $identityHost"

    return "https://$identityHost"
}
