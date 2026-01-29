#Requires -Version 5.1
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
        $response = Invoke-WebRequest -Uri $pcloudBase -UseBasicParsing -ErrorAction Stop
        Write-Verbose "Response Status: $($response.StatusCode)"
        Write-Verbose "Response Type: $($response.GetType().FullName)"

        # PS5.1: Try different property paths
        if ($response.BaseResponse.ResponseUri) {
            $identityHost = $response.BaseResponse.ResponseUri.Host
            Write-Verbose "Using BaseResponse.ResponseUri.Host"
        }
        elseif ($response.BaseResponse.RequestMessage.RequestUri) {
            $identityHost = $response.BaseResponse.RequestMessage.RequestUri.Host
            Write-Verbose "Using BaseResponse.RequestMessage.RequestUri.Host"
        }
        elseif ($response.Headers.Location) {
            $locationUri = [Uri]$response.Headers.Location
            $identityHost = $locationUri.Host
            Write-Verbose "Using Headers.Location"
        }
        else {
            throw "Could not extract Identity URL from response. Response properties: $($response.PSObject.Properties.Name -join ', ')"
        }
    }
    catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            Write-Verbose "Caught redirect response: $($response.StatusCode)"

            # Try to extract from redirect response
            if ($response.ResponseUri) {
                $identityHost = $response.ResponseUri.Host
            }
            elseif ($response.Headers -and $response.Headers.Location) {
                $locationUri = [Uri]$response.Headers.Location
                $identityHost = $locationUri.Host
            }
            else {
                throw "Failed to extract Identity URL from redirect: $($_.Exception.Message)"
            }
        }
        else {
            throw "Failed to connect to PCloud URL: $($_.Exception.Message)"
        }
    }

    Write-Verbose "Discovered Identity host: $identityHost"

    return "https://$identityHost"
}
