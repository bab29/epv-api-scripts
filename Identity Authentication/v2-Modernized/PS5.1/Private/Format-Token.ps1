#Requires -Version 5.1
<#
.SYNOPSIS
    Formats Identity API token response into authorization headers

.DESCRIPTION
    Extracts Bearer token from API response and constructs authorization headers
    for use with CyberArk Privilege Cloud APIs.

.PARAMETER Token
    Raw token string or token response object from Identity API

.OUTPUTS
    Hashtable with Authorization and X-IDAP-NATIVE-CLIENT headers

.EXAMPLE
    $headers = Format-Token -Token $response.access_token

.NOTES
    Private function - Internal use only
#>
function Format-Token {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [object]$Token
    )

    # PS5.1: No ternary operator
    if ($Token -is [string]) {
        $tokenString = $Token
    }
    else {
        $tokenString = $Token.ToString()
    }

    Write-Verbose "Formatting token for authorization header"

    return @{
        'Authorization'        = "Bearer $tokenString"
        'X-IDAP-NATIVE-CLIENT' = 'true'
    }
}
