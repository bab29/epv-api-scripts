#Requires -Version 5.1
<#
.SYNOPSIS
    Centralized REST API call wrapper with logging

.DESCRIPTION
    Makes REST API calls using splatting pattern with consistent error handling
    and optional verbose logging.

.PARAMETER Uri
    API endpoint URI

.PARAMETER Method
    HTTP method (Get, Post, Put, Delete)

.PARAMETER Body
    Request body (string or object to be converted to JSON)

.PARAMETER Headers
    Request headers hashtable

.OUTPUTS
    API response object

.EXAMPLE
    $response = Invoke-Rest -Uri $url -Method Post -Body $jsonBody -Headers $headers

.NOTES
    Private function - Internal use only
#>
function Invoke-Rest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [ValidateSet('Get', 'Post', 'Put', 'Delete', 'Patch')]
        [string]$Method,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [hashtable]$Headers
    )

    Write-Verbose "API Call: $Method $Uri"

    $restParams = @{
        Uri         = $Uri
        Method      = $Method
        ContentType = 'application/json'
        TimeoutSec  = 30
    }

    if ($Headers) {
        $restParams.Headers = $Headers
        Write-Verbose "Headers: $(($Headers.Keys | ForEach-Object { "$_=$($Headers[$_])" }) -join ', ')"
    }

    if ($Body) {
        if ($Body -is [string]) {
            $restParams.Body = $Body
        }
        else {
            $restParams.Body = $Body | ConvertTo-Json -Depth 10 -Compress
        }
        Write-Verbose "Body: $($restParams.Body)"
    }

    try {
        $response = Invoke-RestMethod @restParams
        Write-Verbose "Response received: $($response | ConvertTo-Json -Depth 5 -Compress)"
        return $response
    }
    catch {
        Write-Verbose "API Error: $($_.Exception.Message)"
        throw
    }
}
