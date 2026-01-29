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

    # TODO: Implementation
    throw "Not yet implemented"
}
