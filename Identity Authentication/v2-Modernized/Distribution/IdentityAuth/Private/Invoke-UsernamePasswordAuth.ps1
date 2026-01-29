#Requires -Version 5.1
<#
.SYNOPSIS
    Username/Password authentication implementation

.DESCRIPTION
    Handles traditional username/password authentication with Identity.
    Returns authentication token on successful login.
#>

function Invoke-UsernamePasswordAuth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter(Mandatory)]
        [string]$MechanismId,

        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$IdentityTenantURL
    )

    Write-Verbose "Authenticating with Username/Password"

    $advanceAuthURL = "$IdentityTenantURL/Security/AdvanceAuthentication"

    # Extract password
    $password = $Credential.GetNetworkCredential().Password

    $body = @{
        SessionId   = $SessionId
        MechanismId = $MechanismId
        Action      = 'Answer'
        Answer      = $password
    } | ConvertTo-Json -Compress

    try {
        Write-Verbose "Submitting password..."
        $response = Invoke-RestMethod -Uri $advanceAuthURL -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop

        if ($response.success) {
            if ($response.Result.Auth) {
                Write-Verbose "Username/Password authentication successful"
                return $response.Result.Auth
            } else {
                # May require additional factors (MFA)
                Write-Verbose "Password accepted, but additional authentication required"
                return $response
            }
        } else {
            throw "Username/Password authentication failed: $($response.Message)"
        }
    } catch {
        Write-Error "Username/Password authentication error: $($_.Exception.Message)"
        throw
    }
}
