#Requires -Version 5.1
<#
.SYNOPSIS
    Submits OOBAUTHPIN code for verification

.DESCRIPTION
    Sends user-provided PIN code to Identity for verification.
    Returns authentication token if PIN is correct.
#>

function Submit-OOBAUTHPINCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,
        
        [Parameter(Mandatory)]
        [string]$MechanismId,
        
        [Parameter(Mandatory)]
        [string]$PINCode,
        
        [Parameter(Mandatory)]
        [string]$IdentityTenantURL
    )
    
    Write-Verbose "Submitting OOBAUTHPIN code for verification"
    
    $advanceAuthURL = "$IdentityTenantURL/Security/AdvanceAuthentication"
    $body = @{
        SessionId   = $SessionId
        MechanismId = $MechanismId
        Action      = 'Answer'
        Answer      = $PINCode
    } | ConvertTo-Json -Compress
    
    try {
        Write-Verbose "Verifying PIN code..."
        $response = Invoke-RestMethod -Uri $advanceAuthURL -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop
        
        if ($response.success) {
            Write-Verbose "PIN verification successful"
            
            # Check if we have auth token
            if ($response.Result.Auth) {
                Write-Verbose "Authentication token received"
                return $response.Result.Auth
            } else {
                throw "PIN verification succeeded but no authentication token returned"
            }
        } else {
            throw "PIN verification failed: $($response.Message)"
        }
    } catch {
        Write-Error "Failed to verify OOBAUTHPIN code: $($_.Exception.Message)"
        throw
    }
}
