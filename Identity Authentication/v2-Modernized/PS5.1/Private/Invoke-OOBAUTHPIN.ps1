#Requires -Version 5.1
<#
.SYNOPSIS
    Handles OOBAUTHPIN (SAML + PIN) authentication flow

.DESCRIPTION
    Processes OOBAUTHPIN authentication by:
    1. Displaying short URL for user to complete SAML authentication
    2. Prompting for PIN received via email/SMS
    3. Submitting PIN to complete authentication
    4. Returning token response

.PARAMETER IdaptiveResponse
    StartAuthentication response containing IdpRedirectShortUrl and session IDs

.PARAMETER IdentityURL
    Identity tenant base URL

.PARAMETER PIN
    Optional pre-provided PIN code (for automation scenarios)

.OUTPUTS
    API response object containing authentication token

.EXAMPLE
    $response = Invoke-OOBAUTHPIN -IdaptiveResponse $startAuthResponse -IdentityURL $url

.NOTES
    Private function - Internal use only
    Used by: Get-IdentityHeader (OOBAUTHPIN flow)
#>
function Invoke-OOBAUTHPIN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$IdaptiveResponse,

        [Parameter(Mandatory)]
        [string]$IdentityURL,

        [Parameter()]
        [string]$PIN
    )

    # Extract required session information
    $idpRedirectShortUrl = $IdaptiveResponse.Result.IdpRedirectShortUrl
    $sessionId = $IdaptiveResponse.Result.SessionId
    $idpLoginSessionId = $IdaptiveResponse.Result.IdpLoginSessionId

    Write-Verbose "OOBAUTHPIN Flow Started"
    Write-Verbose "Session ID: $sessionId"
    Write-Verbose "IDP Login Session ID: $idpLoginSessionId"

    if ([string]::IsNullOrEmpty($idpRedirectShortUrl)) {
        throw "IdpRedirectShortUrl is empty. Cannot proceed with OOBAUTHPIN authentication."
    }

    # Display instructions to user
    Write-Host ""
    Write-Host ("=" * 80)
    Write-Host "OOBAUTHPIN Authentication Required"
    Write-Host ("=" * 80)
    Write-Host ""
    Write-Host "Please complete the following steps:"
    Write-Host "  1. Open this URL in your browser: $idpRedirectShortUrl"
    Write-Host "  2. Complete SAML authentication"
    Write-Host "  3. You will receive a PIN code via email or SMS"
    Write-Host "  4. Enter the PIN code below"
    Write-Host ""

    # Attempt to open browser automatically
    try {
        Start-Process $idpRedirectShortUrl -ErrorAction SilentlyContinue
        Write-Host "Browser opened automatically. If not, copy the URL above."
    }
    catch {
        Write-Verbose "Could not auto-open browser: $($_.Exception.Message)"
        Write-Host "Please manually open the URL in your browser."
    }

    Write-Host ""

    # Get PIN from user or parameter
    if ([string]::IsNullOrEmpty($PIN)) {
        $valid = $false
        do {
            $inputValue = Read-Host "Enter PIN code (numbers only)"
            $inputValue = $inputValue.Trim()

            if ($inputValue -match '^\d+$') {
                $pinCode = $inputValue
                $valid = $true
            }
            else {
                Write-Host "Invalid input. Please enter numbers only."
            }
        }
        until ($valid)
    }
    else {
        $pinCode = $PIN
        Write-Verbose "Using provided PIN parameter"
    }

    Write-Verbose "PIN received, submitting to Identity..."

    # Submit PIN to AdvanceAuthentication
    $advanceAuthUrl = "$IdentityURL/Security/AdvanceAuthentication"
    $pinBody = @{
        SessionId   = $idpLoginSessionId
        MechanismId = 'OOBAUTHPIN'
        Action      = 'Answer'
        Answer      = $pinCode
    }

    try {
        $pinResponse = Invoke-Rest -Uri $advanceAuthUrl -Method Post -Body $pinBody
        Write-Verbose "PIN submitted successfully"

        # Check if token received
        if ($pinResponse.success -and $pinResponse.Result.Token) {
            Write-Verbose "OOBAUTHPIN authentication successful"
            return $pinResponse
        }
        elseif ($pinResponse.Result.Challenges) {
            # Additional challenges required
            Write-Verbose "Additional challenges detected after PIN submission"
            throw "Additional challenges after OOBAUTHPIN not yet supported. Response: $($pinResponse | ConvertTo-Json -Depth 5)"
        }
        else {
            throw "PIN authentication failed: $($pinResponse.Message)"
        }
    }
    catch {
        Write-Verbose "PIN submission failed: $($_.Exception.Message)"
        throw "OOBAUTHPIN authentication failed: $($_.Exception.Message)"
    }
}
