#Requires -Version 5.1
<#
.SYNOPSIS
    Authenticates to CyberArk Identity and returns API headers for Privilege Cloud

.DESCRIPTION
    Provides authentication to CyberArk Identity for Privilege Cloud environments.
    Supports OAuth client credentials authentication flow.
    Returns hashtable with Authorization and X-IDAP-NATIVE-CLIENT headers.

    This function caches OAuth tokens automatically and refreshes them when expired.

.PARAMETER OAuthCreds
    PSCredential containing OAuth Client ID (username) and Client Secret (password).
    Used for OAuth client credentials flow (recommended for automation).

.PARAMETER Username
    Username for interactive authentication (OOBAUTHPIN, UsernamePassword, MFA).
    Used for user-based authentication flows.

.PARAMETER Credential
    PSCredential for Username/Password authentication.
    Password is extracted and sent securely to Identity.

.PARAMETER PINCode
    (Optional) Pre-provided PIN code for OOBAUTHPIN authentication.
    If not provided, user will be prompted after PIN is sent to their device.

.PARAMETER OTPCode
    (Optional) One-Time Password for Email/SMS OTP authentication.
    If not provided, user will be prompted.

.PARAMETER UsePush
    Use Push notification authentication to mobile device.
    User approves/denies on their device.

.PARAMETER PCloudURL
    Privilege Cloud URL. Can be in any of these formats:
    - https://subdomain.privilegecloud.cyberark.cloud
    - https://subdomain.cyberark.cloud
    - subdomain.privilegecloud.cyberark.cloud

    The /PasswordVault suffix is added automatically if missing.

.PARAMETER IdentityURL
    (Optional) Identity tenant URL. If not provided, it will be derived from PCloudURL.
    Format: https://subdomain.id.cyberark.cloud

.PARAMETER Force
    Forces new authentication even if valid cached token exists.
    Use when you need to refresh the token before it expires.

.OUTPUTS
    System.Collections.Hashtable
    Returns hashtable with two keys:
    - Authorization: "Bearer <token>"
    - X-IDAP-NATIVE-CLIENT: "true"

    This hashtable can be used directly with Invoke-RestMethod -Headers parameter.

.EXAMPLE
    # OAuth authentication (recommended)
    $creds = Get-Credential -Message "ClientID (Username) and ClientSecret (Password)"
    $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://tenant.cyberark.cloud"

    # Use headers with any PCloud API call
    $accounts = Invoke-RestMethod -Uri "https://tenant.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts" -Headers $headers

.EXAMPLE
    # With Accounts_Onboard_Utility.ps1
    $creds = Get-Credential
    $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://tenant.cyberark.cloud"
    .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://tenant.privilegecloud.cyberark.cloud" -logonToken $headers

.EXAMPLE
    # Force token refresh
    $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url -Force

.EXAMPLE
    # OOBAUTHPIN authentication (interactive)
    $headers = Get-IdentityHeader -Username "user@domain.com" -PCloudURL "https://tenant.cyberark.cloud"
    # User will be prompted to enter PIN sent to their device

.EXAMPLE
    # OOBAUTHPIN with pre-provided PIN
    $headers = Get-IdentityHeader -Username "user@domain.com" -PINCode "123456" -PCloudURL "https://tenant.cyberark.cloud"

.EXAMPLE
    # Username/Password authentication
    $creds = Get-Credential
    $headers = Get-IdentityHeader -Username $creds.UserName -Credential $creds -PCloudURL "https://tenant.cyberark.cloud"

.EXAMPLE
    # Email/SMS OTP authentication
    $headers = Get-IdentityHeader -Username "user@domain.com" -OTPCode "987654" -PCloudURL "https://tenant.cyberark.cloud"

.EXAMPLE
    # Push notification authentication
    $headers = Get-IdentityHeader -Username "user@domain.com" -UsePush -PCloudURL "https://tenant.cyberark.cloud"

.NOTES
    Version:        2.0.0
    Author:         CyberArk
    Creation Date:  2026-01-28

    Requirements:
    - PowerShell 5.1 or later
    - Network access to Identity tenant
    - Valid credentials for chosen auth method

    Supported Authentication Methods:
    - OAuth (Client Credentials) - Recommended for automation
    - OOBAUTHPIN - PIN sent to device/email
    - Username/Password - Traditional credentials
    - Email/SMS OTP - One-time password
    - Push - Mobile device approval

    Security Notes:
    - OAuth tokens are cached in memory only (not persisted to disk)
    - Tokens auto-refresh 5 minutes before expiry
    - Use -Force to manually refresh token if needed
#>

function Get-IdentityHeader {
    [CmdletBinding(DefaultParameterSetName = 'OAuth')]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'OAuth')]
        [PSCredential]$OAuthCreds,

        [Parameter(Mandatory, ParameterSetName = 'OOBAUTHPIN')]
        [Parameter(Mandatory, ParameterSetName = 'UsernamePassword')]
        [Parameter(Mandatory, ParameterSetName = 'OTP')]
        [Parameter(Mandatory, ParameterSetName = 'Push')]
        [string]$Username,

        [Parameter(ParameterSetName = 'OOBAUTHPIN')]
        [string]$PINCode,

        [Parameter(Mandatory, ParameterSetName = 'UsernamePassword')]
        [PSCredential]$Credential,

        [Parameter(ParameterSetName = 'OTP')]
        [string]$OTPCode,

        [Parameter(Mandatory, ParameterSetName = 'Push')]
        [switch]$UsePush,

        [Parameter(Mandatory)]
        [string]$PCloudURL,

        [Parameter()]
        [string]$IdentityURL,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Write-Verbose 'Starting Get-IdentityHeader'
        $ErrorActionPreference = 'Stop'

        # Normalize PCloud URL
        $normalizedPCloudURL = Get-NormalizedPCloudURL -PCloudURL $PCloudURL
        Write-Verbose "Normalized PCloud URL: $normalizedPCloudURL"

        # Derive or validate Identity URL
        if (-not $IdentityURL) {
            $IdentityURL = Get-IdentityURLFromPCloud -PCloudURL $normalizedPCloudURL
            Write-Verbose "Derived Identity URL: $IdentityURL"
        } else {
            Write-Verbose "Using provided Identity URL: $IdentityURL"
        }
    }

    process {
        try {
            # Check for cached token (OAuth only)
            if ($PSCmdlet.ParameterSetName -eq 'OAuth' -and -not $Force) {
                if ($script:OAuthTokenCache -and $script:TokenExpiry) {
                    $isExpired = Test-TokenExpired -ExpiresAt $script:TokenExpiry

                    if (-not $isExpired) {
                        Write-Verbose "Using cached OAuth token"
                        $headers = Format-IdentityHeaders -AccessToken $script:OAuthTokenCache
                        return $headers
                    } else {
                        Write-Verbose "Cached token expired, requesting new token"
                    }
                }
            }

            # OAuth authentication
            if ($PSCmdlet.ParameterSetName -eq 'OAuth') {
                Write-Verbose "Authenticating with OAuth"

                $tokenResponse = Get-OAuthToken -OAuthCreds $OAuthCreds -IdentityTenantURL $IdentityURL

                # Cache token
                $script:OAuthTokenCache = $tokenResponse.AccessToken
                $script:TokenExpiry = $tokenResponse.ExpiresAt

                Write-Verbose "OAuth token cached, expires at: $($script:TokenExpiry)"

                # Format headers
                $headers = Format-IdentityHeaders -AccessToken $tokenResponse.AccessToken

                return $headers
            }

            # OOBAUTHPIN authentication
            if ($PSCmdlet.ParameterSetName -eq 'OOBAUTHPIN') {
                Write-Verbose "Authenticating with OOBAUTHPIN"

                # Start authentication
                $authSession = Start-OOBAUTHPINAuthentication -Username $Username -IdentityTenantURL $IdentityURL

                # Find OOBAUTHPIN mechanism
                $mechanism = Get-OOBAUTHPINMechanism -Challenges $authSession.Challenges

                # Send PIN to user
                Write-Verbose "Sending PIN to user's registered device..."
                $null = Send-OOBAUTHPIN -SessionId $authSession.SessionId -MechanismId $mechanism.MechanismId -IdentityTenantURL $IdentityURL

                Write-Host @"

OOBAUTHPIN Code Sent!
=====================
A PIN code has been sent to your registered device/email.
Please check your device and enter the PIN code below.

"@

                # Get PIN from user if not provided
                if (-not $PINCode) {
                    $PINCode = Read-Host -Prompt "Enter PIN code"
                }

                # Submit PIN
                $authToken = Submit-OOBAUTHPINCode -SessionId $authSession.SessionId -MechanismId $mechanism.MechanismId -PINCode $PINCode -IdentityTenantURL $IdentityURL

                Write-Verbose "OOBAUTHPIN authentication successful"

                # Format headers
                $headers = Format-IdentityHeaders -AccessToken $authToken

                return $headers
            }

            # Username/Password authentication
            if ($PSCmdlet.ParameterSetName -eq 'UsernamePassword') {
                Write-Verbose "Authenticating with Username/Password"

                # Start authentication
                $authSession = Start-OOBAUTHPINAuthentication -Username $Username -IdentityTenantURL $IdentityURL

                # Find Username/Password mechanism
                $mechanism = Get-AuthenticationMechanism -Challenges $authSession.Challenges -AnswerType 'UP'

                # Submit password
                $authToken = Invoke-UsernamePasswordAuth -SessionId $authSession.SessionId -MechanismId $mechanism.MechanismId -Credential $Credential -IdentityTenantURL $IdentityURL

                Write-Verbose "Username/Password authentication successful"

                # Format headers
                $headers = Format-IdentityHeaders -AccessToken $authToken

                return $headers
            }

            # OTP authentication
            if ($PSCmdlet.ParameterSetName -eq 'OTP') {
                Write-Verbose "Authenticating with OTP"

                # Start authentication
                $authSession = Start-OOBAUTHPINAuthentication -Username $Username -IdentityTenantURL $IdentityURL

                # Find OTP mechanism
                $mechanism = Get-AuthenticationMechanism -Challenges $authSession.Challenges -AnswerType 'Text'

                # Get OTP from user if not provided
                if (-not $OTPCode) {
                    Write-Host @"

OTP Authentication
==================
An OTP code has been sent to your registered email/phone.
Please enter the code below.

"@
                    $OTPCode = Read-Host -Prompt "Enter OTP code"
                }

                # Submit OTP
                $authToken = Submit-OTPCode -SessionId $authSession.SessionId -MechanismId $mechanism.MechanismId -OTPCode $OTPCode -IdentityTenantURL $IdentityURL

                Write-Verbose "OTP authentication successful"

                # Format headers
                $headers = Format-IdentityHeaders -AccessToken $authToken

                return $headers
            }

            # Push authentication
            if ($PSCmdlet.ParameterSetName -eq 'Push') {
                Write-Verbose "Authenticating with Push"

                # Start authentication
                $authSession = Start-OOBAUTHPINAuthentication -Username $Username -IdentityTenantURL $IdentityURL

                # Find Push mechanism
                $mechanism = Get-AuthenticationMechanism -Challenges $authSession.Challenges -AnswerType 'StartOob'

                # Start push and wait for approval
                $authToken = Start-PushAuthentication -SessionId $authSession.SessionId -MechanismId $mechanism.MechanismId -IdentityTenantURL $IdentityURL

                Write-Verbose "Push authentication successful"

                # Format headers
                $headers = Format-IdentityHeaders -AccessToken $authToken

                return $headers
            }
        } catch {
            Write-Error "Authentication failed: $($_.Exception.Message)"
            throw
        }
    }

    end {
        Write-Verbose 'Get-IdentityHeader completed'
    }
}
