#Requires -Version 5.1
<#
.SYNOPSIS
    Example: OAuth authentication with IdentityAuth module

.DESCRIPTION
    Demonstrates OAuth client credentials authentication flow.
    Shows token caching and automatic refresh.
#>

# Import module
Import-Module '.\Distribution\IdentityAuth\IdentityAuth.psd1' -Force

Write-Host @"
================================================================================
OAuth Authentication Example
================================================================================

This example demonstrates OAuth client credentials authentication.
You will need:
- OAuth Client ID
- OAuth Client Secret
- Your Privilege Cloud URL

"@

# Get credentials
$oauthCreds = Get-Credential -Message "Enter OAuth Client ID (Username) and Client Secret (Password)"

# Privilege Cloud URL
$pcloudUrl = Read-Host -Prompt "Enter your Privilege Cloud URL (e.g., https://subdomain.cyberark.cloud)"

Write-Host @"

Authenticating...
"@

try {
    # Authenticate
    $headers = Get-IdentityHeader -OAuthCreds $oauthCreds -PCloudURL $pcloudUrl -Verbose

    Write-Host @"

SUCCESS! Authentication headers received.

Headers:
  Authorization: $($headers.Authorization.Substring(0, 50))...
  X-IDAP-NATIVE-CLIENT: $($headers['X-IDAP-NATIVE-CLIENT'])

Token is cached and will be reused for subsequent calls.

Example API Call:
"@

    # Example: Get account count
    $pvwaUrl = $pcloudUrl -replace '\.cyberark\.cloud.*', '.privilegecloud.cyberark.cloud/PasswordVault'
    $accountsUrl = "$pvwaUrl/API/Accounts?limit=1"

    Write-Host "  Calling: $accountsUrl"

    $response = Invoke-RestMethod -Uri $accountsUrl -Headers $headers -Method Get

    Write-Host @"

API call successful!
Total accounts in vault: $($response.count)

Token Caching Demo:
"@

    # Second call uses cached token
    Write-Host "  Making second call (should use cached token)..."
    $headers2 = Get-IdentityHeader -OAuthCreds $oauthCreds -PCloudURL $pcloudUrl -Verbose

    Write-Host @"

Second call completed (token was cached)!

Force Refresh Demo:
"@

    # Force refresh
    Write-Host "  Forcing token refresh with -Force parameter..."
    $headers3 = Get-IdentityHeader -OAuthCreds $oauthCreds -PCloudURL $pcloudUrl -Force -Verbose

    Write-Host @"

Token forcefully refreshed!

================================================================================
OAuth authentication demonstration complete!
================================================================================

"@

} catch {
    Write-Host @"

ERROR: $($_.Exception.Message)

Please check:
- OAuth credentials are correct
- Privilege Cloud URL is correct
- Network connectivity to Identity tenant

================================================================================

"@ -ForegroundColor Red
}
