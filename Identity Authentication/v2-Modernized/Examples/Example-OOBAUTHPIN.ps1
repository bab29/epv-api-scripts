#Requires -Version 5.1
<#
.SYNOPSIS
    Example: OOBAUTHPIN authentication with IdentityAuth module

.DESCRIPTION
    Demonstrates OOBAUTHPIN authentication flow.
    User receives PIN via SMS/Email and enters it for verification.
#>

# Import module
Import-Module '.\Distribution\IdentityAuth\IdentityAuth.psd1' -Force

Write-Host @"
================================================================================
OOBAUTHPIN Authentication Example
================================================================================

This example demonstrates OOBAUTHPIN authentication.
You will need:
- Your CyberArk Identity username
- Access to your registered device/email (for receiving PIN)
- Your Privilege Cloud URL

IMPORTANT: OOBAUTHPIN must be enabled for your user account!

"@

# Get username
$username = Read-Host -Prompt "Enter your CyberArk Identity username"

# Privilege Cloud URL
$pcloudUrl = Read-Host -Prompt "Enter your Privilege Cloud URL (e.g., https://subdomain.cyberark.cloud)"

Write-Host @"

Initiating OOBAUTHPIN authentication...
A PIN will be sent to your registered device/email.

"@

try {
    # Authenticate (user will be prompted for PIN)
    $headers = Get-IdentityHeader -Username $username -PCloudURL $pcloudUrl -Verbose

    Write-Host @"

SUCCESS! Authentication complete.

Headers received:
  Authorization: $($headers.Authorization.Substring(0, 50))...
  X-IDAP-NATIVE-CLIENT: $($headers['X-IDAP-NATIVE-CLIENT'])

Example API Call:
"@

    # Example: Get safes
    $pvwaUrl = $pcloudUrl -replace '\.cyberark\.cloud.*', '.privilegecloud.cyberark.cloud/PasswordVault'
    $safesUrl = "$pvwaUrl/API/Safes?limit=5"

    Write-Host "  Calling: $safesUrl"

    $response = Invoke-RestMethod -Uri $safesUrl -Headers $headers -Method Get

    Write-Host @"

API call successful!
Retrieved $($response.Safes.Count) safes.

Safes:
"@

    $response.Safes | ForEach-Object {
        Write-Host "  - $($_.SafeName)"
    }

    Write-Host @"

================================================================================
OOBAUTHPIN authentication demonstration complete!
================================================================================

"@

} catch {
    Write-Host @"

ERROR: $($_.Exception.Message)

Please check:
- Username is correct
- OOBAUTHPIN is enabled for your account
- You have registered device/email for receiving PINs
- Privilege Cloud URL is correct
- Network connectivity to Identity tenant

================================================================================

"@ -ForegroundColor Red
}
