# CyberArk Identity Authentication Module

**Status:** ✅ Production Ready
**Version:** 2.0.0
**PowerShell Compatibility:** 5.1+ (IdentityAuth.psm1) | 7.0+ (IdentityAuth7.psm1)

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207.0%2B-blue)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)

PowerShell module for authenticating to CyberArk Identity Security Platform with support for OAuth, MFA, and OOBAUTHPIN (SAML+PIN) flows.

---

## Features

- ✅ **Multiple Authentication Methods**
  - OAuth client credentials
  - Username/Password
  - MFA (OTP, Push notifications, SMS, Email)
  - OOBAUTHPIN (SAML + PIN)

- ✅ **Session Management**
  - Automatic token caching
  - Token expiry detection
  - Reusable sessions across multiple API calls

- ✅ **Dual PowerShell Support**
  - **IdentityAuth.psm1**: PowerShell 5.1+ (Windows-compatible)
  - **IdentityAuth7.psm1**: PowerShell 7.0+ (Cross-platform with classes/enums)

- ✅ **Security**
  - No plaintext credential storage
  - Secure credential handling with PSCredential
  - In-memory only token storage

---

## Quick Start

### Installation

```powershell
# Download the module
cd ".\Identity Authentication\v2-Modernized\Distribution"

# PowerShell 5.1 (Windows)
Import-Module .\IdentityAuth.psd1

# PowerShell 7+ (Windows/Linux/macOS)
Import-Module .\IdentityAuth7.psd1
```

### Basic Usage

#### OAuth Authentication

```powershell
# Create OAuth credentials
$clientId = 'your-client-id'
$clientSecret = 'your-client-secret' | ConvertTo-SecureString -AsPlainText -Force
$oauthCreds = New-Object PSCredential($clientId, $clientSecret)

# Authenticate and get token
$headers = Get-IdentityHeader -OAuthCreds $oauthCreds -PCloudURL 'https://subdomain.cyberark.cloud'

# Use headers with other scripts
.\Accounts_Onboard_Utility.ps1 -logonToken $headers -PVWAURL $PCloudURL -CSVFile accounts.csv
```

#### Interactive Authentication (Username/Password)

```powershell
# Prompt for credentials
$upCreds = Get-Credential -Message "Enter CyberArk credentials"

# Authenticate with MFA prompts
$headers = Get-IdentityHeader -UPCreds $upCreds -PCloudURL 'https://subdomain.cyberark.cloud'
```

#### OOBAUTHPIN (SAML + PIN)

```powershell
# Authenticate with SAML + PIN
$headers = Get-IdentityHeader -IdentityUserName 'user@company.com' -PCloudURL 'https://subdomain.cyberark.cloud'

# If PIN is already known
$headers = Get-IdentityHeader -IdentityUserName 'user@company.com' -PIN '123456' -PCloudURL 'https://subdomain.cyberark.cloud'
```

---

## Authentication Flows

### 1. OAuth Flow
Best for: Automation, service accounts, CI/CD pipelines

```powershell
$oauthCreds = New-Object PSCredential('client-id', ('client-secret' | ConvertTo-SecureString -AsPlainText -Force))
$headers = Get-IdentityHeader -OAuthCreds $oauthCreds -PCloudURL $PCloudURL
```

**Returns:** Hashtable with `Authorization` and `X-IDAP-NATIVE-CLIENT` headers

### 2. Username/Password with MFA
Best for: Interactive sessions with MFA

```powershell
$upCreds = Get-Credential
$headers = Get-IdentityHeader -UPCreds $upCreds -PCloudURL $PCloudURL
```

**Supports:** OTP codes, Push notifications, SMS, Email verification

### 3. OOBAUTHPIN (SAML + PIN)
Best for: SAML-configured tenants requiring PIN verification

```powershell
$headers = Get-IdentityHeader -IdentityUserName 'user@domain.com' -PCloudURL $PCloudURL
```

**Flow:**
1. Displays SAML authentication URL
2. User completes SAML login in browser
3. PIN code received via email/SMS
4. User enters PIN in PowerShell prompt
5. Returns authentication headers

---

## Session Management

### Reusing Sessions

```powershell
# First authentication
$headers1 = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $PCloudURL

# Reuses cached session (no new authentication)
$headers2 = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $PCloudURL

# Force new authentication
$headers3 = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $PCloudURL -ForceNewSession
```

### Check Session Status

```powershell
# Get current session details
$session = Get-IdentitySession

# Check token expiry
Write-Host "Token expires: $($session.TokenExpiry)"
Write-Host "Is expired: $($session.IsExpired())"
```

### Clear Session

```powershell
# Logout and clear session
Clear-IdentitySession

# Clear session without logging out
Clear-IdentitySession -NoLogout
```

---

## Return Value

All authentication functions return a **hashtable** with CyberArk API headers:

```powershell
@{
    Authorization        = "Bearer eyJhbGc..."
    X-IDAP-NATIVE-CLIENT = "true"
}
```

**Usage with other scripts:**

```powershell
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $PCloudURL

# Use with any script that accepts -logonToken
.\Accounts_Onboard_Utility.ps1 -logonToken $headers -PVWAURL $PCloudURL

# Use with Invoke-RestMethod
Invoke-RestMethod -Uri $apiUrl -Headers $headers
```

---

## Parameters

### Get-IdentityHeader

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `IdentityUserName` | String | Yes* | Username for interactive authentication |
| `UPCreds` | PSCredential | Yes* | Credentials for UP authentication |
| `OAuthCreds` | PSCredential | Yes* | OAuth client ID (username) and secret (password) |
| `PIN` | String | No | Pre-provided PIN for OOBAUTHPIN flow |
| `PCloudURL` | String | Yes | Privilege Cloud URL |
| `IdentityTenantURL` | String | No | Identity URL (auto-discovered if not provided) |
| `ForceNewSession` | Switch | No | Force new authentication (ignore cached session) |

*One of `IdentityUserName`, `UPCreds`, or `OAuthCreds` is required

---

## Examples

### Example 1: OAuth with EPV-API-Common Module

```powershell
Import-Module EPV-API-Common
Import-Module IdentityAuth7

# Authenticate to Identity
$oauthCreds = Get-Credential -Message "Enter OAuth credentials"
$headers = Get-IdentityHeader -OAuthCreds $oauthCreds -PCloudURL 'https://subdomain.cyberark.cloud'

# Use with EPV-API-Common functions
$pvwaSession = New-PASSession -BaseURI 'https://subdomain.cyberark.cloud' -IdentityHeaders $headers
Get-PASAccount -search "admin"
```

### Example 2: Accounts Onboard Utility

```powershell
# Authenticate once
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL 'https://subdomain.cyberark.cloud'

# Use token with Accounts Onboard Utility
.\Accounts_Onboard_Utility.ps1 `
    -PVWAURL 'https://subdomain.cyberark.cloud' `
    -logonToken $headers.Authorization `
    -CSVFile "accounts.csv"
```

### Example 3: MFA Push Notification

```powershell
$upCreds = Get-Credential -Message "Enter username and password"
$headers = Get-IdentityHeader -UPCreds $upCreds -PCloudURL 'https://subdomain.cyberark.cloud'

# Output:
# Challenge 1
# There are 2 options to choose from:
#   1 - UP - Enter Password
#   2 - PF - Approve Login from CyberArk Mobile App
# Please enter option number (1-2): 2
# Waiting for push notification approval...
```

### Example 4: OOBAUTHPIN with Pre-Provided PIN

```powershell
# Useful for automation when PIN is retrieved programmatically
$pin = Get-PINFromSMS  # Your custom function to retrieve PIN
$headers = Get-IdentityHeader -IdentityUserName 'user@company.com' -PIN $pin -PCloudURL 'https://subdomain.cyberark.cloud'
```

---

## Troubleshooting

### "Invalid URI: The hostname could not be parsed"

**Cause:** Identity URL discovery failed

**Solution:** Provide `-IdentityTenantURL` explicitly:

```powershell
$headers = Get-IdentityHeader -OAuthCreds $creds `
    -PCloudURL 'https://subdomain.cyberark.cloud' `
    -IdentityTenantURL 'https://abc123.id.cyberark.cloud'
```

### "PropertyNotFoundException" errors

**Cause:** Using old cached module after rebuild

**Solution:** Reimport the module:

```powershell
Remove-Module IdentityAuth* -Force -ErrorAction SilentlyContinue
Import-Module .\IdentityAuth7.psd1 -Force
```

### Headers not working with other scripts

**Cause:** Incompatible script expecting different format

**Solution:** Ensure script supports Privilege Cloud authentication:

```powershell
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $PCloudURL
.\Script.ps1 -logonToken $headers -PVWAURL $PCloudURL
```

**Note:** All scripts in epv-api-scripts repository accept the hashtable format.

---

## PowerShell 5.1 vs 7+ Differences

| Feature | PS 5.1 (IdentityAuth) | PS 7+ (IdentityAuth7) |
|---------|----------------------|----------------------|
| Session Object | Hashtable | Class (IdentitySession) |
| Enums | Strings | Enums (AuthenticationMechanism) |
| Type Safety | Basic | Enhanced with classes |
| Syntax | Traditional if/else | Ternary operators, null coalescing |
| Performance | Standard | Slightly faster |
| Compatibility | Windows only | Cross-platform |

**Both versions have identical functionality and return the same results.**

---

## Requirements

- PowerShell 5.1+ (IdentityAuth.psm1) or PowerShell 7.0+ (IdentityAuth7.psm1)
- Network access to CyberArk Identity and Privilege Cloud
- Valid CyberArk credentials (OAuth or user account)

---

## Documentation

- [Architecture Design](Documentation/ARCHITECTURE-DESIGN.md) - Detailed architecture and flow diagrams
- [Developer Guide](Documentation/DEVELOPER-GUIDE.md) - Contributing and development setup
- [Migration Guide](Documentation/MIGRATION-GUIDE.md) - Migrating from v1 module

---

## License

Apache License 2.0 - See [LICENSE](../../LICENSE) for details

---

## Support

For issues and feature requests, please open an issue in the GitHub repository.

---

**Last Updated:** 2026-01-28
**Version:** 2.0.0
