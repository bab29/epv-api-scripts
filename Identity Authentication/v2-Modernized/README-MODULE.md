# IdentityAuth Module v2.0

**Complete CyberArk Identity authentication solution for Privilege Cloud with support for all MFA methods.**

## Features

✅ **5 Authentication Methods**
- OAuth (Client Credentials) - Automation
- OOBAUTHPIN - PIN to device/email
- Username/Password - Traditional credentials
- Email/SMS OTP - One-time password
- Push Notification - Mobile approval

✅ **Automatic Token Management**
- Token caching (OAuth)
- Auto-refresh 5 minutes before expiry
- Manual refresh with `-Force`

✅ **Dual PowerShell Versions**
- PowerShell 5.1+ (hashtables, traditional)
- PowerShell 7+ (classes, enums, type safety)

✅ **Enterprise Features**
- Structured logging with file output
- Enhanced error handling with troubleshooting hints
- Sensitive data masking
- Network connectivity validation
- PSScriptAnalyzer compliant (zero violations)

✅ **100% Backward Compatible**
- Works with existing Accounts_Onboard_Utility.ps1
- Drop-in replacement for v1
- Same return value format

## Quick Start

### OAuth Authentication (Recommended for Automation)

```powershell
# Import module
Import-Module IdentityAuth

# Get OAuth credentials
$creds = Get-Credential -Message "OAuth ClientID (Username) and ClientSecret (Password)"

# Authenticate
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://subdomain.cyberark.cloud"

# Use with any PCloud API
$accounts = Invoke-RestMethod `
    -Uri "https://subdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts" `
    -Headers $headers

# Token is cached - subsequent calls reuse it automatically
$safes = Invoke-RestMethod `
    -Uri "https://subdomain.privilegecloud.cyberark.cloud/PasswordVault/API/Safes" `
    -Headers $headers
```

### OOBAUTHPIN Authentication (Interactive)

```powershell
# User receives PIN on registered device/email
$headers = Get-IdentityHeader -Username "user@domain.com" -PCloudURL "https://subdomain.cyberark.cloud"
# Prompts: Enter PIN code: ______
```

### Username/Password Authentication

```powershell
$creds = Get-Credential
$headers = Get-IdentityHeader -Username $creds.UserName -Credential $creds -PCloudURL "https://subdomain.cyberark.cloud"
```

### Email/SMS OTP Authentication

```powershell
$headers = Get-IdentityHeader -Username "user@domain.com" -OTPCode "987654" -PCloudURL "https://subdomain.cyberark.cloud"
```

### Push Notification Authentication

```powershell
$headers = Get-IdentityHeader -Username "user@domain.com" -UsePush -PCloudURL "https://subdomain.cyberark.cloud"
# Waits for user to approve on mobile device
```

## Integration with Existing Scripts

### With Accounts_Onboard_Utility.ps1

```powershell
# Get headers
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://subdomain.cyberark.cloud"

# Pass to AOU
.\Accounts_Onboard_Utility.ps1 `
    -PVWAURL "https://subdomain.privilegecloud.cyberark.cloud" `
    -logonToken $headers `
    -CsvPath "accounts.csv"
```

### In Custom Scripts

```powershell
# Authenticate once
$headers = Get-IdentityHeader -OAuthCreds $oauthCreds -PCloudURL $pcloudUrl

# Use in multiple API calls
$accounts = Invoke-RestMethod -Uri "$pvwaUrl/API/Accounts" -Headers $headers
$safes = Invoke-RestMethod -Uri "$pvwaUrl/API/Safes" -Headers $headers
$users = Invoke-RestMethod -Uri "$pvwaUrl/API/Users" -Headers $headers
```

## Advanced Features

### Enable File Logging

```powershell
# Enable logging before authentication
Set-IdentityLogFile -Path "C:\Logs\identity-auth.log"

# All operations now logged to file
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url -Verbose

# Disable when done
Disable-IdentityLogFile
```

### Force Token Refresh

```powershell
# Get new token even if cached token is valid
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url -Force
```

### Error Handling

```powershell
try {
    $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url
} catch {
    # Enhanced error with troubleshooting hints
    Write-Host "Error: $($_.Exception.Message)"
    if ($_.CategoryInfo.Category -eq 'AuthenticationError') {
        Write-Host "Recommended: Verify credentials and user permissions"
    }
}
```

## Installation

### Method 1: Manual Installation

```powershell
# Build module
.\Build\Build-PS51Module.ps1

# Copy to user modules
Copy-Item .\Distribution\IdentityAuth -Destination "$env:USERPROFILE\Documents\PowerShell\Modules" -Recurse

# Import
Import-Module IdentityAuth
```

### Method 2: VS Code Tasks

```
Ctrl+Shift+B → Build: PS5.1 Module
Ctrl+Shift+P → Tasks: Run Task → Deploy: Install to User Modules
```

### Method 3: System-wide (Requires Admin)

```powershell
# Use VS Code task
Tasks: Run Task → Deploy: Install to System Modules

# Or manually
Copy-Item .\Distribution\IdentityAuth -Destination "$env:ProgramFiles\PowerShell\Modules" -Recurse
```

## Requirements

- **PowerShell:** 5.1 or 7+
- **Network:** HTTPS access to Identity tenant
- **Credentials:** Valid OAuth or user credentials
- **Modules:** None (self-contained)

## Authentication Method Comparison

| Method | Use Case | Interactive | MFA Required | Automation |
|--------|----------|-------------|--------------|------------|
| **OAuth** | Scripts, automation | ❌ No | ❌ No | ✅ Best |
| **OOBAUTHPIN** | Interactive login | ✅ Yes | ✅ Yes | ❌ Limited |
| **Username/Password** | Simple login | ✅ Yes | Depends | ⚠️ Possible |
| **Email/SMS OTP** | MFA verification | ✅ Yes | ✅ Yes | ⚠️ Possible |
| **Push** | Mobile approval | ✅ Yes | ✅ Yes | ❌ No |

**Recommendation:** Use OAuth for automation, OOBAUTHPIN/Push for interactive scenarios.

## Return Value

All methods return the same hashtable format:

```powershell
@{
    Authorization = "Bearer eyJhbGciOiJSUzI1NiIs..."
    'X-IDAP-NATIVE-CLIENT' = 'true'
}
```

This can be used directly with `Invoke-RestMethod -Headers`:

```powershell
Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get
```

## Examples

See [Examples](Examples/) directory for complete working examples:
- [Example-OAuth.ps1](Examples/Example-OAuth.ps1) - OAuth with API calls
- [Example-OOBAUTHPIN.ps1](Examples/Example-OOBAUTHPIN.ps1) - Interactive PIN auth

## Documentation

- [Implementation Plan](Documentation/IMPLEMENTATION-PLAN.md) - Development roadmap
- [Architecture Design](Documentation/ARCHITECTURE-DESIGN.md) - Technical design
- [Migration Guide](Documentation/MIGRATION-GUIDE.md) - Upgrade from v1
- [Testing Results](Documentation/TESTING-RESULTS.md) - Live test validation

## Testing

```powershell
# Run Pester tests
Invoke-Pester -Path .\Tests\Pester\

# Test PSScriptAnalyzer compliance
Invoke-ScriptAnalyzer -Path .\PS5.1 -Settings .\PSScriptAnalyzerSettings.psd1 -Recurse
```

## Troubleshooting

### Module Not Found

```powershell
# Check module path
$env:PSModulePath -split ';'

# List available modules
Get-Module -ListAvailable IdentityAuth

# Force reimport
Remove-Module IdentityAuth -Force -ErrorAction SilentlyContinue
Import-Module IdentityAuth -Force
```

### OAuth Errors

```powershell
# Verify credentials
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url -Verbose

# Check connectivity
Test-NetConnection subdomain.id.cyberark.cloud -Port 443

# Test with curl
curl https://subdomain.id.cyberark.cloud/oauth2/platformtoken/
```

### OOBAUTHPIN Not Available

OOBAUTHPIN must be enabled in Identity admin portal:
1. Login to Identity admin portal
2. Settings → Authentication
3. Enable OOBAUTHPIN for user/group
4. Configure delivery method (SMS/Email)

### Token Expiry

Tokens auto-refresh 5 minutes before expiry. To manually refresh:

```powershell
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url -Force
```

## Support

- **Issues:** GitHub Issues
- **Documentation:** This README and Documentation/ folder
- **Examples:** Examples/ folder
- **Tests:** Tests/Pester/ folder

## Version History

### v2.0.0 (2026-01-28)
- Complete rewrite
- Added OOBAUTHPIN, OTP, Push, Username/Password
- OAuth token caching and auto-refresh
- Dual PowerShell 5.1/7+ support
- Enhanced logging and error handling
- 100% backward compatible with v1

### v1.x
- Basic OAuth support
- Initial implementation

## License

See [LICENSE](../../LICENSE) file in repository root.

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines.

---

**Status:** Production Ready
**Tested:** serviceslab.privilegecloud.cyberark.cloud
**PowerShell:** 5.1, 7.0, 7.1, 7.2, 7.3, 7.4+
**Platform:** Windows, Linux, macOS (PowerShell 7+)
