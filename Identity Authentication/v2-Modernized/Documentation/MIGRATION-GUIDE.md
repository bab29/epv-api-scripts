# Migration Guide: IdentityAuth v1 → v2

## Overview

IdentityAuth v2 is a complete rewrite with new authentication methods, better error handling, and dual PowerShell version support.

## Breaking Changes

### Return Value Format

**v1 (Current):**
```powershell
# Returns Dictionary[String,String]
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url
# Keys: Authorization, X-IDAP-NATIVE-CLIENT
```

**v2 (New):**
```powershell
# Returns same format - NO BREAKING CHANGE!
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url
# Keys: Authorization, X-IDAP-NATIVE-CLIENT
```

✅ **Compatible!** Return value format is unchanged.

### Parameter Changes

| Parameter | v1 | v2 | Status |
|-----------|----|----|--------|
| `OAuthCreds` | ✅ | ✅ | Unchanged |
| `PCloudURL` | ✅ | ✅ | Unchanged |
| `IdentityURL` | ✅ (optional) | ✅ (optional) | Unchanged |
| `logonToken` | ❌ | ❌ | Not supported (use return value) |

✅ **Compatible!** All parameters work the same way.

## New Features in v2

### Additional Authentication Methods

**OOBAUTHPIN (NEW!):**
```powershell
# Interactive PIN authentication
$headers = Get-IdentityHeader -Username "user@domain.com" -PCloudURL $url

# Pre-provided PIN
$headers = Get-IdentityHeader -Username "user@domain.com" -PINCode "123456" -PCloudURL $url
```

**Username/Password (NEW!):**
```powershell
$creds = Get-Credential
$headers = Get-IdentityHeader -Username $creds.UserName -Credential $creds -PCloudURL $url
```

**Email/SMS OTP (NEW!):**
```powershell
$headers = Get-IdentityHeader -Username "user@domain.com" -OTPCode "987654" -PCloudURL $url
```

**Push Notification (NEW!):**
```powershell
$headers = Get-IdentityHeader -Username "user@domain.com" -UsePush -PCloudURL $url
```

### OAuth Token Caching

**v2 automatically caches OAuth tokens:**
```powershell
# First call: Requests new token
$headers1 = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url

# Second call: Uses cached token (no API call!)
$headers2 = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url

# Force refresh:
$headers3 = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url -Force
```

### Automatic Token Refresh

Tokens are automatically refreshed 5 minutes before expiry - no manual management needed!

## Migration Steps

### Step 1: Test Compatibility

Your existing code should work without changes:

```powershell
# v1 code (still works in v2):
$creds = Get-Credential -Message "OAuth Credentials"
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://tenant.cyberark.cloud"
.\Accounts_Onboard_Utility.ps1 -PVWAURL $pvwaUrl -logonToken $headers
```

### Step 2: Replace Module

**Option A: Side-by-side testing**
```powershell
# Keep v1 as IdentityAuth-v1
Rename-Item "$env:USERPROFILE\Documents\PowerShell\Modules\IdentityAuth" "IdentityAuth-v1"

# Install v2 as IdentityAuth
Copy-Item ".\Distribution\IdentityAuth" -Destination "$env:USERPROFILE\Documents\PowerShell\Modules" -Recurse
```

**Option B: Direct replacement**
```powershell
# Remove v1
Remove-Item "$env:USERPROFILE\Documents\PowerShell\Modules\IdentityAuth" -Recurse -Force

# Install v2
Copy-Item ".\Distribution\IdentityAuth" -Destination "$env:USERPROFILE\Documents\PowerShell\Modules" -Recurse
```

### Step 3: Update Scripts (Optional)

Take advantage of new features:

**Add token caching benefits:**
```powershell
# Before (v1): Token requested every time
for ($i = 0; $i -lt 100; $i++) {
    $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url
    # API call
}

# After (v2): Token cached and reused
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url
for ($i = 0; $i -lt 100; $i++) {
    # Reuse $headers - much faster!
    # API call
}
```

**Add interactive authentication:**
```powershell
# Allow user choice
$authMethod = Read-Host "Auth method (1=OAuth, 2=OOBAUTHPIN)"

if ($authMethod -eq '1') {
    $creds = Get-Credential
    $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url
} else {
    $username = Read-Host "Username"
    $headers = Get-IdentityHeader -Username $username -PCloudURL $url
}
```

## Compatibility Matrix

| Script/Tool | v1 | v2 | Notes |
|-------------|----|----|-------|
| Accounts_Onboard_Utility.ps1 | ✅ | ✅ | Fully compatible |
| Custom REST API scripts | ✅ | ✅ | Return value unchanged |
| EPV-API-Common module | ⚠️ | ⚠️ | Use EPV-API-Common's own auth |
| Direct token usage | ✅ | ✅ | `$headers.Authorization` works same |

## Troubleshooting

### Module Not Loading

```powershell
# Check module path
$env:PSModulePath -split ';'

# Check if module exists
Get-Module -ListAvailable IdentityAuth

# Force reimport
Remove-Module IdentityAuth -Force -ErrorAction SilentlyContinue
Import-Module IdentityAuth -Force
```

### Token Cache Issues

```powershell
# Clear cache by forcing refresh
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url -Force

# Or restart PowerShell session
```

### "Cannot find mechanism" Errors

Some auth methods may not be available for all users:
- OOBAUTHPIN: Requires setup in Identity admin portal
- Push: Requires mobile app registration
- OTP: Requires email/SMS setup

Use OAuth for automation (most reliable).

## Rollback Plan

If issues occur, rollback to v1:

```powershell
# Remove v2
Remove-Item "$env:USERPROFILE\Documents\PowerShell\Modules\IdentityAuth" -Recurse -Force

# Restore v1
Rename-Item "$env:USERPROFILE\Documents\PowerShell\Modules\IdentityAuth-v1" "IdentityAuth"

# Verify
Import-Module IdentityAuth -Force
(Get-Module IdentityAuth).Version  # Should show 1.x
```

## Getting Help

**Check verbose output:**
```powershell
$headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $url -Verbose
```

**View function help:**
```powershell
Get-Help Get-IdentityHeader -Full
Get-Help Get-IdentityHeader -Examples
```

**Run tests:**
```powershell
Invoke-Pester -Path ".\Tests\Pester\Get-IdentityHeader.Tests.ps1"
```

## Summary

✅ **Backward compatible** - Existing code works unchanged  
✅ **New auth methods** - OOBAUTHPIN, MFA, Push  
✅ **Token caching** - Better performance  
✅ **Auto-refresh** - No manual token management  
✅ **Dual versions** - PS5.1 and PS7+ support  

**Recommendation:** Test in non-production first, then migrate production scripts to benefit from new features!
