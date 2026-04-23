# Personal Privileged Accounts

PowerShell script to automate the creation of personal privileged safes and account onboarding in CyberArk using the v2 REST API.

## Overview

`Create-PersonalPrivilgedAccounts.ps1` reads a CSV of privileged users, creates a dedicated personal safe per user (if one does not already exist), adds the account owner and any configured default members, then bulk-onboards all accounts via the CyberArk Bulk Accounts API.

Configuration is layered so defaults can be defined once in JSON and overridden per-environment or per-run:

| Priority | Source |
| --- | --- |
| 1 (lowest) | Script baseline defaults |
| 2 | `PersonalPrivilegedAccounts.json` — `SafeConfigSet.default` / `UserConfigSet.default` |
| 3 | Named config sets (`-SafeConfigSet` / `-UserConfigSet`) |
| 4 (highest) | Explicit CLI parameters (always win) |

Supports CyberArk on-premises (cyberark / ldap / radius) and Privilege Cloud (pass a pre-obtained token via `-logonToken`).

## Features

- Personal safe created per user, named from a configurable pattern (e.g. `jsmith_ADM`)
- Idempotent — skips safes and members that already exist
- Bulk account onboarding via `/api/BulkActions/Accounts`
- Layered JSON config with named sets for multi-environment support
- Built-in roles (`Full`, `AccountsManager`, `Auditor`, `EndUser`, `Approver`) plus custom permission hashtables
- Session token reuse — pass a token to skip logon/logoff (ideal for scripted pipelines)
- Privilege Cloud and on-premises compatible

## Files

| File | Description |
| --- | --- |
| `Create-PersonalPrivilgedAccounts.ps1` | Main script |
| `PersonalPrivilegedAccounts.json` | Config file — safe settings, user defaults, role permission sets |
| `sample_personal_accounts.csv` | Example CSV showing all supported columns |

## CSV Format

```csv
userName,SafeConfigSet,SafeNamePattern,CPMName,NumberOfDaysRetention,NumberOfVersionsRetention,safeName,UserConfigSet,accountUser,password,accountAddress,accountPlatform,enableAutoMgmt,manualMgmtReason,remoteMachineAddresses,restrictMachineAccessToList
```

| Column | Required | Description |
| --- | --- | --- |
| `userName` | Yes | CyberArk vault user — becomes the safe owner and is substituted into `SafeNamePattern` |
| `SafeConfigSet` | No | Named set from `SafeConfigSet` in the config file to use for this row. Falls back to the script-level `-SafeConfigSet` value (or `default`) when blank. An invalid name causes the row to be skipped unless `-FallbackOnInvalidConfigSet` is specified. |
| `SafeNamePattern` | No | Inline override for the safe name pattern (e.g. `*_PRIV`). Takes priority over `SafeConfigSet` values. |
| `CPMName` | No | Inline override for the CPM assigned to the safe. Takes priority over `SafeConfigSet` values. |
| `NumberOfDaysRetention` | No | Inline override for day-based retention. Takes priority over `SafeConfigSet` values. Clears `NumberOfVersionsRetention`. |
| `NumberOfVersionsRetention` | No | Inline override for version-based retention. Takes priority over `SafeConfigSet` values. Ignored when `NumberOfDaysRetention` is also set on the same row. |
| `safeName` | No | Explicit safe name. If empty, derived from `SafeNamePattern` |
| `UserConfigSet` | No | Named set from `UserConfigSet` in the config file to use for this row. Same fallback and error behaviour as `SafeConfigSet`. |
| `accountUser` | No | Username of the privileged account to onboard. If blank, derived from `accountUserPattern` in `UserConfigSet` (replace `*` with `userName`); falls back to `userName` if no pattern is set. |
| `password` | No | Initial password. Leave blank to let CPM manage |
| `accountAddress` | No | Target address / hostname for the account. If blank, falls back to `accountAddress` in `UserConfigSet`. Error if still empty. |
| `accountPlatform` | No | Platform ID for the account. Falls back to config/parameter default |
| `enableAutoMgmt` | No | `yes` / `no` — enables or disables CPM automatic management |
| `manualMgmtReason` | No | Required when `enableAutoMgmt` is `no` |
| `remoteMachineAddresses` | No | Semicolon-separated list of allowed remote machines |
| `restrictMachineAccessToList` | No | `yes` / `no` — restricts logon to `remoteMachineAddresses` only |

## Configuration File

`PersonalPrivilegedAccounts.json` has three top-level sections. The active config set can be selected at script level via `-SafeConfigSet` / `-UserConfigSet` parameters, or overridden per row using the optional `SafeConfigSet` and `UserConfigSet` CSV columns. When a CSV column is blank or absent the script-level selection (or `default`) is used.

### SafeConfigSet

Defines safe creation settings. `default` is always applied; named sets (e.g. `prod`, `dev`) merge on top.

```json
"SafeConfigSet": {
    "default": {
        "CPMName": "PasswordManager",
        "NumberOfDaysRetention": 7,
        "SafeNamePattern": "*_ADM",
        "DefaultSafeMembers": [
            { "Name": "AdminGroup", "Role": "Full", "SearchIn": "Vault" },
            { "Name": "AuditGroup", "RoleConfigSet": "CustomAudit", "SearchIn": "Vault" }
        ]
    },
    "prod": { "CPMName": "PasswordManager_Prod", "NumberOfVersionsRetention": 10 }
}
```

`DefaultSafeMembers` entries support three permission modes (in priority order):

1. `"Permissions": { ... }` — explicit permission hashtable
2. `"RoleConfigSet": "name"` — reference a named set from `RoleConfigSet`
3. `"Role": "name"` — built-in role: `Full` | `AccountsManager` | `Auditor` | `EndUser` | `Approver`

### UserConfigSet

Defines account defaults. Named sets merge on top of `default`.

```json
"UserConfigSet": {
    "default": {
        "accountPlatform": "WinDomain",
        "accountUserPattern": "*_adm",
        "accountAddress": "corp.example.com",
        "enableAutoMgmt": "yes"
    },
    "dev": {
        "accountAddress": "dev.example.com",
        "enableAutoMgmt": "no",
        "manualMgmtReason": "Managed externally in dev"
    }
}
```

### RoleConfigSet

Named permission sets that can be referenced by `DefaultSafeMembers` entries.

```json
"RoleConfigSet": {
    "CustomAudit": { "listAccounts": true, "viewAuditLog": true, "viewSafeMembers": true }
}
```

## Parameters

### Connection

| Parameter | Default | Description |
| --- | --- | --- |
| `-PVWAURL` | *(required)* | PVWA base URL (e.g. `https://pvwa.company.com/PasswordVault`) |
| `-AuthenticationType` | `cyberark` | `cyberark` \| `ldap` \| `radius` |
| `-OTP` | — | RADIUS one-time password |
| `-PVWACredentials` | *(prompt)* | PSCredential — if omitted, interactive prompt is shown |
| `-logonToken` | — | Pre-obtained token string or hashtable; skips logon/logoff |
| `-DisableCertificateValidation` | `$false` | Bypass SSL validation — test environments only |

### Safe / Account

| Parameter | Default | Description |
| --- | --- | --- |
| `-SafeNamePattern` | `*_ADM` | Pattern with exactly one `*` replaced by `userName` |
| `-PlatformID` | `WinDomain` | Default platform ID when CSV row has no `accountPlatform` |
| `-CSVPath` | *(file picker)* | Path to the accounts CSV |
| `-ConfigPath` | *(script dir)* | Path to `PersonalPrivilegedAccounts.json` |

### Config overrides

| Parameter | Default | Description |
| --- | --- | --- |
| `-SafeConfigSet` | `default` | Named set within `SafeConfigSet` to apply for the whole run (overridden per row via CSV column) |
| `-UserConfigSet` | `default` | Named set within `UserConfigSet` to apply for the whole run (overridden per row via CSV column) |
| `-FallbackOnInvalidConfigSet` | `$false` | When a CSV row names a set that does not exist: warn and use base config instead of logging an error and skipping the row |
| `-CPMName` | *(from config)* | CPM name for new safes |
| `-NumberOfVersionsRetention` | *(from config)* | Versions to retain — mutually exclusive with days |
| `-NumberOfDaysRetention` | *(from config)* | Days to retain — wins when both are supplied |

## Quick Start

### On-premises — interactive

```powershell
$params = @{
    PVWAURL = 'https://pvwa.company.com/PasswordVault'
    CSVPath = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### On-premises — named config sets

```powershell
$params = @{
    PVWAURL         = 'https://pvwa.company.com/PasswordVault'
    SafeConfigSet   = 'prod'
    UserConfigSet   = 'prod'
    CSVPath         = '.\accounts.csv'
    PVWACredentials = (Get-Credential)
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### Privilege Cloud — pre-obtained token

```powershell
$token = Get-IdentityHeader @{
    IdentityTenantURL  = 'https://tenant.id.cyberark.cloud'
    PCloudTenantAPIURL = 'https://tenant.privilegecloud.cyberark.cloud'
}

$params = @{
    logonToken = $token
    CSVPath    = '.\accounts.csv'
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

### With CyberArkDefaults module

```powershell
Import-Module G:\epv-api-scripts\.Defaults\CyberArkDefaults.psd1
Set-CyberArkDefaults -PVWAUrl https://pvwa.company.com/PasswordVault

.\Create-PersonalPrivilgedAccounts.ps1 -CSVPath .\accounts.csv
```

### Override retention and CPM from CLI

```powershell
$params = @{
    PVWAURL                   = 'https://pvwa.company.com/PasswordVault'
    CSVPath                   = '.\accounts.csv'
    CPMName                   = 'PasswordManager_DR'
    NumberOfVersionsRetention = 10
}
.\Create-PersonalPrivilgedAccounts.ps1 @params
```

## Requirements

- PowerShell 5.1 or later
- CyberArk PVWA v12.1 or later (v2 REST API)
- Vault user running the script must have permission to create safes and add safe members
