#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end test runner for Create-PersonalPrivilgedAccounts.ps1.
.DESCRIPTION
    Generates a unique run ID on every invocation, builds a temporary CSV and config
    file whose safe names embed that ID, executes the main script against a live
    CyberArk environment, then verifies the results via direct REST API calls.

    Because CyberArk safes cannot be deleted due to retention policies, every run
    produces fresh safe names so there are no name collisions between runs.
    Test safes accumulate harmlessly in the vault; the temporary CSV and config
    are removed in the finally block regardless of outcome.

    Connection parameters are resolved from (highest to lowest priority):
      1. Parameters passed directly to this script
      2. $PSDefaultParameterValues set by the CyberArkDefaults module
         (run: Set-CyberArkDefaults -PVWAUrl ... or import CyberArkDefaults)

    Tests performed:
      T01  Script exits without fatal error (exit code 0) — first run
      T02  Safe for user 1 exists after run
      T03  Safe for user 2 exists after run
      T04  User 1 is a member of their safe
      T05  User 2 is a member of their safe
      T06  User 1's membership has addAccounts = true (AccountsManager role)
      T07  Account(s) onboarded into safe 1
      T08  Account(s) onboarded into safe 2
      T09  User 2's account has automaticManagementEnabled = false
      T10  Safe for user 3 exists (per-row SafeConfigSet 'alt' applied — row not skipped)
      T11  Safe for user 3 has numberOfDaysRetention = 14 (named config set values used)
      T12  Safe for user 4 does NOT exist without -FallbackOnInvalidConfigSet (row skipped)
      T13  Safe for user 4 DOES exist with -FallbackOnInvalidConfigSet (base config used)
      T14  Script exits without fatal error on re-run (idempotency)
      T15  User 1's onboarded account has userName = '<user1Name>_adm' (derived from accountUserPattern)
      T16  User 1's onboarded account has address = 'testenv.corp.com' (derived from config accountAddress)

.PARAMETER PVWAURL
    PVWA base URL (e.g. https://pvwa.lab.local/PasswordVault).
    If omitted, falls back to $PSDefaultParameterValues set by CyberArkDefaults.

.PARAMETER AuthenticationType
    Authentication type for on-premises logon: cyberark | ldap | radius.
    Default: cyberark.

.PARAMETER PVWACredentials
    PSCredential for authentication. If omitted and no logonToken available,
    an interactive prompt is shown.

.PARAMETER logonToken
    Pre-obtained logon token (string or hashtable).
    If omitted, falls back to $PSDefaultParameterValues set by CyberArkDefaults.

.PARAMETER DisableCertificateValidation
    Bypass SSL certificate validation. Use only in test environments.

.PARAMETER ScriptPath
    Full path to Create-PersonalPrivilgedAccounts.ps1.
    Defaults to the same directory as this test script.

.PARAMETER CPMName
    CPM name assigned to test safes. Default: PasswordManager.

.PARAMETER SafeNamePattern
    Safe name pattern (must contain exactly one *). Default: *_ADM.

.PARAMETER AccountPlatform
    Platform ID to assign to test accounts (e.g. WinDomain, WinServerLocal, UnixSSH).
    Must already exist in the target vault. Required — no default is assumed.

.OUTPUTS
    None. Results are written to the console.
    Exit code 0 = all assertions passed; 1 = one or more failed.

.EXAMPLE
    # Relies on CyberArkDefaults already configured in the session:
    .\Test-PersonalPrivilgedAccountsv2.ps1

.EXAMPLE
    # Explicit connection (on-premises, interactive credential prompt):
    .\Test-PersonalPrivilgedAccountsv2.ps1 -PVWAURL https://pvwa.lab.local/PasswordVault

.EXAMPLE
    # Explicit connection with credential object:
    $cred = Get-Credential
    .\Test-PersonalPrivilgedAccountsv2.ps1 -PVWAURL https://pvwa.lab.local/PasswordVault -PVWACredentials $cred

.EXAMPLE
    # Using a pre-obtained token (e.g. from Get-IdentityHeader for PCloud):
    .\Test-PersonalPrivilgedAccountsv2.ps1 -PVWAURL https://tenant.privilegecloud.cyberark.cloud/PasswordVault -logonToken $token

.NOTES
    Version: 1.0
    Safe names created by this script cannot be deleted. They follow the pattern:
      e<MMddHHmmss>1_ADM  and  e<MMddHHmmss>2_ADM
    These accumulate in the vault as evidence of each test run.
#>
[CmdletBinding()]
param (
    #region Connection
    [Parameter(Mandatory = $false)]
    [string]$PVWAURL,

    [Parameter(Mandatory = $false)]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [string]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false)]
    [PSCredential]$PVWACredentials,

    [Parameter(Mandatory = $false)]
    $logonToken,

    [Parameter(Mandatory = $false)]
    [switch]$DisableCertificateValidation,
    #endregion

    #region Test configuration
    [Parameter(Mandatory = $false)]
    [string]$ScriptPath,

    [Parameter(Mandatory = $false)]
    [string]$CPMName = 'PasswordManager',

    [Parameter(Mandatory = $false)]
    [string]$SafeNamePattern = '*_ADM',

    [Parameter(Mandatory = $true)]
    [string]$AccountPlatform
    #endregion
)

Set-StrictMode -Off
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region Setup

$testScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# MMddHHmmss = 10 chars → username ≤ 12 chars → safe name ≤ 16 chars (limit is 28)
$runId = Get-Date -Format 'MMddHHmmss'

#endregion

#region Resolve parameters from PSDefaultParameterValues (CyberArkDefaults module)

if ([string]::IsNullOrEmpty($PVWAURL)) {
    $urlKey = $global:PSDefaultParameterValues.Keys |
        Where-Object { $PSItem -like '*:PVWAURL' -or $PSItem -like '*:PVWAUrl' } |
        Select-Object -First 1
    if ($urlKey) { $PVWAURL = $global:PSDefaultParameterValues[$urlKey] }
}

if ($null -eq $logonToken) {
    $tokenKey = $global:PSDefaultParameterValues.Keys |
        Where-Object { $PSItem -like '*:logonToken' } |
        Select-Object -First 1
    if ($tokenKey) { $logonToken = $global:PSDefaultParameterValues[$tokenKey] }
}

if (-not $DisableCertificateValidation) {
    $sslKey = $global:PSDefaultParameterValues.Keys |
        Where-Object { $PSItem -like '*:DisableCertificateValidation' } |
        Select-Object -First 1
    if ($null -ne $sslKey -and $global:PSDefaultParameterValues[$sslKey]) {
        $DisableCertificateValidation = $true
    }
}

#endregion

#region Validate prerequisites

if ([string]::IsNullOrEmpty($PVWAURL)) {
    Write-Host 'ERROR: -PVWAURL is required. Pass it directly or run Set-CyberArkDefaults first.' -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrEmpty($ScriptPath)) {
    $ScriptPath = Join-Path -Path $testScriptDir -ChildPath 'Create-PersonalPrivilgedAccounts.ps1'
}

if (-not (Test-Path -Path $ScriptPath -PathType Leaf)) {
    Write-Host "ERROR: Script under test not found: $ScriptPath" -ForegroundColor Red
    exit 1
}

if ($DisableCertificateValidation) {
    if (-not ('DisableCertValidationCallback' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Net; using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object s, X509Certificate c,
        X509Chain ch, SslPolicyErrors e) { return true; }
    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue); }
}
'@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback =
        [DisableCertValidationCallback]::GetDelegate()
}

#endregion

#region Helper functions

function Get-TestAuthHeader {
    <#
    .SYNOPSIS Returns an Authorization hashtable for verification REST calls.
    #>
    if ($null -ne $logonToken) {
        if ($logonToken -is [hashtable]) { return $logonToken }
        return @{ Authorization = $logonToken }
    }

    if ($null -eq $PVWACredentials) {
        $PVWACredentials = $Host.UI.PromptForCredential(
            'E2E Test Authentication',
            "Enter CyberArk credentials ($AuthenticationType)",
            '', '')
        if ($null -eq $PVWACredentials) { throw 'No credentials provided — cannot authenticate.' }
    }

    $BSTR = $null
    try {
        $BSTR     = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PVWACredentials.Password)
        $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        $authBody = @{
            username          = $PVWACredentials.UserName
            password          = $plainPwd
            concurrentSession = $true
        } | ConvertTo-Json -Compress

        $authParams = @{
            Uri         = "$($PVWAURL.TrimEnd('/'))/api/auth/$AuthenticationType/Logon"
            Method      = 'POST'
            Body        = $authBody
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        $token = Invoke-RestMethod @authParams
        return @{ Authorization = $token }
    }
    finally {
        if ($null -ne $BSTR) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) }
        $plainPwd = $null
    }
}

function Invoke-VerifyRest {
    <#
    .SYNOPSIS Lightweight REST wrapper for test assertions. Returns $null on failure.
    #>
    param (
        [Parameter(Mandatory = $true)]  [string]$Method,
        [Parameter(Mandatory = $true)]  [string]$URI,
        [Parameter(Mandatory = $true)]  [hashtable]$Header
    )
    try {
        $restParams = @{
            Uri         = $URI
            Method      = $Method
            Headers     = $Header
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        return Invoke-RestMethod @restParams
    }
    catch {
        return $null
    }
}

$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Assert-Condition {
    param (
        [Parameter(Mandatory = $true)]  [string]$Id,
        [Parameter(Mandatory = $true)]  [string]$Description,
        [Parameter(Mandatory = $true)]  [bool]$Condition,
        [Parameter(Mandatory = $false)] [string]$FailDetail = ''
    )
    $status = if ($Condition) { 'PASS' } else { 'FAIL' }
    $color  = if ($Condition) { 'Green' } else { 'Red' }

    Write-Host ("  [{0}] {1} - {2}" -f $status, $Id, $Description) -ForegroundColor $color
    if (-not $Condition -and -not [string]::IsNullOrEmpty($FailDetail)) {
        Write-Host ("        Detail: {0}" -f $FailDetail) -ForegroundColor DarkRed
    }

    $testResults.Add([PSCustomObject]@{
        Id         = $Id
        Description = $Description
        Status     = $status
        FailDetail = $FailDetail
    })
}

#endregion

#region Test data — unique names per run

# Usernames: e{10}1 / e{10}4 = 12 chars max → safe names ≤ 16 chars (limit: 28)
$user1Name = "e${runId}1"
$user2Name = "e${runId}2"
$user3Name = "e${runId}3"   # named SafeConfigSet 'alt' — tests per-row config set
$user4Name = "e${runId}4"   # invalid SafeConfigSet — tests skip + fallback behaviour
$safe1Name = $SafeNamePattern.Replace('*', $user1Name)
$safe2Name = $SafeNamePattern.Replace('*', $user2Name)
$safe3Name = $SafeNamePattern.Replace('*', $user3Name)
$safe4Name = $SafeNamePattern.Replace('*', $user4Name)
$baseURL   = $PVWAURL.TrimEnd('/')

$tempCsvPath    = Join-Path -Path $testScriptDir -ChildPath "E2ETest_${runId}.csv"
$tempCsvPath2   = Join-Path -Path $testScriptDir -ChildPath "E2ETest_${runId}_invalid.csv"
$tempConfigPath = Join-Path -Path $testScriptDir -ChildPath "E2ETest_${runId}_config.json"

#endregion

#region Banner

Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host '  E2E Test Runner — Create-PersonalPrivilgedAccounts.ps1' -ForegroundColor Cyan
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ("  Run ID     : {0}" -f $runId)
Write-Host ("  Safe 1     : {0}" -f $safe1Name)
Write-Host ("  Safe 2     : {0}" -f $safe2Name)
Write-Host ("  Safe 3     : {0}  (named SafeConfigSet 'alt')" -f $safe3Name)
Write-Host ("  Safe 4     : {0}  (invalid SafeConfigSet tests)" -f $safe4Name)
Write-Host ("  PVWA URL   : {0}" -f $PVWAURL)
Write-Host ("  Script     : {0}" -f $ScriptPath)
Write-Host ("  CPM        : {0}" -f $CPMName)
Write-Host ("  Platform   : {0}" -f $AccountPlatform)
Write-Host ('=' * 72) -ForegroundColor Cyan
Write-Host ''

#endregion

$authHeader   = $null
$ownedSession = $false   # true when we authenticated (so we logoff in finally)

try {

    #region Build temp CSV
    # Three test accounts:
    #   user1: auto-managed, safe name from pattern, accountUser BLANK (derived via accountUserPattern)
    #   user2: manual management, explicit safe name, explicit accountUser
    #   user3: per-row SafeConfigSet='alt' (14-day retention), accountUser BLANK (also derived)
    $csvContent = @(
        'userName,SafeConfigSet,SafeNamePattern,CPMName,NumberOfDaysRetention,NumberOfVersionsRetention,safeName,UserConfigSet,accountUser,password,accountAddress,accountPlatform,enableAutoMgmt,manualMgmtReason,remoteMachineAddresses,restrictMachineAccessToList'
        "${user1Name},,,,,,,,,,,${AccountPlatform},yes,,,"  # accountUser+accountAddress blank - derived from config
        "${user2Name},,,,,,${safe2Name},,${user2Name}_adm,,testenv.corp.com,${AccountPlatform},no,E2E test manual mgmt,,"  # explicit accountUser+address
        "${user3Name},alt,,,,,,,,,,${AccountPlatform},yes,,,"  # per-row SafeConfigSet, accountUser+address from config
    )
    $csvContent | Out-File -FilePath $tempCsvPath -Encoding utf8 -Force

    # Minimal config: no DefaultSafeMembers to avoid dependency on specific vault groups.
    # 'alt' SafeConfigSet has 14-day retention - used by user3 to prove per-row config set merging.
    # accountUserPattern '*_adm' derives account username from userName when accountUser column is blank.
    $testConfig = [ordered]@{
        SafeConfigSet = [ordered]@{
            default = [ordered]@{
                CPMName               = $CPMName
                NumberOfDaysRetention = 7
                SafeNamePattern       = $SafeNamePattern
                DefaultSafeMembers    = @()
            }
            alt     = [ordered]@{
                NumberOfDaysRetention = 14
            }
        }
        UserConfigSet = [ordered]@{
            default = [ordered]@{
                accountPlatform    = $AccountPlatform
                accountUserPattern = '*_adm'
                accountAddress     = 'testenv.corp.com'
                enableAutoMgmt     = 'yes'
            }
        }
        RoleConfigSet = [ordered]@{}
    }
    $testConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $tempConfigPath -Encoding utf8 -Force

    Write-Host "[SETUP] Temp CSV    : $tempCsvPath" -ForegroundColor Gray
    Write-Host "[SETUP] Temp config : $tempConfigPath" -ForegroundColor Gray
    Write-Host ''
    #endregion

    #region Authenticate (for verification REST calls)
    Write-Host '[AUTH] Resolving authentication for verification calls...' -ForegroundColor Gray
    $authHeader   = Get-TestAuthHeader
    $ownedSession = ($null -eq $logonToken)   # we own the session only if we created it
    Write-Host '[AUTH] Done.' -ForegroundColor Gray
    Write-Host ''
    #endregion

    # Common params passed to the main script
    $mainScriptParams = @{
        PVWAURL         = $PVWAURL
        logonToken      = $authHeader       # pass header so main script skips logon/logoff
        CSVPath         = $tempCsvPath
        ConfigPath      = $tempConfigPath
        SafeNamePattern = $SafeNamePattern
    }
    if ($DisableCertificateValidation) { $mainScriptParams.DisableCertificateValidation = $true }

    # ─────────────────────────────────────────────────────────────────────────
    # Step 1 — Execute main script (first run: create safes + onboard accounts)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ('─' * 72) -ForegroundColor DarkCyan
    Write-Host ' Step 1: Execute main script (first run)' -ForegroundColor DarkCyan
    Write-Host ('─' * 72) -ForegroundColor DarkCyan

    $null = $LASTEXITCODE
    & $ScriptPath @mainScriptParams
    $step1ExitCode = $LASTEXITCODE

    Assert-Condition -Id 'T01' `
        -Description 'Script exits without fatal error code (first run)' `
        -Condition ($null -eq $step1ExitCode -or $step1ExitCode -eq 0) `
        -FailDetail "Exit code: $step1ExitCode"

    Write-Host ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 2 — Verify safes were created
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ('─' * 72) -ForegroundColor DarkCyan
    Write-Host ' Step 2: Verify safes exist' -ForegroundColor DarkCyan
    Write-Host ('─' * 72) -ForegroundColor DarkCyan

    $safe1Result = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe1Name))" `
        -Header $authHeader
    Assert-Condition -Id 'T02' `
        -Description "Safe '$safe1Name' exists in the vault" `
        -Condition ($null -ne $safe1Result) `
        -FailDetail 'GET /api/Safes returned null — safe may not have been created'

    $safe2Result = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe2Name))" `
        -Header $authHeader
    Assert-Condition -Id 'T03' `
        -Description "Safe '$safe2Name' exists in the vault" `
        -Condition ($null -ne $safe2Result) `
        -FailDetail 'GET /api/Safes returned null — safe may not have been created'

    $safe3Result = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe3Name))" `
        -Header $authHeader
    Assert-Condition -Id 'T10' `
        -Description "Safe '$safe3Name' exists (per-row SafeConfigSet 'alt' applied — row not skipped)" `
        -Condition ($null -ne $safe3Result) `
        -FailDetail 'GET /api/Safes returned null — safe may not have been created'

    Write-Host ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 3 — Verify safe owners
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ('─' * 72) -ForegroundColor DarkCyan
    Write-Host ' Step 3: Verify safe owners (AccountsManager role)' -ForegroundColor DarkCyan
    Write-Host ('─' * 72) -ForegroundColor DarkCyan

    $member1 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe1Name))/Members/$([URI]::EscapeDataString($user1Name))" `
        -Header $authHeader
    Assert-Condition -Id 'T04' `
        -Description "'$user1Name' is a member of '$safe1Name'" `
        -Condition ($null -ne $member1) `
        -FailDetail "GET /Members/$user1Name returned null"

    $member2 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe2Name))/Members/$([URI]::EscapeDataString($user2Name))" `
        -Header $authHeader
    Assert-Condition -Id 'T05' `
        -Description "'$user2Name' is a member of '$safe2Name'" `
        -Condition ($null -ne $member2) `
        -FailDetail "GET /Members/$user2Name returned null"

    # Spot-check permissions — AccountsManager role must have addAccounts = true
    if ($null -ne $member1) {
        Assert-Condition -Id 'T06' `
            -Description "'$user1Name' has addAccounts = true (AccountsManager role confirmed)" `
            -Condition ($member1.permissions.addAccounts -eq $true) `
            -FailDetail "permissions.addAccounts = $($member1.permissions.addAccounts)"
    }

    Write-Host ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 4 — Verify accounts were onboarded via Bulk API
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ('─' * 72) -ForegroundColor DarkCyan
    Write-Host ' Step 4: Verify accounts onboarded' -ForegroundColor DarkCyan
    Write-Host ('─' * 72) -ForegroundColor DarkCyan

    $accts1 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Accounts?filter=$([URI]::EscapeDataString("safeName eq $safe1Name"))" `
        -Header $authHeader
    Assert-Condition -Id 'T07' `
        -Description "Account(s) exist in '$safe1Name'" `
        -Condition ($null -ne $accts1 -and $accts1.count -gt 0) `
        -FailDetail "count = $($accts1.count)"

    # Spot-check: user1 accountUser and accountAddress were derived from config (CSV columns blank)
    if ($null -ne $accts1 -and $accts1.count -gt 0) {
        $u1Account = $accts1.value | Select-Object -First 1
        Assert-Condition -Id 'T15' `
            -Description "'${user1Name}_adm' is the onboarded account userName (derived from accountUserPattern)" `
            -Condition ($u1Account.userName -eq "${user1Name}_adm") `
            -FailDetail "userName = $($u1Account.userName)"
        Assert-Condition -Id 'T16' `
            -Description "Account address = 'testenv.corp.com' (derived from config accountAddress)" `
            -Condition ($u1Account.address -eq 'testenv.corp.com') `
            -FailDetail "address = $($u1Account.address)"
    }

    $accts2 = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Accounts?filter=$([URI]::EscapeDataString("safeName eq $safe2Name"))" `
        -Header $authHeader
    Assert-Condition -Id 'T08' `
        -Description "Account(s) exist in '$safe2Name'" `
        -Condition ($null -ne $accts2 -and $accts2.count -gt 0) `
        -FailDetail "count = $($accts2.count)"

    # Spot-check: user2 account must have automaticManagementEnabled = false
    if ($null -ne $accts2 -and $accts2.count -gt 0) {
        $u2Account = $accts2.value |
            Where-Object { $PSItem.userName -eq "${user2Name}_adm" } |
            Select-Object -First 1
        if ($null -ne $u2Account) {
            Assert-Condition -Id 'T09' `
                -Description "'${user2Name}_adm' has automaticManagementEnabled = false" `
                -Condition ($u2Account.secretManagement.automaticManagementEnabled -eq $false) `
                -FailDetail "automaticManagementEnabled = $($u2Account.secretManagement.automaticManagementEnabled)"
        }
        else {
            Assert-Condition -Id 'T09' `
                -Description "'${user2Name}_adm' found in accounts list" `
                -Condition $false `
                -FailDetail 'Account not found in safe2 accounts response'
        }
    }

    Write-Host ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 5 — Per-row SafeConfigSet/UserConfigSet validation
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ('─' * 72) -ForegroundColor DarkCyan
    Write-Host ' Step 5: Per-row SafeConfigSet/UserConfigSet validation' -ForegroundColor DarkCyan
    Write-Host ('─' * 72) -ForegroundColor DarkCyan

    # T11 — named config set values were actually applied (safe3 should have 14-day retention)
    if ($null -ne $safe3Result) {
        Assert-Condition -Id 'T11' `
            -Description "Safe '$safe3Name' has numberOfDaysRetention = 14 (named 'alt' config set applied)" `
            -Condition ($safe3Result.numberOfDaysRetention -eq 14) `
            -FailDetail "numberOfDaysRetention = $($safe3Result.numberOfDaysRetention)"
    }
    else {
        Assert-Condition -Id 'T11' `
            -Description "Safe '$safe3Name' retention cannot be verified (T10 failed)" `
            -Condition $false `
            -FailDetail 'Safe does not exist — cannot verify retention'
    }

    # T12/T13 — invalid SafeConfigSet: row skipped by default; safe created when -FallbackOnInvalidConfigSet used
    $invalidSetCsvContent = @(
        'userName,SafeConfigSet,SafeNamePattern,CPMName,NumberOfDaysRetention,NumberOfVersionsRetention,safeName,UserConfigSet,accountUser,password,accountAddress,accountPlatform,enableAutoMgmt,manualMgmtReason,remoteMachineAddresses,restrictMachineAccessToList'
        "${user4Name},DoesNotExistXYZ,,,,,,,,,,${AccountPlatform},yes,,,"
    )
    $invalidSetCsvContent | Out-File -FilePath $tempCsvPath2 -Encoding utf8 -Force

    $skipTestParams = @{
        PVWAURL         = $PVWAURL
        logonToken      = $authHeader
        CSVPath         = $tempCsvPath2
        ConfigPath      = $tempConfigPath
        SafeNamePattern = $SafeNamePattern
    }
    if ($DisableCertificateValidation) { $skipTestParams.DisableCertificateValidation = $true }

    Write-Host '  Sub-test A: invalid SafeConfigSet without -FallbackOnInvalidConfigSet (row should be skipped)' -ForegroundColor Gray
    $null = $LASTEXITCODE
    & $ScriptPath @skipTestParams

    $safe4BeforeFallback = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe4Name))" `
        -Header $authHeader
    Assert-Condition -Id 'T12' `
        -Description "Safe '$safe4Name' does NOT exist (invalid SafeConfigSet skips row by default)" `
        -Condition ($null -eq $safe4BeforeFallback) `
        -FailDetail 'Safe exists — row should have been skipped due to invalid SafeConfigSet'

    Write-Host '  Sub-test B: same row with -FallbackOnInvalidConfigSet (safe should be created using base config)' -ForegroundColor Gray
    $fallbackTestParams = @{
        PVWAURL                    = $PVWAURL
        logonToken                 = $authHeader
        CSVPath                    = $tempCsvPath2
        ConfigPath                 = $tempConfigPath
        SafeNamePattern            = $SafeNamePattern
        FallbackOnInvalidConfigSet = $true
    }
    if ($DisableCertificateValidation) { $fallbackTestParams.DisableCertificateValidation = $true }

    $null = $LASTEXITCODE
    & $ScriptPath @fallbackTestParams

    $safe4AfterFallback = Invoke-VerifyRest -Method GET `
        -URI "$baseURL/api/Safes/$([URI]::EscapeDataString($safe4Name))" `
        -Header $authHeader
    Assert-Condition -Id 'T13' `
        -Description "Safe '$safe4Name' DOES exist after -FallbackOnInvalidConfigSet run (base config used)" `
        -Condition ($null -ne $safe4AfterFallback) `
        -FailDetail 'Safe not found — fallback may not have applied correctly'

    Write-Host ''

    # ─────────────────────────────────────────────────────────────────────────
    # Step 6 — Idempotency: re-run against safes that already exist
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ('─' * 72) -ForegroundColor DarkCyan
    Write-Host ' Step 6: Idempotency — re-run with safes already present' -ForegroundColor DarkCyan
    Write-Host ('─' * 72) -ForegroundColor DarkCyan
    Write-Host '  (Safe-already-exists errors are expected and should be handled gracefully)' -ForegroundColor Gray
    Write-Host ''

    $null = $LASTEXITCODE
    & $ScriptPath @mainScriptParams
    $step6ExitCode = $LASTEXITCODE

    Assert-Condition -Id 'T14' `
        -Description 'Script exits without fatal error code on re-run (idempotency)' `
        -Condition ($null -eq $step6ExitCode -or $step6ExitCode -eq 0) `
        -FailDetail "Exit code: $step6ExitCode"

    Write-Host ''

}
catch {
    Write-Host ''
    Write-Host "FATAL: Unexpected error during test execution: $($PSItem.Exception.Message)" -ForegroundColor Red
    Write-Host "       $($PSItem.ScriptStackTrace)" -ForegroundColor DarkRed
}
finally {
    # Remove temp files (safes are NOT deleted — retention policy prevents it)
    if (Test-Path -Path $tempCsvPath)    { Remove-Item -Path $tempCsvPath    -Force }
    if (Test-Path -Path $tempCsvPath2)   { Remove-Item -Path $tempCsvPath2   -Force }
    if (Test-Path -Path $tempConfigPath) { Remove-Item -Path $tempConfigPath -Force }
    Write-Host '[CLEANUP] Temp CSV and config removed.' -ForegroundColor Gray

    # Logoff only if this test script performed authentication
    if ($ownedSession -and $null -ne $authHeader) {
        try {
            $logoffParams = @{
                Uri         = "$baseURL/api/Auth/Logoff"
                Method      = 'POST'
                Headers     = $authHeader
                ContentType = 'application/json'
                ErrorAction = 'SilentlyContinue'
            }
            Invoke-RestMethod @logoffParams | Out-Null
            Write-Host '[CLEANUP] Session logged off.' -ForegroundColor Gray
        }
        catch {
            Write-Host '[CLEANUP] Logoff skipped (session may have already expired).' -ForegroundColor Gray
        }
    }
    else {
        Write-Host '[CLEANUP] Session owned externally — not logging off.' -ForegroundColor Gray
    }
}

#region Summary

$passedCount = ($testResults | Where-Object { $PSItem.Status -eq 'PASS' }).Count
$failedCount = ($testResults | Where-Object { $PSItem.Status -eq 'FAIL' }).Count
$totalCount  = $testResults.Count

Write-Host ''
Write-Host ('=' * 72) -ForegroundColor Cyan
$summaryColor = if ($failedCount -eq 0) { 'Green' } else { 'Red' }
Write-Host ("  RESULTS: {0} passed, {1} failed out of {2} assertions" -f $passedCount, $failedCount, $totalCount) -ForegroundColor $summaryColor
Write-Host ('=' * 72) -ForegroundColor Cyan

if ($failedCount -gt 0) {
    Write-Host ''
    Write-Host 'Failed assertions:' -ForegroundColor Red
    $testResults | Where-Object { $PSItem.Status -eq 'FAIL' } | ForEach-Object {
        Write-Host ("  [{0}] {1}" -f $PSItem.Id, $PSItem.Description) -ForegroundColor Red
        if (-not [string]::IsNullOrEmpty($PSItem.FailDetail)) {
            Write-Host ("        {0}" -f $PSItem.FailDetail) -ForegroundColor DarkRed
        }
    }
}

Write-Host ''
Write-Host 'Test safes created (retained per vault policy — not deleted):' -ForegroundColor Yellow
Write-Host "  $safe1Name" -ForegroundColor Yellow
Write-Host "  $safe2Name" -ForegroundColor Yellow
Write-Host "  $safe3Name  (named SafeConfigSet 'alt')" -ForegroundColor Yellow
Write-Host "  $safe4Name  (invalid SafeConfigSet fallback — only if T13 passed)" -ForegroundColor Yellow
Write-Host ''

#endregion

exit $failedCount
