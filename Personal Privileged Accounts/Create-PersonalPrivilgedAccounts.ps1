#Requires -Version 5.1
<#
.SYNOPSIS
    Creates personal privileged accounts and their dedicated safes in CyberArk using the v2 REST API.
.DESCRIPTION
    Reads a CSV of privileged accounts, creates a personal safe per user (if it does not already
    exist), adds the account owner and any configured default members, then bulk-onboards all
    accounts via the CyberArk Bulk Accounts API.

    Configuration is layered (lowest to highest priority):
      1. Script baseline defaults
      2. PersonalPrivilegedAccounts.json — SafeConfigSet.default / UserConfigSet.default
      3. Named config sets  (-SafeConfigSet / -UserConfigSet)
      4. Explicit parameters (always win)

    Supports CyberArk on-premises (cyberark / ldap / radius) and Privilege Cloud
    (pass a pre-obtained PCloud token via -logonToken).
.PARAMETER PVWAURL
    Base URL of the CyberArk PVWA (e.g. https://pvwa.company.com/PasswordVault).
    Not required when -logonToken is a PCloud header hashtable.
.PARAMETER AuthenticationType
    Authentication type for on-premises logon: cyberark | ldap | radius. Default: cyberark.
.PARAMETER OTP
    RADIUS one-time password. Appended to the password with a comma delimiter.
.PARAMETER PVWACredentials
    PSCredential for on-premises authentication. If omitted, an interactive prompt is shown.
.PARAMETER logonToken
    Pre-obtained logon token (string or hashtable). When supplied, logon/logoff are skipped.
    Use for Privilege Cloud tokens obtained from Get-IdentityHeader.
.PARAMETER DisableCertificateValidation
    Bypasses SSL certificate validation. Use only in test environments.
.PARAMETER SafeNamePattern
    Safe name pattern containing exactly one wildcard (*). The asterisk is replaced by the user
    name from each CSV row. Default: *_ADM. Overrides the config file value.
.PARAMETER PlatformID
    Default platform ID for accounts that do not specify one in the CSV. Default: WinDomain.
    Overrides the config file value.
.PARAMETER CSVPath
    Path to the accounts CSV file. If omitted, a file picker dialog is shown.
.PARAMETER ConfigPath
    Path to PersonalPrivilegedAccounts.json. If omitted, the script looks in its own directory.
.PARAMETER SafeConfigSet
    Named set within SafeConfigSet in the config file to apply. Defaults to the "default" set.
.PARAMETER UserConfigSet
    Named set within UserConfigSet in the config file to apply. Defaults to the "default" set.
.PARAMETER CPMName
    CPM name for new safes. Overrides the config file value.
.PARAMETER NumberOfVersionsRetention
    Number of password versions to retain. Mutually exclusive with -NumberOfDaysRetention.
    Overrides the config file value.
.PARAMETER NumberOfDaysRetention
    Number of days to retain passwords. Mutually exclusive with -NumberOfVersionsRetention.
    Wins when both are supplied. Overrides the config file value.
.PARAMETER FallbackOnInvalidConfigSet
    When a CSV row specifies a SafeConfigSet or UserConfigSet that does not exist in the
    config file, log a warning and fall back to the base resolved config instead of skipping
    the row. By default (without this switch) an invalid set name is treated as an error
    and the row is skipped.
.OUTPUTS
    None. Progress and results are written to the log file and console.
.EXAMPLE
    .\Create-PersonalPrivilgedAccounts.ps1 -PVWAURL https://pvwa.company.com -CSVPath .\accounts.csv

    Authenticates interactively and onboards accounts using baseline defaults.
.EXAMPLE
    $params = @{
        PVWAURL         = 'https://pvwa.company.com'
        SafeConfigSet   = 'prod'
        UserConfigSet   = 'prod'
        CSVPath         = '.\accounts.csv'
        PVWACredentials = (Get-Credential)
    }
    .\Create-PersonalPrivilgedAccounts.ps1 @params

    Applies the "prod" named config sets for safe and user settings.
.EXAMPLE
    $identityParams = @{
        IdentityTenantURL   = 'https://tenant.id.cyberark.cloud'
        PCloudTenantAPIURL  = 'https://tenant.privilegecloud.cyberark.cloud'
    }
    $token = Get-IdentityHeader @identityParams
    .\Create-PersonalPrivilgedAccounts.ps1 -logonToken $token -CSVPath .\accounts.csv

    Uses a pre-obtained Privilege Cloud token; no logon/logoff is performed.
.NOTES
    Version:       2.0
    Requires:      PowerShell 5.1+, CyberArk PVWA v12.1+ (v2 REST API)
    Related files: PersonalPrivilegedAccounts.json (config), accounts CSV
#>
[CmdletBinding()]
param
(
    #region Connection parameters
    [Parameter(Mandatory = $false, HelpMessage = 'Please enter your PVWA address (e.g. https://pvwa.mydomain.com/PasswordVault)')]
    [Alias('url')]
    [ValidateNotNullOrEmpty()]
    [String]$PVWAURL,

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Authentication type (Default:CyberArk)')]
    [ValidateSet('cyberark', 'ldap', 'radius')]
    [String]$AuthenticationType = 'cyberark',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the RADIUS OTP')]
    [String]$OTP,

    [Parameter(Mandatory = $false, HelpMessage = 'PSCredential for on-prem authentication. If omitted, will prompt interactively.')]
    [PSCredential]$PVWACredentials,

    [Parameter(Mandatory = $false, HelpMessage = 'Pre-obtained logon token (string or hashtable). Skips logon/logoff. Use for PCloud tokens from Get-IdentityHeader.')]
    $logonToken,

    # Use this switch to Disable SSL verification (NOT RECOMMENDED)
    [Parameter(Mandatory = $false)]
    [Switch]$DisableCertificateValidation,
    #endregion

    #region Safe / Account parameters
    [Parameter(Mandatory = $false, HelpMessage = 'Enter the safe name pattern to use (must contain exactly one *)')]
    [Alias('pattern')]
    [ValidateScript({ ($_.ToCharArray() | Where-Object { $PSItem -eq '*' } | Measure-Object).Count -eq 1 })]
    [string]$SafeNamePattern = '*_ADM',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Platform ID (Default:WinDomain)')]
    [string]$PlatformID = 'WinDomain',

    [Parameter(Mandatory = $false, HelpMessage = 'Enter the Accounts CSV path')]
    [ValidateScript( { Test-Path -Path $_ -PathType Leaf -IsValid })]
    [Alias('path')]
    [string]$CSVPath,
    #endregion

    #region Config / retention overrides
    [Parameter(Mandatory = $false, HelpMessage = 'Path to PersonalPrivilegedAccounts.json config file. If omitted, looks for the file in the script directory.')]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false, HelpMessage = 'Named set within SafeConfigSet to use. Defaults to the "default" set.')]
    [string]$SafeConfigSet,

    [Parameter(Mandatory = $false, HelpMessage = 'Named set within UserConfigSet to use. Defaults to the "default" set.')]
    [string]$UserConfigSet,

    [Parameter(Mandatory = $false, HelpMessage = 'CPM name override. Overrides config file value.')]
    [string]$CPMName,

    [Parameter(Mandatory = $false, HelpMessage = 'Number of password versions to retain. Mutually exclusive with NumberOfDaysRetention. Overrides config.')]
    [ValidateRange(1, 999)]
    [int]$NumberOfVersionsRetention,

    [Parameter(Mandatory = $false, HelpMessage = 'Number of days to retain passwords. Mutually exclusive with NumberOfVersionsRetention. Overrides config. Wins if both supplied.')]
    [ValidateRange(1, 3650)]
    [int]$NumberOfDaysRetention,
    #endregion

    [Parameter(Mandatory = $false,
        HelpMessage = 'When a CSV row names a SafeConfigSet or UserConfigSet that does not exist, warn and fall back to base config instead of skipping the row.')]
    [switch]$FallbackOnInvalidConfigSet,

    #region Troubleshooting parameters
    [Parameter(Mandatory = $false, DontShow = $true,
        HelpMessage = 'Write a separate verbose log file alongside the main log. Intended for deep troubleshooting only.')]
    [switch]$UseVerboseFile
    #endregion
)

# Get Script Location
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$scriptParamsStr        = ($PSBoundParameters.GetEnumerator() | ForEach-Object { '-{0} ''{1}''' -f $PSItem.Key, $PSItem.Value }) -join ' '
$script:g_ScriptCommand = '{0} {1}' -f $ScriptFullPath, $scriptParamsStr

# Script Version
$ScriptVersion = '2.0'

# Set Log file path
$LOG_FILE_PATH = "$ScriptLocation\PersonalPrivilegedAccounts.log"

$InDebug   = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

# Baseline defaults (lowest priority - overridden by config then by parameters)
$script:DEFAULT_CPM_NAME         = 'PasswordManager'
$script:DEFAULT_DAYS_RETENTION   = 7
$script:DEFAULT_SAFE_PATTERN     = '*_ADM'
$script:DEFAULT_PLATFORM_ID      = 'WinDomain'

# Global script state
$script:g_LogonHeader    = $null
$script:g_SSLChanged     = $false
$script:g_LogAccountName = ''
$script:g_CsvDefaultPath = Join-Path -Path ([Environment]::GetFolderPath('UserProfile')) -ChildPath 'Downloads'
$script:g_DefaultUsers   = @('Master', 'Batch', 'Backup Users', 'Auditors', 'Operators', 'DR Users',
    'Notification Engines', 'PVWAGWAccounts', 'PVWAGWUser', 'PVWAAppUser', 'PasswordManager')
$script:g_ShouldLogoff   = $true   # set to $false when $logonToken is passed in
$script:Config           = $null   # populated by Import-ScriptConfig
$script:g_JsonContent    = $null   # raw parsed JSON; retained for per-row config lookups

# Global URLs - populated by Initialize-ScriptURLs after PVWA URL is normalized
$script:URL_PVWAAPI          = $null
$script:URL_Logon            = $null
$script:URL_Logoff           = $null
$script:URL_Safes            = $null
$script:URL_SafeDetails      = $null
$script:URL_SafeMembers      = $null
$script:URL_BulkAccounts     = $null
$script:URL_BulkAccountsTask = $null

#region Functions

#region Writer Functions
function Remove-SensitiveData {
    <#
.SYNOPSIS
    Masks sensitive field values in a log message string.
.DESCRIPTION
    Replaces values of known sensitive fields (password, secret, access_token,
    Authorization, Token, etc.) with ****.
    Set $global:LogSensitiveData = $true to bypass masking for debugging.
.PARAMETER message
    The message string to sanitize.
#>
    [CmdletBinding()]
    param (
        [Alias('MSG', 'value', 'string')]
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$message
    )
    begin {
        $cleanedMessage = $message
    }
    process {
        if ($global:LogSensitiveData -eq $true) {
            return $message
        }
        $checkFor = @('password', 'secret', 'NewCredentials', 'access_token', 'client_secret', 'auth', 'Authorization', 'Answer', 'Token')
        $checkFor | ForEach-Object {
            if ($cleanedMessage -imatch "[{\\""']{2,}\s{0,}$PSitem\s{0,}[\\""']{2,}\s{0,}[:=][\\""']{2,}\s{0,}(?<Sensitive>.*?)\s{0,}[\\""']{2,}(?=[,:;])") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
            elseif ($cleanedMessage -imatch "[""']{1,}\s{0,}$PSitem\s{0,}[""']{1,}\s{0,}[:=][""']{1,}\s{0,}(?<Sensitive>.*?)\s{0,}[""']{1,}") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
            elseif ($cleanedMessage -imatch "(?:\s{0,}$PSitem\s{0,}[:=])\s{0,}(?<Sensitive>.*?)(?=; |:|,|}|\))") {
                $cleanedMessage = $cleanedMessage.Replace($Matches['Sensitive'], '****')
            }
        }
    }
    end {
        return $cleanedMessage
    }
}

Function Write-LogMessage {
    <#
.SYNOPSIS
    Method to log a message on screen and in a log file.
.DESCRIPTION
    Logs to file and writes coloured output to the screen.
    Supports verbose file, call stack tracing, and sensitive data masking.
.PARAMETER MSG
    The message to log.
.PARAMETER Header
    Write a header separator before the message.
.PARAMETER SubHeader
    Write a sub-header separator before the message.
.PARAMETER Footer
    Write a footer separator after the message.
.PARAMETER type
    Info | Warning | Error | Debug | Verbose  (default: Info)
.PARAMETER LogFile
    Log file path. Defaults to $LOG_FILE_PATH.
.PARAMETER pad
    Column width for verbose alignment (default: 20).
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug', 'Verbose')]
        [String]$type = 'Info',
        [Parameter(Mandatory = $false)]
        [int]$pad = 20
    )

    $verboseFile = $($LOG_FILE_PATH.replace('.log', '_Verbose.log'))
    try {
        If ($Header) {
            '=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '======================================='
        }
        ElseIf ($SubHeader) {
            '------------------------------------' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '------------------------------------'
        }

        $LogTime    = "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')]`t"
        $msgToWrite = "$LogTime"
        $writeToFile = $true

        if ([string]::IsNullOrEmpty($Msg)) { $Msg = 'N/A' }
        $Msg = Remove-SensitiveData -message $Msg

        switch ($type) {
            'Info' {
                Write-Host $MSG
                $msgToWrite += "[INFO]`t`t$Msg"
            }
            'Warning' {
                Write-Host $MSG -ForegroundColor DarkYellow
                $msgToWrite += "[WARNING]`t$Msg"
                if ($UseVerboseFile) { $msgToWrite | Out-File -Append -FilePath $verboseFile }
            }
            'Error' {
                Write-Host $MSG -ForegroundColor Red
                $msgToWrite += "[ERROR]`t`t$Msg"
                if ($UseVerboseFile) { $msgToWrite | Out-File -Append -FilePath $verboseFile }
            }
            'Debug' {
                if ($InDebug -or $InVerbose) {
                    Write-Debug $MSG
                    $writeToFile = $true
                    $msgToWrite += "[DEBUG]`t`t$Msg"
                }
                else { $writeToFile = $false }
            }
            'Verbose' {
                if ($InVerbose -or $UseVerboseFile) {
                    $arrMsg = $Msg.split(":`t", 2)
                    if ($arrMsg.Count -gt 1) {
                        $Msg = $arrMsg[0].PadRight($pad) + $arrMsg[1]
                    }
                    $msgToWrite += "[VERBOSE]`t$Msg"
                    if ($global:IncludeCallStack) {
                        function Get-CallStack {
                            $stack = ''
                            $excludeItems = @('Write-LogMessage', 'Get-CallStack', '<ScriptBlock>')
                            Get-PSCallStack | ForEach-Object {
                                if ($PSItem.Command -notin $excludeItems) {
                                    $command = $PSItem.Command
                                    if ($command -eq $Global:scriptName) { $command = 'Base' }
                                    elseif ([string]::IsNullOrEmpty($command)) { $command = '**Blank**' }
                                    $stack = $stack + "$command $($PSItem.Location); "
                                }
                            }
                            return $stack
                        }
                        $stack    = Get-CallStack
                        $stackMsg = "CallStack:`t$stack"
                        $arrStack = $stackMsg.split(":`t", 2)
                        if ($arrStack.Count -gt 1) {
                            $stackMsg = $arrStack[0].PadRight($pad) + $arrStack[1].trim()
                        }
                        Write-Verbose $stackMsg
                        $msgToWrite += "`n$LogTime[STACK]`t`t$stackMsg"
                    }
                    if ($InVerbose) { Write-Verbose $MSG }
                    else { $writeToFile = $false }
                    if ($UseVerboseFile) { $msgToWrite | Out-File -Append -FilePath $verboseFile }
                }
                else { $writeToFile = $false }
            }
        }
        if ($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH }
        If ($Footer) {
            '=======================================' | Out-File -Append -FilePath $LOG_FILE_PATH
            Write-Host '======================================='
        }
    }
    catch {
        Write-Error "Error writing log: $($PSItem.Exception.Message)"
    }
}

Function Join-ExceptionMessage {
    <#
.SYNOPSIS
    Formats an exception and all inner exceptions into a single readable string.
.DESCRIPTION
    Walks the InnerException chain and appends each level with arrow notation
    (->Source; Message) for easy log output.
.PARAMETER e
    The Exception object to format.
.OUTPUTS
    System.String
#>
    param (
        [Parameter(Mandatory = $true)]
        [Exception]$e
    )
    $msg = 'Source:{0}; Message: {1}' -f $e.Source, $e.Message
    while ($e.InnerException) {
        $e    = $e.InnerException
        $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
    }
    return $msg
}
#endregion Writer Functions

#region Helper Functions
function Format-PVWAURL {
    <#
.SYNOPSIS
    Normalizes a PVWA URL ensuring correct scheme and /PasswordVault/ path.
.DESCRIPTION
    - Upgrades http:// to https://
    - Corrects malformed Privilege Cloud URLs (.cyberark.cloud/privilegecloud/...)
    - Appends /PasswordVault/ if missing
.PARAMETER PVWAURL
    The raw PVWA URL to normalize.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$PVWAURL
    )
    if ($PVWAURL -match '^(?<scheme>https:\/\/|http:\/\/|).*$') {
        if ('http://' -eq $Matches['scheme']) {
            $PVWAURL = $PVWAURL.Replace('http://', 'https://')
            Write-LogMessage -type Warning -MSG "Detected insecure URL scheme. Updated to: $PVWAURL"
        }
        elseif ([string]::IsNullOrEmpty($Matches['scheme'])) {
            $PVWAURL = "https://$PVWAURL"
            Write-LogMessage -type Warning -MSG "Detected missing URL scheme. Updated to: $PVWAURL"
        }
    }
    if ($PVWAURL -match '^(?:https|http):\/\/(?<sub>.*).cyberark.(?<top>cloud|com)\/privilegecloud.*$') {
        $PVWAURL = "https://$($Matches['sub']).privilegecloud.cyberark.$($Matches['top'])/PasswordVault/"
        Write-LogMessage -type Warning -MSG "Detected improperly formatted Privilege Cloud URL. Updated to: $PVWAURL"
    }
    elseif ($PVWAURL -notmatch '^.*PasswordVault(?:\/|)$') {
        $PVWAURL = "$PVWAURL/PasswordVault/"
        Write-LogMessage -type Warning -MSG "Detected missing /PasswordVault/. Updated to: $PVWAURL"
    }
    return $PVWAURL
}

function Initialize-ScriptURLs {
    <#
.SYNOPSIS
    Initializes all REST API URL variables from the normalized $PVWAURL.
.DESCRIPTION
    Populates script-scoped URL variables used by all Invoke-Rest calls.
    Must be called after $PVWAURL has been normalized by Format-PVWAURL.
#>
    $script:URL_PVWAAPI  = $PVWAURL + 'api/'
    $authBase            = $script:URL_PVWAAPI + 'auth'
    $script:URL_Logon    = $authBase + "/$AuthenticationType/Logon"
    $script:URL_Logoff   = $authBase + '/Logoff'
    $script:URL_Safes            = $script:URL_PVWAAPI + 'Safes'
    $script:URL_SafeDetails      = $script:URL_Safes + '/{0}'
    $script:URL_SafeMembers      = $script:URL_SafeDetails + '/Members'
    $script:URL_BulkAccounts     = $script:URL_PVWAAPI + 'BulkActions/Accounts'
    $script:URL_BulkAccountsTask = $script:URL_PVWAAPI + 'BulkActions/Accounts/{0}'
    Write-LogMessage -type Debug -MSG "URLs initialized. Base API: $($script:URL_PVWAAPI)"
}

function Import-ScriptConfig {
    <#
.SYNOPSIS
    Loads PersonalPrivilegedAccounts.json and resolves the active named sets.
.DESCRIPTION
    The config file has two independent top-level sections: SafeConfigSet and
    UserConfigSet. Each section has its own "default" named set plus any number
    of additional named sets.

    Resolution order (lowest to highest priority):
      1. Script baseline defaults
      2. SafeConfigSet.default  /  UserConfigSet.default
      3. SafeConfigSet.<name>   (if -SafeConfigSet supplied)
         UserConfigSet.<name>   (if -UserConfigSet supplied)
      4. Explicit command-line parameters (always win)

    NumberOfVersionsRetention and NumberOfDaysRetention are mutually exclusive.
    If both are present after all layers are merged, NumberOfDaysRetention wins
    and a warning is emitted. DefaultSafeMembers is replaced wholesale by the
    named set when it defines the key; otherwise falls back to the default set.
#>
    # Start with baseline defaults
    $resolved = @{
        CPMName                   = $script:DEFAULT_CPM_NAME
        NumberOfVersionsRetention = $null
        NumberOfDaysRetention     = $script:DEFAULT_DAYS_RETENTION
        SafeNamePattern           = $script:DEFAULT_SAFE_PATTERN
        UserDefaults              = @{ accountPlatform = $script:DEFAULT_PLATFORM_ID }
        DefaultSafeMembers        = @()
        RoleConfigSets            = @{}
    }

    # Locate config file
    $effectiveConfigPath = $null
    if (-not [string]::IsNullOrEmpty($ConfigPath) -and (Test-Path -Path $ConfigPath -PathType Leaf)) {
        $effectiveConfigPath = $ConfigPath
    }
    else {
        $autoConfig = Join-Path -Path $ScriptLocation -ChildPath 'PersonalPrivilegedAccounts.json'
        if (Test-Path -Path $autoConfig -PathType Leaf) {
            $effectiveConfigPath = $autoConfig
        }
    }

    if (-not [string]::IsNullOrEmpty($effectiveConfigPath)) {
        Write-LogMessage -type Info -MSG "Loading config from: $effectiveConfigPath"
        try {
            $jsonContent = Get-Content -Path $effectiveConfigPath -Raw | ConvertFrom-Json
            $script:g_JsonContent = $jsonContent   # retained for per-row SafeConfigSet / UserConfigSet lookups

            # Load all RoleConfigSet entries (flat dictionary - no named-set layering)
            if ($null -ne $jsonContent.RoleConfigSet) {
                $jsonContent.RoleConfigSet.PSObject.Properties | ForEach-Object {
                    $roleName  = $PSItem.Name
                    $rolePerms = @{}
                    $PSItem.Value.PSObject.Properties | ForEach-Object { $rolePerms[$PSItem.Name] = $PSItem.Value }
                    $resolved.RoleConfigSets[$roleName] = $rolePerms
                    Write-LogMessage -type Verbose -MSG "Import-ScriptConfig:`tLoaded RoleConfigSet: $roleName"
                }
            }

            function Merge-SafeSet {
                param([Parameter(Mandatory = $true)] $Set)
                if (-not [string]::IsNullOrEmpty($Set.CPMName)) { $resolved.CPMName = $Set.CPMName }
                if ($null -ne $Set.NumberOfVersionsRetention) {
                    $resolved.NumberOfVersionsRetention = $Set.NumberOfVersionsRetention
                    $resolved.NumberOfDaysRetention     = $null
                }
                if ($null -ne $Set.NumberOfDaysRetention) {
                    $resolved.NumberOfDaysRetention     = $Set.NumberOfDaysRetention
                    $resolved.NumberOfVersionsRetention = $null
                }
                if (-not [string]::IsNullOrEmpty($Set.SafeNamePattern)) { $resolved.SafeNamePattern   = $Set.SafeNamePattern }
                if ($null -ne $Set.DefaultSafeMembers)                   { $resolved.DefaultSafeMembers = $Set.DefaultSafeMembers }
            }

            # Keys match CSV column names exactly; any key is accepted as a default
            function Merge-UserSet {
                param([Parameter(Mandatory = $true)] $Set)
                $Set.PSObject.Properties | ForEach-Object {
                    $resolved.UserDefaults[$PSItem.Name] = $PSItem.Value
                }
            }

            # Layer 2: SafeConfigSet.default
            if ($null -ne $jsonContent.SafeConfigSet -and $null -ne $jsonContent.SafeConfigSet.default) {
                Write-LogMessage -type Verbose -MSG 'Import-ScriptConfig:`tApplying SafeConfigSet.default'
                Merge-SafeSet -Set $jsonContent.SafeConfigSet.default
            }

            # Layer 2: UserConfigSet.default
            if ($null -ne $jsonContent.UserConfigSet -and $null -ne $jsonContent.UserConfigSet.default) {
                Write-LogMessage -type Verbose -MSG 'Import-ScriptConfig:`tApplying UserConfigSet.default'
                Merge-UserSet -Set $jsonContent.UserConfigSet.default
            }

            # Layer 3: SafeConfigSet named set (if -SafeConfigSet supplied)
            if (-not [string]::IsNullOrEmpty($SafeConfigSet)) {
                $safeSet = $jsonContent.SafeConfigSet.PSObject.Properties[$SafeConfigSet]
                if ($null -ne $safeSet) {
                    Write-LogMessage -type Info -MSG "Applying SafeConfigSet: $SafeConfigSet"
                    Merge-SafeSet -Set $safeSet.Value
                }
                else {
                    Write-LogMessage -type Warning -MSG "SafeConfigSet '$SafeConfigSet' not found in config. Using 'default'."
                }
            }

            # Layer 3: UserConfigSet named set (if -UserConfigSet supplied)
            if (-not [string]::IsNullOrEmpty($UserConfigSet)) {
                $userSet = $jsonContent.UserConfigSet.PSObject.Properties[$UserConfigSet]
                if ($null -ne $userSet) {
                    Write-LogMessage -type Info -MSG "Applying UserConfigSet: $UserConfigSet"
                    Merge-UserSet -Set $userSet.Value
                }
                else {
                    Write-LogMessage -type Warning -MSG "UserConfigSet '$UserConfigSet' not found in config. Using 'default'."
                }
            }
        }
        catch {
            Write-LogMessage -type Warning -MSG "Failed to load config '$effectiveConfigPath': $($PSItem.Exception.Message). Using baseline defaults."
        }
    }
    else {
        Write-LogMessage -type Info -MSG 'No config file found. Using baseline defaults.'
    }

    # Layer 4: explicit parameter overrides (always win)
    if ($PSBoundParameters.ContainsKey('CPMName')) {
        $resolved.CPMName = $CPMName
    }
    if ($PSBoundParameters.ContainsKey('SafeNamePattern')) {
        $resolved.SafeNamePattern = $SafeNamePattern
    }
    if ($PSBoundParameters.ContainsKey('PlatformID')) {
        $resolved.UserDefaults['accountPlatform'] = $PlatformID
    }
    if ($PSBoundParameters.ContainsKey('NumberOfVersionsRetention')) {
        $resolved.NumberOfVersionsRetention = $NumberOfVersionsRetention
        $resolved.NumberOfDaysRetention     = $null
    }
    if ($PSBoundParameters.ContainsKey('NumberOfDaysRetention')) {
        $resolved.NumberOfDaysRetention     = $NumberOfDaysRetention
        $resolved.NumberOfVersionsRetention = $null
    }

    # Mutual-exclusion final guard: if somehow both survived, NumberOfDaysRetention wins
    if ($null -ne $resolved.NumberOfVersionsRetention -and $null -ne $resolved.NumberOfDaysRetention) {
        Write-Warning "Both NumberOfVersionsRetention ($($resolved.NumberOfVersionsRetention)) and NumberOfDaysRetention ($($resolved.NumberOfDaysRetention)) are set. NumberOfDaysRetention wins. NumberOfVersionsRetention will be ignored."
        $resolved.NumberOfVersionsRetention = $null
    }

    # Fallback: if neither retention value is set, use baseline default
    if ($null -eq $resolved.NumberOfVersionsRetention -and $null -eq $resolved.NumberOfDaysRetention) {
        $resolved.NumberOfDaysRetention = $script:DEFAULT_DAYS_RETENTION
    }

    $script:Config = $resolved
    Write-LogMessage -type Debug -MSG "Resolved config: CPM=$($script:Config.CPMName), VersionsRetention=$($script:Config.NumberOfVersionsRetention), DaysRetention=$($script:Config.NumberOfDaysRetention), SafePattern=$($script:Config.SafeNamePattern), UserDefaults=$($script:Config.UserDefaults.Keys -join ','), DefaultMembers=$($script:Config.DefaultSafeMembers.Count), CustomRoles=$($script:Config.RoleConfigSets.Count)"
}

function Get-RowConfig {
    <#
.SYNOPSIS
    Returns a per-row config hashtable by overlaying named SafeConfigSet / UserConfigSet entries
    from the parsed JSON on top of the base resolved config.
.DESCRIPTION
    Called once per CSV row when that row has a non-blank SafeConfigSet or UserConfigSet value.
    Starts from a shallow copy of $script:Config (so CLI param overrides are preserved as the
    base), then merges the named set(s) from $script:g_JsonContent on top.

    When a named set is not found in the JSON:
      - Default behaviour  : returns $null  (caller logs Error and skips the row)
      - -FallbackOnInvalidConfigSet switch : logs Warning and returns the unmodified base config
.PARAMETER RowSafeConfigSet
    Value of the SafeConfigSet column for this CSV row. May be empty.
.PARAMETER RowUserConfigSet
    Value of the UserConfigSet column for this CSV row. May be empty.
.OUTPUTS
    System.Collections.Hashtable, or $null when an invalid set name is encountered and
    -FallbackOnInvalidConfigSet was not specified.
#>
    param(
        [Parameter(Mandatory = $false)] [string]$RowSafeConfigSet = '',
        [Parameter(Mandatory = $false)] [string]$RowUserConfigSet = ''
    )

    # Shallow copy of the base config so we never mutate $script:Config
    $resolved = @{
        CPMName                   = $script:Config.CPMName
        NumberOfVersionsRetention = $script:Config.NumberOfVersionsRetention
        NumberOfDaysRetention     = $script:Config.NumberOfDaysRetention
        SafeNamePattern           = $script:Config.SafeNamePattern
        UserDefaults              = $script:Config.UserDefaults.Clone()
        DefaultSafeMembers        = $script:Config.DefaultSafeMembers   # replaced wholesale; never mutated
        RoleConfigSets            = $script:Config.RoleConfigSets        # read-only reference
    }

    # Apply SafeConfigSet override
    if (-not [string]::IsNullOrEmpty($RowSafeConfigSet)) {
        if ($null -eq $script:g_JsonContent) {
            Write-LogMessage -type Warning -MSG "Get-RowConfig: SafeConfigSet '$RowSafeConfigSet' requested but no config file was loaded — using base config"
        }
        else {
            $safeSet = $script:g_JsonContent.SafeConfigSet.PSObject.Properties[$RowSafeConfigSet]
            if ($null -eq $safeSet) {
                if ($FallbackOnInvalidConfigSet) {
                    Write-LogMessage -type Warning -MSG "Get-RowConfig: SafeConfigSet '$RowSafeConfigSet' not found in config — falling back to base config"
                }
                else {
                    Write-LogMessage -type Error -MSG "Get-RowConfig: SafeConfigSet '$RowSafeConfigSet' not found in config — row will be skipped. Use -FallbackOnInvalidConfigSet to fall back instead."
                    return $null
                }
            }
            else {
                $set = $safeSet.Value
                if (-not [string]::IsNullOrEmpty($set.CPMName))             { $resolved.CPMName = $set.CPMName }
                if ($null -ne $set.NumberOfVersionsRetention) {
                    $resolved.NumberOfVersionsRetention = $set.NumberOfVersionsRetention
                    $resolved.NumberOfDaysRetention     = $null
                }
                if ($null -ne $set.NumberOfDaysRetention) {
                    $resolved.NumberOfDaysRetention     = $set.NumberOfDaysRetention
                    $resolved.NumberOfVersionsRetention = $null
                }
                if (-not [string]::IsNullOrEmpty($set.SafeNamePattern))     { $resolved.SafeNamePattern    = $set.SafeNamePattern }
                if ($null -ne $set.DefaultSafeMembers)                       { $resolved.DefaultSafeMembers = $set.DefaultSafeMembers }
                Write-LogMessage -type Verbose -MSG "Get-RowConfig: Applied SafeConfigSet '$RowSafeConfigSet'"
            }
        }
    }

    # Apply UserConfigSet override
    if (-not [string]::IsNullOrEmpty($RowUserConfigSet)) {
        if ($null -eq $script:g_JsonContent) {
            Write-LogMessage -type Warning -MSG "Get-RowConfig: UserConfigSet '$RowUserConfigSet' requested but no config file was loaded — using base config"
        }
        else {
            $userSet = $script:g_JsonContent.UserConfigSet.PSObject.Properties[$RowUserConfigSet]
            if ($null -eq $userSet) {
                if ($FallbackOnInvalidConfigSet) {
                    Write-LogMessage -type Warning -MSG "Get-RowConfig: UserConfigSet '$RowUserConfigSet' not found in config — falling back to base config"
                }
                else {
                    Write-LogMessage -type Error -MSG "Get-RowConfig: UserConfigSet '$RowUserConfigSet' not found in config — row will be skipped. Use -FallbackOnInvalidConfigSet to fall back instead."
                    return $null
                }
            }
            else {
                $userSet.Value.PSObject.Properties | ForEach-Object {
                    $resolved.UserDefaults[$PSItem.Name] = $PSItem.Value
                }
                Write-LogMessage -type Verbose -MSG "Get-RowConfig: Applied UserConfigSet '$RowUserConfigSet'"
            }
        }
    }

    return $resolved
}

Function ConvertTo-URL {
    <#
.SYNOPSIS
    RFC 3986-encodes a string for safe use in a URL path segment.
.PARAMETER sText
    The text to encode. Empty or null values are returned unchanged.
.OUTPUTS
    System.String
#>
    param (
        [Parameter(Mandatory = $false)]
        [string]$sText
    )
    if (-not [string]::IsNullOrEmpty($sText)) {
        Write-LogMessage -type Verbose -MSG "ConvertTo-URL:`tEncoding: $sText"
        return [URI]::EscapeDataString($sText)
    }
    else { return $sText }
}

Function ConvertTo-Bool {
    <#
.SYNOPSIS
    Converts a CSV string value to a Boolean.
.DESCRIPTION
    Accepts yes/y ($true) and no/n ($false) in addition to the standard true/false
    values accepted by [bool]::TryParse(). Case-insensitive.
    Returns $false for any unrecognized value.
.PARAMETER txt
    The string value to convert.
.OUTPUTS
    System.Boolean
#>
    param (
        [Parameter(Mandatory = $false)]
        [string]$txt
    )
    $retBool = $false
    if ($txt -match '^y$|^yes$')      { $retBool = $true }
    elseif ($txt -match '^n$|^no$')   { $retBool = $false }
    else { [bool]::TryParse($txt, [ref]$retBool) | Out-Null }
    return $retBool
}

Function Get-TrimmedString {
    <#
.SYNOPSIS
    Returns a trimmed string; passes $null through unchanged.
.PARAMETER sText
    The string to trim. $null is returned as-is.
.OUTPUTS
    System.String
#>
    param (
        [Parameter(Mandatory = $false)]
        [string]$sText
    )
    if ($null -ne $sText) { return $sText.Trim() }
    return $sText
}

Function Get-PersonalSafeNameFromPattern {
    <#
.SYNOPSIS
    Returns the personal safe name by substituting a user name into the active safe name pattern.
.DESCRIPTION
    Replaces the single wildcard (*) in $SafeNamePattern with the supplied user name.
    For example, pattern *_ADM with user jsmith yields jsmith_ADM.
.PARAMETER userName
    The user name to substitute for the * placeholder in the pattern.
.OUTPUTS
    System.String
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$userName
    )
    return $SafeNamePattern.Replace('*', $userName)
}

Function Disable-SSLVerification {
    <#
.SYNOPSIS
    Bypasses SSL certificate validation. Use only in test environments.
#>
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    [System.Net.ServicePointManager]::SecurityProtocol   = [System.Net.SecurityProtocolType]::Tls12
    if (-not ('DisableCertValidationCallback' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class DisableCertValidationCallback {
    public static bool ReturnTrue(object sender, X509Certificate certificate,
        X509Chain chain, SslPolicyErrors sslPolicyErrors) { return true; }
    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(DisableCertValidationCallback.ReturnTrue);
    }
}
'@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DisableCertValidationCallback]::GetDelegate()
}

function Invoke-Rest {
    <#
.SYNOPSIS
    Invokes a REST method with CyberArk-aware error handling.
.DESCRIPTION
    Wraps Invoke-RestMethod and handles:
      - HTTP 401/403: exits script with code 5
      - DNS resolution failure: exits script with code 1
      - PASWS006E / PASWS013E (auth errors): exits script with code 5
      - SFWS0002 (safe already exists): throws message string
      - SFWS0007 (safe deleted/not found): re-throws exception
      - SFWS0012 (already a member): logs verbose, re-throws
      - All others: logs and re-throws
.PARAMETER Command
    HTTP method: GET, POST, DELETE, PATCH, PUT
.PARAMETER URI
    The REST endpoint URI.
.PARAMETER Header
    Request headers hashtable.
.PARAMETER Body
    Optional request body (string or object).
.PARAMETER ErrAction
    ErrorAction preference (default: Continue).
.PARAMETER TimeoutSec
    Request timeout in seconds (default: 2700).
.PARAMETER ContentType
    Content-Type header (default: application/json).
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'DELETE', 'PATCH', 'PUT')]
        [Alias('Method')]
        [String]$Command,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$URI,
        [Parameter(Mandatory = $false)]
        [Alias('Headers')]
        $Header,
        [Parameter(Mandatory = $false)]
        $Body,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue',
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 2700,
        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json'
    )
    Write-LogMessage -type Verbose -MSG 'Invoke-Rest:`tStart'
    $restResponse = $null
    try {
        if ([string]::IsNullOrEmpty($Body)) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tGET/no-body $URI"
            $restParams = @{
                Uri         = $URI
                Method      = $Command
                Header      = $Header
                ContentType = $ContentType
                TimeoutSec  = $TimeoutSec
                ErrorAction = $ErrAction
                Verbose     = $InVerbose
                Debug       = $InDebug
            }
            $restResponse = Invoke-RestMethod @restParams
        }
        else {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$Command $URI"
            $restParams = @{
                Uri         = $URI
                Method      = $Command
                Header      = $Header
                ContentType = $ContentType
                Body        = $Body
                TimeoutSec  = $TimeoutSec
                ErrorAction = $ErrAction
                Verbose     = $InVerbose
                Debug       = $InDebug
            }
            $restResponse = Invoke-RestMethod @restParams
        }
        Write-LogMessage -type Verbose -MSG 'Invoke-Rest:`tCompleted without error'
    }
    catch {
        if ($PSItem.ErrorDetails.Message -notmatch '.*ErrorCode[\s\S]*ErrorMessage.*') {
            if ($PSItem.Exception.response.StatusCode.value__ -eq 401) {
                Write-LogMessage -type Error -MSG 'Received error 401 - Unauthorized access'
                Write-LogMessage -type Error -MSG '**** Exiting script ****' -Footer -Header
                exit 5
            }
            elseif ($PSItem.Exception.response.StatusCode.value__ -eq 403) {
                Write-LogMessage -type Error -MSG 'Received error 403 - Forbidden access'
                Write-LogMessage -type Error -MSG '**** Exiting script ****' -Footer -Header
                exit 5
            }
            elseif ($PSItem.Exception -match 'The remote name could not be resolved:') {
                Write-LogMessage -type Error -MSG 'Received error - The remote name could not be resolved'
                Write-LogMessage -type Error -MSG '**** Exiting script ****' -Footer -Header
                exit 1
            }
            else {
                throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $PSItem.Exception))
            }
        }
        $Details = ($PSItem.ErrorDetails.Message | ConvertFrom-Json)
        if ('PASWS006E' -eq $Details.ErrorCode -or 'PASWS013E' -eq $Details.ErrorCode) {
            Write-LogMessage -type Error -MSG "$($Details.ErrorMessage)"
            Write-LogMessage -type Error -MSG '**** Exiting script ****' -Footer -Header
            exit 5
        }
        elseif ('SFWS0007' -eq $Details.ErrorCode) {
            throw $PSItem.Exception
        }
        elseif ('SFWS0002' -eq $Details.ErrorCode) {
            Write-LogMessage -type Warning -MSG "$($Details.ErrorMessage)"
            throw "$($Details.ErrorMessage)"
        }
        elseif ('SFWS0012' -eq $Details.ErrorCode) {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`t$($Details.ErrorMessage)"
            throw $PSItem
        }
        else {
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tError running $Command on '$URI'"
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tMessage: $PSItem"
            Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tException: $($PSItem.Exception.Message)"
            if ($PSItem.Exception.Response) {
                Write-LogMessage -type Error -MSG "Status Code: $($PSItem.Exception.Response.StatusCode.value__)"
                Write-LogMessage -type Error -MSG "Status Description: $($PSItem.Exception.Response.StatusDescription)"
            }
            if ($($PSItem.ErrorDetails.Message | ConvertFrom-Json).ErrorMessage) {
                Write-LogMessage -type Error -MSG "Error Message: $($($PSItem.ErrorDetails.Message | ConvertFrom-Json).ErrorMessage)"
            }
            $restResponse = $null
            throw $(New-Object System.Exception ("Invoke-Rest: Error in running $Command on '$URI'", $PSItem.Exception))
        }
    }
    Write-LogMessage -type Verbose -MSG "Invoke-Rest:`tResponse: $restResponse"
    return $restResponse
}

Function Invoke-Logon {
    <#
.SYNOPSIS
    Authenticates to PVWA and returns an Authorization header hashtable.
.PARAMETER Credentials
    PSCredential for authentication.
.PARAMETER RadiusOTP
    Optional RADIUS one-time password (appended to password with comma delimiter).
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP
    )
    $BSTR = $null
    try {
        $BSTR          = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credentials.Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        $logonBody = @{
            username          = $Credentials.UserName.Replace('\', '')
            password          = $plainPassword
            concurrentSession = $true
        } | ConvertTo-Json -Compress

        if (-not [string]::IsNullOrEmpty($RadiusOTP)) {
            $logonBodyObj          = $logonBody | ConvertFrom-Json
            $logonBodyObj.password = "$plainPassword,$RadiusOTP"
            $logonBody             = $logonBodyObj | ConvertTo-Json -Compress
        }

        $logonToken = Invoke-Rest -Command POST -URI $script:URL_Logon -Body $logonBody
        $logonBody  = ''
    }
    catch {
        Throw $(New-Object System.Exception ("Invoke-Logon: $($PSItem.Exception.Response.StatusDescription)", $PSItem.Exception))
    }
    finally {
        if ($null -ne $BSTR) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) }
        $plainPassword = $null
    }

    if ([string]::IsNullOrEmpty($logonToken)) {
        Throw 'Invoke-Logon: Logon Token is Empty - Cannot login'
    }

    if ($logonToken.PSObject.Properties.Name -contains 'CyberArkLogonResult') {
        return @{Authorization = $($logonToken.CyberArkLogonResult) }
    }
    else {
        return @{Authorization = $logonToken }
    }
}

Function Invoke-Logoff {
    <#
.SYNOPSIS
    Logs off a PVWA session.
.DESCRIPTION
    Posts to the Logoff endpoint and clears $script:g_LogonHeader.
    No-ops silently when Header is $null.
.PARAMETER Header
    The logon header to use for logoff. Defaults to $script:g_LogonHeader.
#>
    param(
        [Parameter(Mandatory = $false)]
        $Header = $script:g_LogonHeader
    )
    try {
        If ($null -ne $Header) {
            Write-LogMessage -type Info -MSG 'Logoff Session...'
            Invoke-Rest -Command POST -URI $script:URL_Logoff -Header $Header | Out-Null
            $script:g_LogonHeader = $null
        }
    }
    catch {
        Throw $(New-Object System.Exception ('Invoke-Logoff: Failed to logoff session', $PSItem.Exception))
    }
}

Function Get-LogonHeader {
    <#
.SYNOPSIS
    Returns a valid logon header. For RADIUS auth, reuses an existing session.
.PARAMETER Credentials
    PSCredential for authentication.
.PARAMETER RadiusOTP
    Optional RADIUS OTP.
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials,
        [Parameter(Mandatory = $false)]
        [string]$RadiusOTP
    )
    try {
        If ([string]::IsNullOrEmpty($RadiusOTP)) {
            return $(Invoke-Logon -Credentials $Credentials)
        }
        else {
            if ([string]::IsNullOrEmpty($script:g_LogonHeader)) {
                $script:g_LogonHeader = $(Invoke-Logon -Credentials $Credentials -RadiusOTP $RadiusOTP)
            }
            return $script:g_LogonHeader
        }
    }
    catch {
        Throw $(New-Object System.Exception ('Get-LogonHeader: Error returning the logon header.', $PSItem.Exception))
    }
}

Function Open-FileDialog {
    <#
.SYNOPSIS
    Opens a Windows file picker dialog to select a CSV file.
.PARAMETER LocationPath
    The initial directory shown when the dialog opens.
.OUTPUTS
    System.String — the selected file path, or empty string if cancelled.
#>
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$LocationPath
    )
    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null
    $OpenFileDialog                  = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $LocationPath
    $OpenFileDialog.filter           = 'CSV (*.csv)| *.csv'
    $OpenFileDialog.ShowDialog()     | Out-Null
    return $OpenFileDialog.filename
}
function Get-AuthHeader {
    if ($null -ne $script:g_LogonHeader) {
        return $script:g_LogonHeader
    }
    return Get-LogonHeader -Credentials $PVWACredentials -RadiusOTP $OTP
}
#endregion Helper Functions

#region Accounts and Safes Functions
Function Get-Safe {
    <#
.SYNOPSIS
    Returns an existing safe object via the v2 REST API (/api/Safes).
.DESCRIPTION
    The v2 API returns a flat object — there is no .GetSafeResult wrapper as in v1.
    Returns $null when the safe is not found and -ErrAction SilentlyContinue is used.
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to retrieve.
.PARAMETER ErrAction
    ErrorAction preference for the underlying REST call. Default: Continue.
.OUTPUTS
    PSCustomObject — the safe details object, or $null if not found.
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Continue', 'Ignore', 'Inquire', 'SilentlyContinue', 'Stop', 'Suspend')]
        [String]$ErrAction = 'Continue'
    )
    $_safe = $null
    try {
        $accSafeURL = $script:URL_SafeDetails -f $(ConvertTo-URL $safeName)
        $_safe      = $(Invoke-Rest -URI $accSafeURL -Header $Header -Command 'GET' -ErrAction $ErrAction)
    }
    catch {
        Throw $(New-Object System.Exception ("Get-Safe: Error getting safe '$safeName' details.", $PSItem.Exception))
    }
    return $_safe
}

Function Test-Safe {
    <#
.SYNOPSIS
    Returns $true if the named safe exists, $false otherwise.
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to test.
.OUTPUTS
    System.Boolean
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName
    )
    try {
        If ($null -eq $(Get-Safe -safeName $safeName -Header $Header -ErrAction 'SilentlyContinue')) {
            Write-LogMessage -type Warning -MSG "Safe '$safeName' does not exist"
            return $false
        }
        else {
            Write-LogMessage -type Verbose -MSG "Safe '$safeName' exists"
            return $true
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Test-Safe: Error testing safe '$safeName' existence.", $PSItem.Exception))
    }
}

Function Add-Safe {
    <#
.SYNOPSIS
    Creates a new safe using the v2 REST API (/api/Safes).
.DESCRIPTION
    Sends a flat JSON body (no { safe: {} } wrapper, as required by v2).
    CPM name and retention settings are read from $script:Config.
    Only one of numberOfVersionsRetention / numberOfDaysRetention is sent
    (mutual exclusion is resolved by Import-ScriptConfig).
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to create.
.PARAMETER description
    Optional safe description.
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName,
        [Parameter(Mandatory = $false)]
        [String]$description = ''
    )
    Write-LogMessage -type Info -MSG "Creating safe '$safeName'"

    $bodySafe = @{
        safeName    = $safeName
        description = $description
        olacEnabled = $false
        managingCPM = $script:Config.CPMName
    }

    if ($null -ne $script:Config.NumberOfDaysRetention) {
        $bodySafe.numberOfDaysRetention    = $script:Config.NumberOfDaysRetention
    }
    else {
        $bodySafe.numberOfVersionsRetention = $script:Config.NumberOfVersionsRetention
    }

    $restBody = $bodySafe | ConvertTo-Json -Depth 3 -Compress

    try {
        $createSafeResult = $(Invoke-Rest -URI $script:URL_Safes -Header $Header -Command 'POST' -Body $restBody)
        if ($createSafeResult) {
            Write-LogMessage -type Debug -MSG "Safe '$safeName' created"
            return $true
        }
        else {
            Write-LogMessage -type Error -MSG 'Safe creation failed - skipping account creation'
            return $false
        }
    }
    catch {
        Throw $(New-Object System.Exception ("Add-Safe: Failed to create safe '$safeName'", $PSItem.Exception))
    }
}

Function Add-SafeOwner {
    <#
.SYNOPSIS
    Adds a member to a safe using a named role or custom permissions (v2 REST API flat permissions object).
.DESCRIPTION
    Permission source priority (highest wins):
      1. -CustomPermissions hashtable  — inline permissions object passed directly
      2. -ownerRole named role         — one of the 5 built-in roles:
           ConnectOnly, ReadOnly, Approver, AccountsManager, Full

    Uses v2 flat permissions object. requestsAuthorizationLevel1 and
    requestsAuthorizationLevel2 are separate boolean fields.
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to add the member to.
.PARAMETER ownerName
    Vault or LDAP user/group name.
.PARAMETER ownerRole
    ConnectOnly | ReadOnly | Approver | AccountsManager | Full
    Not required when -CustomPermissions is supplied.
.PARAMETER CustomPermissions
    Hashtable of all 22 permission fields. Overrides -ownerRole when supplied.
    Can come from a RoleConfigSet entry or an inline Permissions block.
.PARAMETER memberSearchInLocation
    LDAP directory to search (default: Vault).
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$safeName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ownerName,
        [Parameter(Mandatory = $false)]
        [ValidateSet('ConnectOnly', 'ReadOnly', 'Approver', 'AccountsManager', 'Full')]
        [string]$ownerRole,
        [Parameter(Mandatory = $false)]
        [hashtable]$CustomPermissions,
        [Parameter(Mandatory = $false)]
        [string]$memberSearchInLocation = 'Vault'
    )

    if ($null -eq $CustomPermissions -and [string]::IsNullOrEmpty($ownerRole)) {
        Throw "Add-SafeOwner: Either -ownerRole or -CustomPermissions must be supplied for '$ownerName' on '$safeName'."
    }

    Write-LogMessage -type Verbose -MSG "Adding member '$ownerName' to safe '$safeName' (role: $(if ($CustomPermissions) { 'Custom' } else { $ownerRole }))..."

    if ($null -ne $CustomPermissions) {
        $permissions = $CustomPermissions
    }
    else {
    switch ($ownerRole) {
        'ConnectOnly' {
            $permissions = @{
                useAccounts                            = $true
                retrieveAccounts                       = $false
                listAccounts                           = $true
                addAccounts                            = $false
                updateAccountContent                   = $false
                updateAccountProperties                = $false
                initiateCPMAccountManagementOperations = $false
                specifyNextAccountContent              = $false
                renameAccounts                         = $false
                deleteAccounts                         = $false
                unlockAccounts                         = $false
                manageSafe                             = $false
                manageSafeMembers                      = $false
                backupSafe                             = $false
                viewAuditLog                           = $false
                viewSafeMembers                        = $false
                accessWithoutConfirmation              = $false
                createFolders                          = $false
                deleteFolders                          = $false
                moveAccountsAndFolders                 = $false
                requestsAuthorizationLevel1            = $false
                requestsAuthorizationLevel2            = $false
            }
        }
        'ReadOnly' {
            $permissions = @{
                useAccounts                            = $true
                retrieveAccounts                       = $true
                listAccounts                           = $true
                addAccounts                            = $false
                updateAccountContent                   = $false
                updateAccountProperties                = $false
                initiateCPMAccountManagementOperations = $false
                specifyNextAccountContent              = $false
                renameAccounts                         = $false
                deleteAccounts                         = $false
                unlockAccounts                         = $false
                manageSafe                             = $false
                manageSafeMembers                      = $false
                backupSafe                             = $false
                viewAuditLog                           = $false
                viewSafeMembers                        = $false
                accessWithoutConfirmation              = $false
                createFolders                          = $false
                deleteFolders                          = $false
                moveAccountsAndFolders                 = $false
                requestsAuthorizationLevel1            = $false
                requestsAuthorizationLevel2            = $false
            }
        }
        'Approver' {
            $permissions = @{
                useAccounts                            = $false
                retrieveAccounts                       = $false
                listAccounts                           = $true
                addAccounts                            = $false
                updateAccountContent                   = $false
                updateAccountProperties                = $false
                initiateCPMAccountManagementOperations = $false
                specifyNextAccountContent              = $false
                renameAccounts                         = $false
                deleteAccounts                         = $false
                unlockAccounts                         = $false
                manageSafe                             = $false
                manageSafeMembers                      = $true
                backupSafe                             = $false
                viewAuditLog                           = $false
                viewSafeMembers                        = $true
                accessWithoutConfirmation              = $false
                createFolders                          = $false
                deleteFolders                          = $false
                moveAccountsAndFolders                 = $false
                requestsAuthorizationLevel1            = $true
                requestsAuthorizationLevel2            = $false
            }
        }
        'AccountsManager' {
            $permissions = @{
                useAccounts                            = $true
                retrieveAccounts                       = $true
                listAccounts                           = $true
                addAccounts                            = $true
                updateAccountContent                   = $true
                updateAccountProperties                = $true
                initiateCPMAccountManagementOperations = $true
                specifyNextAccountContent              = $true
                renameAccounts                         = $true
                deleteAccounts                         = $true
                unlockAccounts                         = $true
                manageSafe                             = $false
                manageSafeMembers                      = $true
                backupSafe                             = $false
                viewAuditLog                           = $true
                viewSafeMembers                        = $true
                accessWithoutConfirmation              = $true
                createFolders                          = $false
                deleteFolders                          = $false
                moveAccountsAndFolders                 = $false
                requestsAuthorizationLevel1            = $true
                requestsAuthorizationLevel2            = $false
            }
        }
        'Full' {
            $permissions = @{
                useAccounts                            = $true
                retrieveAccounts                       = $true
                listAccounts                           = $true
                addAccounts                            = $true
                updateAccountContent                   = $true
                updateAccountProperties                = $true
                initiateCPMAccountManagementOperations = $true
                specifyNextAccountContent              = $true
                renameAccounts                         = $true
                deleteAccounts                         = $true
                unlockAccounts                         = $true
                manageSafe                             = $true
                manageSafeMembers                      = $true
                backupSafe                             = $true
                viewAuditLog                           = $true
                viewSafeMembers                        = $true
                accessWithoutConfirmation              = $true
                createFolders                          = $true
                deleteFolders                          = $true
                moveAccountsAndFolders                 = $true
                requestsAuthorizationLevel1            = $true
                requestsAuthorizationLevel2            = $false
            }
        }
    }   # end if/else CustomPermissions

    If ($ownerName -NotIn $script:g_DefaultUsers) {
        try {
            $safeMembersBody = @{
                memberName               = $ownerName
                searchIn                 = $memberSearchInLocation
                membershipExpirationDate = $null
                permissions              = $permissions
            } | ConvertTo-Json -Depth 5 -Compress

            Write-LogMessage -type Verbose -MSG "Adding '$ownerName' (searchIn: $memberSearchInLocation) to '$safeName'..."
            $setSafeMember = Invoke-Rest -Command POST -URI ($script:URL_SafeMembers -f $(ConvertTo-URL $safeName)) -Body $safeMembersBody -Header $Header
            If ($null -ne $setSafeMember) {
                Write-LogMessage -type Verbose -MSG "Member '$ownerName' successfully added to '$safeName' (role: $(if ($CustomPermissions) { 'Custom' } else { $ownerRole }))"
            }
        }
        catch {
            Throw $(New-Object System.Exception ("Add-SafeOwner: Error setting membership for '$ownerName' on '$safeName'.", $PSItem.Exception))
        }
    }
    else {
        Write-LogMessage -type Info -MSG "Skipping default vault user '$ownerName'"
    }
}

Function Add-DefaultSafeMembers {
    <#
.SYNOPSIS
    Adds all DefaultSafeMembers from the resolved config to a safe.
.DESCRIPTION
    Each DefaultSafeMembers entry supports three permission sources (priority order):
      1. Permissions  — inline permissions object (PSCustomObject or hashtable)
      2. RoleConfigSet — name of a custom role defined in the RoleConfigSet section
      3. Role          — one of the 5 built-in named roles
    A failed individual member add is logged as a warning but does not stop the loop.
.PARAMETER Header
    Logon header hashtable.
.PARAMETER safeName
    Name of the safe to add default members to.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Header,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$safeName
    )
    if ($null -eq $script:Config.DefaultSafeMembers -or $script:Config.DefaultSafeMembers.Count -eq 0) {
        Write-LogMessage -type Verbose -MSG "No DefaultSafeMembers configured - skipping for safe '$safeName'"
        return
    }
    foreach ($member in $script:Config.DefaultSafeMembers) {
        try {
            $searchIn = if ([string]::IsNullOrEmpty($member.SearchIn)) { 'Vault' } else { $member.SearchIn }

            # Resolve permissions source (priority: Permissions > RoleConfigSet > Role)
            if ($null -ne $member.Permissions) {
                # Inline permissions object — convert PSCustomObject to hashtable if needed
                $customPerms = @{}
                $member.Permissions.PSObject.Properties | ForEach-Object { $customPerms[$_.Name] = $_.Value }
                Write-LogMessage -type Info -MSG "Adding default member '$($member.Name)' (inline permissions) to safe '$safeName'"
                $ownerParams = @{
                    Header                 = $Header
                    safeName               = $safeName
                    ownerName              = $member.Name
                    CustomPermissions      = $customPerms
                    memberSearchInLocation = $searchIn
                }
                Add-SafeOwner @ownerParams
            }
            elseif (-not [string]::IsNullOrEmpty($member.RoleConfigSet)) {
                $customPerms = $script:Config.RoleConfigSets[$member.RoleConfigSet]
                if ($null -eq $customPerms) {
                    Write-LogMessage -type Warning -MSG "RoleConfigSet '$($member.RoleConfigSet)' not found for member '$($member.Name)' - skipping"
                    continue
                }
                Write-LogMessage -type Info -MSG "Adding default member '$($member.Name)' (RoleConfigSet: $($member.RoleConfigSet)) to safe '$safeName'"
                $ownerParams = @{
                    Header                 = $Header
                    safeName               = $safeName
                    ownerName              = $member.Name
                    CustomPermissions      = $customPerms
                    memberSearchInLocation = $searchIn
                }
                Add-SafeOwner @ownerParams
            }
            else {
                Write-LogMessage -type Info -MSG "Adding default member '$($member.Name)' (role: $($member.Role)) to safe '$safeName'"
                $ownerParams = @{
                    Header                 = $Header
                    safeName               = $safeName
                    ownerName              = $member.Name
                    ownerRole              = $member.Role
                    memberSearchInLocation = $searchIn
                }
                Add-SafeOwner @ownerParams
            }
        }
        catch {
            Write-LogMessage -type Warning -MSG "Failed to add default member '$($member.Name)' to '$safeName': $($PSItem.Exception.Message)"
        }
    }
}

Function New-AccountObject {
    <#
.SYNOPSIS
    Builds a CyberArk account object from a CSV row for bulk onboarding.
.DESCRIPTION
    Maps standard CSV columns (accountUser, accountAddress, safeName, accountPlatform,
    enableAutoMgmt, etc.) to the v2 Bulk Accounts API shape.
    Missing optional fields fall back to UserDefaults from $script:Config.
    If accountUser is blank, it is derived from the accountUserPattern in UserDefaults
    (replace * with userName). If no pattern is set, userName is used as-is.
    If accountAddress is blank, accountAddress from UserDefaults is used.
    Unknown CSV columns are promoted to platformAccountProperties.
.PARAMETER AccountLine
    A single row from the accounts CSV, as a PSObject from Import-Csv.
.OUTPUTS
    PSCustomObject — account object ready for the CyberArk Bulk Accounts API.
#>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject]$AccountLine
    )
    try {
        # Helper: return CSV field value, falling back to UserDefaults if empty
        function Get-UserDefault {
            param([string]$fieldValue, [string]$fieldName)
            if (-not [string]::IsNullOrEmpty($fieldValue)) { return $fieldValue }
            if ($null -ne $script:Config -and $script:Config.UserDefaults.ContainsKey($fieldName)) {
                return [string]$script:Config.UserDefaults[$fieldName]
            }
            return $null
        }

        $_safeName = $_platformID = ''
        # Resolve accountUser: CSV value → accountUserPattern from config → userName as fallback
        $_accountUser = Get-TrimmedString $AccountLine.accountUser
        If ([string]::IsNullOrEmpty($_accountUser)) {
            $_pattern = Get-UserDefault -fieldValue '' -fieldName 'accountUserPattern'
            $_accountUser = If (-not [string]::IsNullOrEmpty($_pattern)) {
                $_pattern.Replace('*', (Get-TrimmedString $AccountLine.userName))
            } Else {
                Get-TrimmedString $AccountLine.userName
            }
        }
        If ([string]::IsNullOrEmpty($_accountUser))  { throw 'Missing mandatory field: Account User Name' }
        # Resolve accountAddress: CSV value -> accountAddress in UserDefaults -> error
        $_accountAddress = Get-TrimmedString $AccountLine.accountAddress
        If ([string]::IsNullOrEmpty($_accountAddress)) {
            $_accountAddress = Get-UserDefault -fieldValue '' -fieldName 'accountAddress'
        }
        If ([string]::IsNullOrEmpty($_accountAddress)) { throw 'Missing mandatory field: Account Address' }
        If ([string]::IsNullOrEmpty($AccountLine.safeName))       { $_safeName = Get-PersonalSafeNameFromPattern -userName $AccountLine.userName }
        Else                                                       { $_safeName = $AccountLine.safeName }
        If ([string]::IsNullOrEmpty($AccountLine.accountPlatform)) { $_platformID = Get-UserDefault -fieldValue '' -fieldName 'accountPlatform' }
        Else                                                        { $_platformID = $AccountLine.accountPlatform }
        If ([string]::IsNullOrEmpty($_platformID))                  { $_platformID = $script:DEFAULT_PLATFORM_ID }

        $excludedProperties = @('accountuser', 'accountaddress', 'accountplatform', 'name', 'username',
            'address', 'safename', 'platformid', 'password', 'key', 'enableautomgmt', 'manualmgmtreason',
            'groupname', 'groupplatformid', 'remotemachineaddresses', 'restrictmachineaccesstolist', 'sshkey',
            'safeconfigset', 'userconfigset', 'cpmname', 'numberofdaysretention', 'numberofversionsretention',
            'safenamepattern')
        $customProps = $($AccountLine.PSObject.Properties | Where-Object { $_.Name.ToLower() -NotIn $excludedProperties })

        $_Account = [PSCustomObject]@{
            address                  = $_accountAddress
            userName                 = $_accountUser
            platformId               = (Get-TrimmedString $_platformID)
            safeName                 = (Get-TrimmedString $_safeName)
            secret                   = $AccountLine.password
            platformAccountProperties = $null
            secretManagement         = [PSCustomObject]@{
                automaticManagementEnabled = $null
                manualManagementReason     = $null
            }
            remoteMachinesAccess     = $null
        }

        if (-not [string]::IsNullOrEmpty($customProps)) {
            $_Account.platformAccountProperties = [PSCustomObject]@{}
            foreach ($prop in $customProps) {
                If (-not [string]::IsNullOrEmpty($prop.Value)) {
                    $_Account.platformAccountProperties | Add-Member -MemberType NoteProperty -Name $prop.Name -Value (Get-TrimmedString $prop.Value)
                }
            }
        }

        $_enableAutoMgmt    = Get-UserDefault -fieldValue $AccountLine.enableAutoMgmt    -fieldName 'enableAutoMgmt'
        $_manualMgmtReason  = Get-UserDefault -fieldValue $AccountLine.manualMgmtReason  -fieldName 'manualMgmtReason'
        $_remoteMachines    = Get-UserDefault -fieldValue $AccountLine.remoteMachineAddresses   -fieldName 'remoteMachineAddresses'
        $_restrictMachines  = Get-UserDefault -fieldValue $AccountLine.restrictMachineAccessToList -fieldName 'restrictMachineAccessToList'

        If (-not [String]::IsNullOrEmpty($_enableAutoMgmt)) {
            $_Account.secretManagement.automaticManagementEnabled = ConvertTo-Bool $_enableAutoMgmt
            if ($_Account.secretManagement.automaticManagementEnabled -eq $false) {
                $_Account.secretManagement.manualManagementReason = $_manualMgmtReason
            }
        }

        $_Account.remoteMachinesAccess = [PSCustomObject]@{
            remoteMachines                   = $null
            accessRestrictedToRemoteMachines = $null
        }
        If (-not [String]::IsNullOrEmpty($_remoteMachines)) {
            $_Account.remoteMachinesAccess.remoteMachines                   = $_remoteMachines
            $_Account.remoteMachinesAccess.accessRestrictedToRemoteMachines = ConvertTo-Bool $_restrictMachines
        }

        If ($null -eq $_Account.platformAccountProperties)                  { $_Account.PSObject.Properties.Remove('platformAccountProperties') }
        If ($null -eq $_Account.remoteMachinesAccess.remoteMachines)         { $_Account.PSObject.Properties.Remove('remoteMachinesAccess') }
        If ($null -eq $_Account.secretManagement.automaticManagementEnabled) { $_Account.PSObject.Properties.Remove('secretManagement') }

        If (([string]::IsNullOrEmpty($_Account.userName) -or [string]::IsNullOrEmpty($_Account.Address)) -and
            (-not [string]::IsNullOrEmpty($_Account.name))) {
            $script:g_LogAccountName = $_Account.name
        }
        Else { $script:g_LogAccountName = '{0}@{1}' -f $_Account.userName, $_Account.Address }

        return $_Account
    }
    catch {
        Throw $(New-Object System.Exception ('New-AccountObject: Error creating account object.', $PSItem.Exception))
    }
}
#endregion Accounts and Safes Functions

#endregion Functions

#region Main Execution

Write-LogMessage -type Verbose -MSG $script:g_ScriptCommand
Write-LogMessage -type Info -MSG "Starting script (v$ScriptVersion)" -Header
if ($InDebug)   { Write-LogMessage -type Info -MSG 'Running in Debug Mode' }
if ($InVerbose) { Write-LogMessage -type Info -MSG 'Running in Verbose Mode' }
Write-LogMessage -type Debug -MSG "Running PowerShell version $($PSVersionTable.PSVersion.Major) compatible of versions $($PSVersionTable.PSCompatibleVersions -join ', ')"

If ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-LogMessage -type Error -MSG "PowerShell is running in $($ExecutionContext.SessionState.LanguageMode) mode which limits API methods used by this script."
    Write-LogMessage -type Info -MSG 'Script ended' -Footer
    return
}

If ([string]::IsNullOrEmpty($PVWAURL) -and [string]::IsNullOrEmpty($logonToken)) {
    Write-LogMessage -type Error -MSG 'PVWAURL is required when not using a pre-obtained logonToken.'
    Write-LogMessage -type Info -MSG 'Script ended' -Footer
    return
}

If (-not [string]::IsNullOrEmpty($PVWAURL)) {
    $PVWAURL = Format-PVWAURL -PVWAURL $PVWAURL
}

Initialize-ScriptURLs

# Load and resolve config (baseline defaults -> config file -> parameter overrides)
Import-ScriptConfig

# Apply config-resolved values to script parameters (only when not explicitly supplied)
If (-not $PSBoundParameters.ContainsKey('SafeNamePattern')) { $SafeNamePattern = $script:Config.SafeNamePattern }

If ($DisableCertificateValidation -and -not $script:g_SSLChanged) {
    Disable-SSLVerification
    $script:g_SSLChanged = $true
    Write-Warning 'Certificate validation is disabled. This should only be used for testing!'
}

# Resolve authentication
# Priority: $logonToken (pass-through, no logoff) -> $PVWACredentials -> interactive prompt
If (-not [string]::IsNullOrEmpty($logonToken)) {
    Write-LogMessage -type Info -MSG 'Using provided logon token. Session logoff will be skipped.'
    if ($logonToken.GetType().Name -eq 'String') {
        $script:g_LogonHeader = @{Authorization = $logonToken }
    }
    else {
        $script:g_LogonHeader = $logonToken
    }
    $script:g_ShouldLogoff = $false
}
ElseIf ($null -eq $PVWACredentials) {
    $PVWACredentials = $Host.UI.PromptForCredential(
        'Personal Privileged Accounts',
        "Enter your CyberArk credentials ($AuthenticationType)",
        '', '')
    If ($null -eq $PVWACredentials) {
        Write-LogMessage -type Error -MSG 'Credentials are required to proceed.'
        Write-LogMessage -type Info -MSG 'Script ended' -Footer
        return
    }
}

If ([string]::IsNullOrEmpty($CSVPath)) {
    $CSVPath = Open-FileDialog -LocationPath $script:g_CsvDefaultPath
}
If ([string]::IsNullOrEmpty($CSVPath)) {
    Write-LogMessage -type Error -MSG 'No CSV file selected. Exiting.'
    Write-LogMessage -type Info -MSG 'Script ended' -Footer
    return
}

# Read CSV and process each account
$accountsCSV          = Import-Csv $CSVPath
$personalPrivAccounts = @()
$counter              = 1

# Saved before the loop so per-row overrides can be cleanly restored
$baseConfig          = $script:Config
$baseSafeNamePattern = $SafeNamePattern

Write-LogMessage -type Info -MSG 'Creating needed personal safes and collecting accounts for onboard' -SubHeader

ForEach ($account in $accountsCSV) {
    $rowHasOverride = $false
    try {
        # Per-row SafeConfigSet / UserConfigSet override
        $rowSafeSet = if ($null -ne $account.PSObject.Properties['SafeConfigSet']) { $account.SafeConfigSet } else { '' }
        $rowUserSet = if ($null -ne $account.PSObject.Properties['UserConfigSet']) { $account.UserConfigSet } else { '' }
        $rowHasOverride = (-not [string]::IsNullOrEmpty($rowSafeSet)) -or (-not [string]::IsNullOrEmpty($rowUserSet))

        if ($rowHasOverride) {
            $rowConfig = Get-RowConfig -RowSafeConfigSet $rowSafeSet -RowUserConfigSet $rowUserSet
            if ($null -eq $rowConfig) {
                # Invalid set name and -FallbackOnInvalidConfigSet not set — skip row
                $rowHasOverride = $false   # nothing to restore
                continue
            }
            $script:Config   = $rowConfig
            $SafeNamePattern = $script:Config.SafeNamePattern
        }

        # Inline safe-field overrides: CSV columns CPMName, NumberOfDaysRetention,
        # NumberOfVersionsRetention and SafeNamePattern (if present and non-blank) take
        # priority over anything resolved from config sets, but are still below CLI params.
        # We make a shallow copy only when at least one column has a value.
        $_rowCPM         = if ($null -ne $account.PSObject.Properties['CPMName'])                  { $account.CPMName }                  else { '' }
        $_rowDays        = if ($null -ne $account.PSObject.Properties['NumberOfDaysRetention'])     { $account.NumberOfDaysRetention }     else { '' }
        $_rowVersions    = if ($null -ne $account.PSObject.Properties['NumberOfVersionsRetention']) { $account.NumberOfVersionsRetention } else { '' }
        $_rowSafePattern = if ($null -ne $account.PSObject.Properties['SafeNamePattern'])           { $account.SafeNamePattern }           else { '' }
        if (-not [string]::IsNullOrEmpty($_rowCPM) -or -not [string]::IsNullOrEmpty($_rowDays) -or
            -not [string]::IsNullOrEmpty($_rowVersions) -or -not [string]::IsNullOrEmpty($_rowSafePattern)) {
            # Clone config if we haven't already (rowHasOverride handles full sets; this is inline only)
            if (-not $rowHasOverride) {
                $script:Config = @{
                    CPMName                   = $script:Config.CPMName
                    NumberOfVersionsRetention = $script:Config.NumberOfVersionsRetention
                    NumberOfDaysRetention     = $script:Config.NumberOfDaysRetention
                    SafeNamePattern           = $script:Config.SafeNamePattern
                    UserDefaults              = $script:Config.UserDefaults.Clone()
                    DefaultSafeMembers        = $script:Config.DefaultSafeMembers
                    RoleConfigSets            = $script:Config.RoleConfigSets
                }
                $rowHasOverride = $true
            }
            if (-not [string]::IsNullOrEmpty($_rowCPM))         { $script:Config.CPMName = $_rowCPM }
            if (-not [string]::IsNullOrEmpty($_rowDays)) {
                $script:Config.NumberOfDaysRetention     = [int]$_rowDays
                $script:Config.NumberOfVersionsRetention = $null
            }
            elseif (-not [string]::IsNullOrEmpty($_rowVersions)) {
                $script:Config.NumberOfVersionsRetention = [int]$_rowVersions
                $script:Config.NumberOfDaysRetention     = $null
            }
            if (-not [string]::IsNullOrEmpty($_rowSafePattern)) {
                $script:Config.SafeNamePattern = $_rowSafePattern
                $SafeNamePattern = $_rowSafePattern
            }
        }

        $objAccount = (New-AccountObject -AccountLine $account)

        $authHeader = Get-AuthHeader

        Write-LogMessage -type Info -MSG "Checking if safe '$($objAccount.safeName)' exists..."
        If (-not $(Test-Safe -safeName $objAccount.safeName -Header $authHeader)) {
            Write-LogMessage -type Info -MSG "Creating safe '$($objAccount.safeName)' and adding '$($account.userName)' as owner"
            try {
                If ($(Add-Safe -safeName $objAccount.safeName -Header $authHeader)) {
                    $ownerParams = @{
                        Header    = $authHeader
                        safeName  = $objAccount.safeName
                        ownerName = $account.userName
                        ownerRole = 'AccountsManager'
                    }
                    Add-SafeOwner @ownerParams
                    Add-DefaultSafeMembers -Header $authHeader -safeName $objAccount.safeName
                }
            }
            catch {
                Throw $(New-Object System.Exception ('Error creating safe or adding safe members', $PSItem.Exception))
            }
        }

        $objAccount | Add-Member -NotePropertyName uploadIndex -NotePropertyValue $counter
        $personalPrivAccounts += $objAccount
        $counter++

        # Logoff per-iteration session only when we own it and are not using RADIUS
        If ($script:g_ShouldLogoff -and $AuthenticationType -ne 'radius') {
            Invoke-Logoff -Header $authHeader
        }
    }
    catch {
        Write-LogMessage -type Error -MSG "Error onboarding '$($script:g_LogAccountName)' into the Vault. Error: $(Join-ExceptionMessage $PSItem.Exception)"
    }
    finally {
        # Restore base config so the next row starts clean
        if ($rowHasOverride) {
            $script:Config   = $baseConfig
            $SafeNamePattern = $baseSafeNamePattern
        }
    }
}

# Bulk onboard all collected accounts
$authHeader = $null
try {
    If ($personalPrivAccounts.Count -gt 0) {
        Write-LogMessage -type Info -MSG "Starting bulk onboard of $($personalPrivAccounts.Count) personal privileged accounts"

        $authHeader = Get-AuthHeader

        $bulkBody = @{
            source       = $(Split-Path -Resolve $CSVPath -Leaf)
            accountsList = $personalPrivAccounts
        }
        $bulkID = Invoke-Rest -Command POST -URI $script:URL_BulkAccounts -Body ($bulkBody | ConvertTo-Json -Depth 5) -Header $authHeader

        if ($null -ne $bulkID) {
            $bulkResult = Invoke-Rest -Command GET -URI ($script:URL_BulkAccountsTask -f $bulkID) -Header $authHeader
            while (($bulkResult.Status -eq 'inProgress') -or ($bulkResult.Status -eq 'Pending')) {
                Start-Sleep -Seconds 5
                Write-LogMessage -type Info -MSG "Current onboarding status: $($bulkResult.Status -creplace '([A-Z])','$1')"
                $bulkResult = Invoke-Rest -Command GET -URI ($script:URL_BulkAccountsTask -f $bulkID) -Header $authHeader
            }

            Write-LogMessage -type Info -MSG "Onboarding $($bulkResult.Status -creplace '([A-Z])','$1')"
            switch ($bulkResult.Status) {
                'completedWithErrors' {
                    Write-LogMessage -type Info -MSG ('{0} accounts onboarded successfully; {1} failed' -f $bulkResult.Result.succeeded, $bulkResult.Result.failed)
                    ForEach ($item in $bulkResult.FailedItems.Items) {
                        $failedAccount = '{0}@{1} (index: {2})' -f $item.userName, $item.address, $item.uploadIndex
                        Write-LogMessage -type Info -MSG ('Account {0} failed: {1}' -f $failedAccount, $item.error)
                    }
                }
                'failed' {
                    Write-LogMessage -type Info -MSG ('Onboarding failed: {0}' -f $bulkResult.Result.Error)
                }
                'completed' {
                    Write-LogMessage -type Info -MSG ('{0} accounts successfully onboarded' -f $bulkResult.Result.succeeded)
                }
            }
        }
        else {
            Throw 'The Bulk Account Upload ID returned empty'
        }
    }
    else {
        Write-LogMessage -type Info -MSG 'No personal privileged accounts to onboard'
    }
}
catch {
    Write-LogMessage -type Error -MSG "Error during bulk onboarding: $(Join-ExceptionMessage $_.Exception)"
}
finally {
    # Logoff only if we own the session
    if ($script:g_ShouldLogoff -and $null -ne $authHeader) {
        Invoke-Logoff -Header $authHeader
    }
    Write-LogMessage -type Info -MSG 'Script Ended' -Footer
}

#endregion Main Execution
