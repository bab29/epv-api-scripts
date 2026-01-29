# Identity Authentication Module - Implementation Plan

## Project Overview

### Purpose
Create a comprehensive PowerShell module for authenticating to CyberArk Identity Security Platform Shared Services (ISPSS) with support for multiple authentication mechanisms including Username/Password, OAuth, MFA challenges (Push, SMS, Email), and SAML/OOBAUTHPIN flows.

### Objectives
1. Replace deprecated SAML functionality with modern OOBAUTHPIN flow
2. Create dual-version modules: IdentityAuth.psm1 (PS5.1) and IdentityAuth7.psm1 (PS7+ with maximum modern features)
3. Eliminate all Write-Host usage and achieve zero PSScriptAnalyzer violations
4. Implement automatic token refresh capability for OAuth
5. Maintain single-step interactive user experience
6. Provide comprehensive logging with transcript support
7. Support session state persistence with `$script:CurrentSession`
8. Return Bearer token string for direct use with scripts

### Key Features
- **Multi-Mechanism Support**: UP, OAuth, Email/SMS/Push MFA, OOBAUTHPIN
- **Session Management**: Token caching, automatic refresh (OAuth), expiry detection
- **Cross-Version Compatibility**: PS5.1 baseline + PS7+ enhanced with classes/enums
- **Secure Credential Handling**: No plaintext credential storage
- **Comprehensive Logging**: Transcript support, sensitive data masking
- **Standards Compliance**: Zero PSScriptAnalyzer violations, extensive splatting, no backticks

---

## Implementation Steps

### Step 1: Create Dual Module Structure with PS7 Classes/Enums
**Duration**: 3-5 days

#### Tasks
1. **Create IdentityAuth7.psm1 with Maximum PS7 Features**
   - Add `#Requires -Version 7.0`
   - Define classes:
     - `[IdentitySession]`: Properties (Token, TokenExpiry, IdentityURL, PCloudURL, Username, AuthMethod, SessionId, StoredCredentials, Metadata), Methods (IsExpired(), IsExpiringSoon(), Refresh(), GetAuthHeader(), Dispose())
     - `[IdentityAuthResponse]`: Properties (Success, Message, Result, ErrorInfo, StatusCode, Timestamp), Methods (ToToken(), HasChallenges())
     - `[ChallengeInfo]`: Properties (ChallengeId, Mechanisms, Type, Metadata), Methods (GetMechanismByName(), HasMultipleMechanisms())
     - `[MechanismInfo]`: Properties (MechanismId, Name, AnswerType, PromptMechChosen, Properties), Methods (RequiresUserInput(), IsOOB())
   - Define enums:
     - `[AuthenticationMechanism]`: UP, OAuth, EmailOTP, SMSOTP, PushNotification, SAML_Deprecated, OOBAUTHPIN, PhoneCall, SecurityQuestions
     - `[ChallengeType]`: Text, StartTextOob, StartOob, Poll, Answer, SAML
     - `[MechanismType]`: UP, OTP, EMAIL, SMS, PF, OATH, RADIUS, SQ, SAML
     - `[SessionState]`: NotAuthenticated, Authenticating, Authenticated, Expired, RefreshRequired, Invalid
   - Use PS7 features throughout:
     - Ternary operators (`$x ? $a : $b`)
     - Null-coalescing operators (`??`, `??=`)
     - Null-conditional operators (`?.`)
     - Pipeline chain operators (`&&`, `||`)
   - Implement `$script:CurrentSession` for state persistence
   - Zero backticks - use splatting exclusively

2. **Create IdentityAuth.psm1 as PS5.1 Baseline**
   - Add `#Requires -Version 5.1`
   - Replicate IdentityAuth7 functionality using:
     - Hashtables instead of classes
     - Traditional if/else instead of ternary operators
     - Standard logic instead of null-coalescing
     - SecureString BSTR marshal pattern (PS5.1 compatible)
   - Maintain identical function signatures and return structures
   - Implement `$script:CurrentSession` hashtable matching PS7 class structure
   - Use splatting exclusively
   - Pass PSScriptAnalyzer with zero violations

3. **Create PSScriptAnalyzerSettings.psd1**
   - Enable strictest rules (all default rules + code formatting)
   - Based on EPV-API-Common-5.1 settings but enhanced
   - Include rules for:
     - No Write-Host
     - Named parameters required
     - UTF-8 with BOM encoding
     - Proper error handling
     - Null on left side of comparisons

4. **Setup VS Code Configuration**
   - Create `.vscode/settings.json` with:
     - PowerShell formatting rules
     - PSScriptAnalyzer integration
     - Format on save enabled
     - Consistent indentation (4 spaces)
   - Document required VS Code extensions in README

#### Success Criteria
- ✅ Both modules load without errors
- ✅ PS7 module uses classes/enums successfully
- ✅ PS5.1 module replicates functionality with hashtables
- ✅ Zero PSScriptAnalyzer violations on both
- ✅ Alt+Shift+F formatting works without creating violations

---

### Step 2: Implement OOBAUTHPIN Authentication Flow (Replace SAML)
**Duration**: 3-4 days

#### Tasks
1. **Remove Legacy SAML Code**
   - Delete `Invoke-SAMLLogon` function (lines 401-511 in current IdentityAuth.psm1)
   - Remove SAML invocation logic (lines 110-123)
   - Remove any SAML-related parameters and documentation

2. **Update StartAuthentication Headers**
   - Always include in StartAuthentication requests:
     ```powershell
     $headers = @{
         'Content-Type' = 'application/json'
         'X-IDAP-NATIVE-CLIENT' = 'true'
         'OobIdPAuth' = 'true'
     }
     ```
   - Use splatting for Invoke-RestMethod:
     ```powershell
     $invokeParams = @{
         Uri = $startPlatformAPIAuth
         Method = 'Post'
         ContentType = 'application/json'
         Body = $startPlatformAPIBody
         Headers = $headers
         SessionVariable = 'webSession'
         TimeoutSec = 30
     }
     $IdaptiveResponse = Invoke-RestMethod @invokeParams
     ```

3. **Detect and Handle IdpRedirectShortUrl**
   - Check response for `IdpRedirectShortUrl` presence
   - Extract: `IdpRedirectShortUrl`, `IdpLoginSessionId`, `SessionId`
   - Output formatted instructions using here-string:
     ```powershell
     $instructions = @"
     
     ============================================================
     OOBAUTHPIN Authentication Required
     ============================================================
     
     Step 1: Open your web browser
     Step 2: Navigate to the following URL:
     
         $IdpRedirectShortUrl
     
     Step 3: Complete SAML authentication with your Identity Provider
     Step 4: You will receive a PIN code after successful authentication
     Step 5: Enter the PIN code when prompted below
     
     ============================================================
     "@
     Write-Output $instructions
     ```

4. **Implement PIN Collection and Validation**
   - Add optional `-PIN [string]$PIN` parameter (plain string, one-time use)
   - If PIN not provided, prompt with validation:
     ```powershell
     do {
         $pinInput = Read-Host -Prompt "Enter PIN code from SAML authentication"
         $pinInput = $pinInput.Trim()
         if ($pinInput -match '^\d+$') {
             $PIN = $pinInput
             $validPIN = $true
         } else {
             Write-Warning "Invalid PIN format. Please enter numbers only."
             $validPIN = $false
         }
     } until ($validPIN)
     ```

5. **Submit PIN via AdvanceAuthentication**
   - Build request body:
     ```powershell
     $pinBody = @{
         SessionId = $IdpLoginSessionId
         MechanismId = 'OOBAUTHPIN'
         Action = 'Answer'
         Answer = $PIN
     } | ConvertTo-Json -Depth 9
     
     $advanceParams = @{
         Uri = $startPlatformAPIAdvancedAuth
         Method = 'Post'
         ContentType = 'application/json'
         Body = $pinBody
         Headers = $headers
         TimeoutSec = 30
     }
     $pinResponse = Invoke-RestMethod @advanceParams
     ```

6. **Handle Post-OOBAUTHPIN Challenges**
   - Check if additional challenges returned after PIN submission
   - If yes, recursively call `Invoke-Challenge` to process them
   - If no, extract and return token
   - Store successful session in `$script:CurrentSession`

7. **Fallback to Standard Flow**
   - If `IdpRedirectShortUrl` not present, fall back to existing challenge flow
   - Maintain backward compatibility with non-OOBAUTHPIN tenants

#### API Flow
```
1. StartAuthentication (with OobIdPAuth header)
   POST /Security/StartAuthentication
   Headers: { "OobIdPAuth": "true", "X-IDAP-NATIVE-CLIENT": "true" }
   Response: { "IdpRedirectShortUrl": "...", "IdpLoginSessionId": "...", "SessionId": "..." }

2. User navigates to IdpRedirectShortUrl, completes SAML auth, receives PIN

3. Submit PIN
   POST /Security/AdvanceAuthentication
   Body: { "SessionId": "{IdpLoginSessionId}", "MechanismId": "OOBAUTHPIN", "Action": "Answer", "Answer": "{PIN}" }
   Response: { "Success": true, "Result": { "Token": "..." } }

4. Process additional challenges if present, else return token
```

#### Success Criteria
- ✅ OOBAUTHPIN flow successfully replaces SAML
- ✅ URL displayed clearly with step-by-step instructions
- ✅ PIN validation prevents invalid input
- ✅ Additional challenges processed correctly
- ✅ Fallback to standard flow works when OOBAUTHPIN unavailable
- ✅ Session stored in `$script:CurrentSession`

---

### Step 3: Modernize OAuth with Multi-Format Credential Support
**Duration**: 2-3 days

#### Tasks
1. **Update OAuth Parameter Sets**
   - Create three parameter sets:
     - `OAuthCreds`: PSCredential (Username=ClientID, Password=ClientSecret) - PRIMARY
     - `OAuthPlainText`: `-ClientId [string]` + `-ClientSecret [string]`
     - `OAuthSecureString`: `-ClientId [string]` + `-ClientSecret [securestring]`
   
2. **Implement Credential Extraction Logic**
   ```powershell
   # Extract based on parameter set
   switch ($PSCmdlet.ParameterSetName) {
       'OAuthCreds' {
           $ClientId = $OAuthCreds.UserName
           $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($OAuthCreds.Password)
           $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
       }
       'OAuthPlainText' {
           # Already have $ClientId and $ClientSecret
       }
       'OAuthSecureString' {
           $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
           $ClientSecretPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
           $ClientSecret = $ClientSecretPlain
       }
   }
   ```

3. **Implement OAuth Token Request with Splatting**
   ```powershell
   $body = "grant_type=client_credentials&client_id=$ClientId&client_secret=$ClientSecret"
   
   $oauthParams = @{
       Uri = "$IdaptiveBasePlatformURL/OAuth2/Token/$ClientId"
       Method = 'Post'
       ContentType = 'application/x-www-form-urlencoded'
       Body = $body
       ErrorAction = 'Stop'
   }
   
   try {
       $response = Invoke-RestMethod @oauthParams
   } catch {
       $errorRecord = [System.Management.Automation.ErrorRecord]::new(
           $_.Exception,
           'OAuthAuthenticationFailed',
           [System.Management.Automation.ErrorCategory]::AuthenticationError,
           $ClientId
       )
       $PSCmdlet.ThrowTerminatingError($errorRecord)
   } finally {
       # Clear sensitive data
       if ($bstr) {
           [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
       }
       $ClientSecret = $null
       $ClientSecretPlain = $null
   }
   ```

4. **Calculate and Store Token Expiry**
   ```powershell
   $tokenExpiry = (Get-Date).AddSeconds($response.expires_in)
   
   # PS7 version - create IdentitySession object
   $script:CurrentSession = [IdentitySession]@{
       Token = $response.access_token
       TokenExpiry = $tokenExpiry
       IdentityURL = $IdaptiveBasePlatformURL
       Username = $ClientId
       AuthMethod = [AuthenticationMechanism]::OAuth
       StoredCredentials = $OAuthCreds  # Store for auto-refresh
       Metadata = @{
           CreatedAt = (Get-Date)
           LastRefreshed = (Get-Date)
           RefreshCount = 0
       }
   }
   
   # PS5.1 version - create hashtable
   $script:CurrentSession = @{
       Token = $response.access_token
       TokenExpiry = $tokenExpiry
       IdentityURL = $IdaptiveBasePlatformURL
       Username = $ClientId
       AuthMethod = 'OAuth'
       StoredCredentials = $OAuthCreds
       Metadata = @{
           CreatedAt = (Get-Date)
           LastRefreshed = (Get-Date)
           RefreshCount = 0
       }
   }
   ```

5. **Update Format-Token Function**
   - Extract Bearer token from response
   - Return token string (strip 'Bearer ' prefix if present)
   - Use splatting for all operations

#### Success Criteria
- ✅ OAuth works with PSCredential (primary use case)
- ✅ OAuth works with plain text ClientId/ClientSecret
- ✅ OAuth works with SecureString ClientSecret
- ✅ Token expiry calculated and stored correctly
- ✅ Sensitive data cleaned up in finally block
- ✅ Proper error handling with ErrorRecord
- ✅ Session stored with OAuth credentials for auto-refresh

---

### Step 4: Replace Write-LogMessage with Standard Streams and Transcript
**Duration**: 2-3 days

#### Tasks
1. **Delete Write-LogMessage Function**
   - Remove entire function (lines 278-399 in current module)
   - Remove all Write-Host calls within it

2. **Replace All Write-LogMessage Calls**
   - Map message types to appropriate cmdlets:
     - `Info` → `Write-Output` (data output)
     - `Verbose` → `Write-Verbose` (operational details)
     - `Warning` → `Write-Warning` (warnings)
     - `Error` → `Write-Error` or `$PSCmdlet.ThrowTerminatingError()`
     - `Debug` → `Write-Debug` (debug information)
     - `Success` → `Write-Output` (data output)

3. **Add Transcript Support Parameters**
   ```powershell
   [Parameter(Mandatory = $false)]
   [switch]$EnableTranscript,

   [Parameter(Mandatory = $false)]
   [ValidateScript({
       $parentPath = Split-Path -Parent $_
       if ($parentPath) {
           Test-Path -Path $parentPath -PathType Container
       } else {
           $true
       }
   })]
   [string]$TranscriptPath = "$PWD\IdentityAuth_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
   ```

4. **Implement Transcript Management**
   ```powershell
   function Get-IdentityHeader {
       [CmdletBinding()]
       param(
           # ... parameters ...
           [switch]$EnableTranscript,
           [string]$TranscriptPath = "$PWD\IdentityAuth_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
       )
       
       begin {
           if ($EnableTranscript) {
               try {
                   Start-Transcript -Path $TranscriptPath -ErrorAction Stop
                   Write-Verbose "Transcript started: $TranscriptPath"
               } catch {
                   Write-Warning "Failed to start transcript: $($_.Exception.Message)"
               }
           }
       }
       
       process {
           try {
               # Main authentication logic
               Write-Verbose "Starting authentication process"
               # ... code ...
           } catch {
               Write-Error "Authentication failed: $($_.Exception.Message)"
               throw
           }
       }
       
       end {
           if ($EnableTranscript) {
               try {
                   Stop-Transcript -ErrorAction SilentlyContinue
                   Write-Verbose "Transcript stopped"
               } catch {
                   # Suppress transcript stop errors
               }
           }
       }
   }
   ```

5. **Update All Output Calls**
   - Use Write-Verbose for operational details:
     ```powershell
     Write-Verbose "Connecting to Identity URL: $IdaptiveBasePlatformURL"
     Write-Verbose "Starting OAuth authentication"
     Write-Verbose "Token expiry: $tokenExpiry"
     ```
   - Use Write-Output for user-facing messages:
     ```powershell
     Write-Output "Authentication successful"
     Write-Output $instructions  # OOBAUTHPIN instructions
     ```
   - Use Write-Warning for warnings:
     ```powershell
     Write-Warning "Token expires in 60 seconds. Consider refreshing."
     ```

6. **Use Splatting for All Multi-Parameter Cmdlets**
   ```powershell
   # GOOD - Use splatting
   $outputParams = @{
       InputObject = $message
       ErrorAction = 'Continue'
   }
   Write-Output @outputParams
   
   # BAD - No backticks allowed
   Write-Output `
       -InputObject $message `
       -ErrorAction Continue
   ```

#### Success Criteria
- ✅ Zero Write-Host calls remaining
- ✅ All output uses appropriate streams
- ✅ Transcript support works correctly
- ✅ Verbose output provides sufficient operational context
- ✅ `-Verbose` switch shows all operational details
- ✅ Zero backticks in entire codebase
- ✅ All multi-parameter calls use splatting

---

### Step 5: Implement Comprehensive Error Handling and Parameter Reordering
**Duration**: 3-4 days

#### Tasks
1. **Reorder Parameters in All Functions**
   - Standard order: Authentication → Switches → Session/Config
   ```powershell
   function Get-IdentityHeader {
       [CmdletBinding(DefaultParameterSetName = 'IdentityUserName')]
       param(
           # Authentication parameters (FIRST)
           [Parameter(ParameterSetName = 'IdentityUserName', Mandatory)]
           [ValidateNotNullOrEmpty()]
           [string]$IdentityUserName,
           
           [Parameter(ParameterSetName = 'UPCreds', Mandatory)]
           [ValidateNotNullOrEmpty()]
           [pscredential]$UPCreds,
           
           [Parameter(ParameterSetName = 'OAuthCreds', Mandatory)]
           [ValidateNotNullOrEmpty()]
           [pscredential]$OAuthCreds,
           
           [Parameter(ParameterSetName = 'OAuthPlainText', Mandatory)]
           [ValidateNotNullOrEmpty()]
           [string]$ClientId,
           
           [Parameter(ParameterSetName = 'OAuthPlainText', Mandatory)]
           [ValidateNotNullOrEmpty()]
           [string]$ClientSecret,
           
           [Parameter(Mandatory = $false)]
           [ValidatePattern('^\d+$')]
           [string]$PIN,
           
           # Optional switches (SECOND)
           [Parameter(Mandatory = $false)]
           [switch]$EnableTranscript,
           
           [Parameter(Mandatory = $false)]
           [switch]$ForceNewSession,
           
           # Session/Config parameters (LAST)
           [Parameter(Mandatory = $false)]
           [ValidateNotNullOrEmpty()]
           [string]$IdentityTenantURL,
           
           [Parameter(Mandatory = $false)]
           [ValidateNotNullOrEmpty()]
           [string]$PCloudURL,
           
           [Parameter(Mandatory = $false)]
           [string]$PCloudSubdomain,
           
           [Parameter(Mandatory = $false)]
           [ValidateScript({
               $parentPath = Split-Path -Parent $_
               if ($parentPath) { Test-Path -Path $parentPath -PathType Container } else { $true }
           })]
           [string]$TranscriptPath = "$PWD\IdentityAuth_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
       )
   ```

2. **Wrap All API Calls in Try/Catch**
   ```powershell
   try {
       $invokeParams = @{
           Uri = $apiUrl
           Method = 'Post'
           Body = $body
           ContentType = 'application/json'
           Headers = $headers
           TimeoutSec = 30
       }
       $response = Invoke-RestMethod @invokeParams
       Write-Verbose "API call successful"
   } catch {
       $statusCode = $null
       if ($_.Exception.Response) {
           $statusCode = $_.Exception.Response.StatusCode.value__
       }
       
       $errorMessage = "API call failed"
       if ($statusCode) {
           $errorMessage += " (HTTP $statusCode)"
       }
       $errorMessage += ": $($_.Exception.Message)"
       
       $errorRecord = [System.Management.Automation.ErrorRecord]::new(
           $_.Exception,
           'IdentityAPICallFailed',
           [System.Management.Automation.ErrorCategory]::InvalidOperation,
           $apiUrl
       )
       $PSCmdlet.ThrowTerminatingError($errorRecord)
   } finally {
       # Cleanup sensitive data
       $ClientSecret = $null
       if ($bstr) {
           [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
       }
   }
   ```

3. **Add Comprehensive Comment-Based Help**
   ```powershell
   <#
   .SYNOPSIS
       Authenticates to CyberArk Identity and returns authorization headers.
   
   .DESCRIPTION
       The Get-IdentityHeader function authenticates to CyberArk Identity Security Platform Shared Services using various authentication methods including Username/Password, OAuth, MFA challenges, and OOBAUTHPIN (SAML). It returns authorization headers that can be used for subsequent API calls.
       
       The function supports automatic token refresh for OAuth authentication when credentials are stored in the session. For MFA-based authentication, manual re-authentication is required when tokens expire.
   
   .PARAMETER IdentityUserName
       The username to authenticate with. Used for interactive authentication with MFA challenges.
   
   .PARAMETER UPCreds
       PSCredential object containing username and password for non-interactive authentication.
   
   .PARAMETER OAuthCreds
       PSCredential object containing OAuth ClientID (username) and ClientSecret (password) for OAuth authentication.
   
   .PARAMETER ClientId
       OAuth Client ID as plain text string. Use with ClientSecret parameter.
   
   .PARAMETER ClientSecret
       OAuth Client Secret as plain text string. Use with ClientId parameter.
   
   .PARAMETER PIN
       PIN code for OOBAUTHPIN authentication. If not provided, user will be prompted after SAML authentication.
   
   .PARAMETER EnableTranscript
       Switch to enable PowerShell transcript logging of the authentication session.
   
   .PARAMETER ForceNewSession
       Switch to force new authentication even if valid session exists.
   
   .PARAMETER IdentityTenantURL
       Direct URL to Identity tenant (e.g., https://tenant.id.cyberark.cloud).
   
   .PARAMETER PCloudURL
       Privilege Cloud URL. Identity URL will be auto-discovered from this.
   
   .PARAMETER PCloudSubdomain
       Privilege Cloud subdomain. Used for constructing URLs.
   
   .PARAMETER TranscriptPath
       Path for transcript log file. Defaults to current directory with timestamp.
   
   .OUTPUTS
       System.String
       Returns the Bearer token string (e.g., 'eyJ0eXAiOiJKV1QiLC...'). For PCloud API calls, use as: -logonToken $token
   
   .EXAMPLE
       $token = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://tenant.cyberark.cloud"
       
       Authenticates using OAuth credentials and returns the Bearer token string.
   
   .EXAMPLE
       $token = Get-IdentityHeader -IdentityUserName "admin@company.com" -IdentityTenantURL "https://tenant.id.cyberark.cloud" -Verbose
       .\Accounts_Onboard_Utility.ps1 -PVWAURL "https://tenant.privilegecloud.cyberark.cloud" -logonToken $token
       
       Authenticates interactively with verbose output, then uses token with onboarding utility.
   
   .EXAMPLE
       $token = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://tenant.cyberark.cloud"
       Invoke-RestMethod -Uri "$pvwaUrl/PasswordVault/API/Accounts" -Method Get -Headers @{Authorization = $token}
       
       Authenticates with OAuth and uses token for direct REST API call.
   
   .NOTES
       Version:        2.0.0
       Author:         CyberArk
       Creation Date:  2026-01-28
       Purpose/Change: Complete rewrite with OOBAUTHPIN support, PS7 classes, and modern PowerShell standards
       
       Requires:       PowerShell 5.1 (IdentityAuth.psm1) or PowerShell 7.0+ (IdentityAuth7.psm1)
       
   .LINK
       https://docs.cyberark.com/identity-administration/latest/en/content/developer/authentication/adaptive-mfa-overview.htm
   
   .LINK
       https://api-docs.cyberark.com/create-api-token/docs/create-api-token
   #>
   ```

4. **Add Parameter Validation Attributes**
   - `[ValidateNotNullOrEmpty()]` on all mandatory string parameters
   - `[ValidatePattern('^\d+$')]` on PIN parameter (numeric only)
   - `[ValidateScript()]` on TranscriptPath (verify parent directory exists)
   - `[ValidateSet()]` where applicable for enumerated values

5. **Implement Consistent Error Categories**
   - AuthenticationError: Failed authentication attempts
   - InvalidOperation: API call failures
   - InvalidArgument: Invalid parameter values
   - ObjectNotFound: Resource not found errors
   - ConnectionError: Network/connectivity issues

#### Success Criteria
- ✅ All parameters ordered correctly (Auth → Switches → Config)
- ✅ All API calls wrapped in try/catch/finally
- ✅ Proper ErrorRecord construction with category, target, ID
- ✅ Comprehensive comment-based help on all functions
- ✅ Parameter validation prevents invalid inputs
- ✅ Sensitive data cleaned up in finally blocks
- ✅ Error messages are clear and actionable

---

### Step 6: Implement Automatic Token Refresh Logic
**Duration**: 3-4 days

#### Tasks
1. **Add Session Expiry Checking**
   ```powershell
   # At start of Get-IdentityHeader
   if (-not $ForceNewSession -and $script:CurrentSession) {
       Write-Verbose "Checking existing session"
       
       $isExpired = (Get-Date) -gt $script:CurrentSession.TokenExpiry
       $isExpiringSoon = $script:CurrentSession.TokenExpiry -lt (Get-Date).AddSeconds(60)
       
       if ($isExpired) {
           Write-Verbose "Token expired, attempting refresh"
           # Attempt refresh
       } elseif ($isExpiringSoon) {
           Write-Warning "Token expires in less than 60 seconds. Consider refreshing."
       } else {
           Write-Verbose "Using existing valid token"
           return (ConvertFrom-SessionToHeaders -Session $script:CurrentSession)
       }
   }
   ```

2. **Implement OAuth Auto-Refresh**
   ```powershell
   # PS7 version with method
   [void] Refresh() {
       if ($this.AuthMethod -eq [AuthenticationMechanism]::OAuth) {
           if ($this.StoredCredentials) {
               Write-Verbose "Auto-refreshing OAuth token"
               
               $ClientId = $this.StoredCredentials.UserName
               $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.StoredCredentials.Password)
               $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
               
               try {
                   $body = "grant_type=client_credentials&client_id=$ClientId&client_secret=$ClientSecret"
                   $oauthParams = @{
                       Uri = "$($this.IdentityURL)/OAuth2/Token/$ClientId"
                       Method = 'Post'
                       ContentType = 'application/x-www-form-urlencoded'
                       Body = $body
                       ErrorAction = 'Stop'
                   }
                   $response = Invoke-RestMethod @oauthParams
                   
                   $this.Token = $response.access_token
                   $this.TokenExpiry = (Get-Date).AddSeconds($response.expires_in)
                   $this.Metadata.LastRefreshed = Get-Date
                   $this.Metadata.RefreshCount++
                   
                   Write-Verbose "OAuth token refreshed successfully"
               } catch {
                   throw "Failed to refresh OAuth token: $($_.Exception.Message)"
               } finally {
                   if ($bstr) {
                       [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                   }
                   $ClientSecret = $null
               }
           } else {
               throw "Cannot refresh: OAuth credentials not stored in session"
           }
       } else {
           throw "Cannot auto-refresh: AuthMethod $($this.AuthMethod) requires user interaction"
       }
   }
   
   # PS5.1 version with function
   function Update-IdentitySession {
       param([hashtable]$Session)
       
       if ($Session.AuthMethod -eq 'OAuth') {
           if ($Session.StoredCredentials) {
               Write-Verbose "Auto-refreshing OAuth token"
               # ... same logic as PS7 version ...
           } else {
               throw "Cannot refresh: OAuth credentials not stored"
           }
       } else {
           throw "Cannot auto-refresh: Manual re-authentication required"
       }
   }
   ```

3. **Handle MFA Re-Authentication**
   ```powershell
   # For MFA, inform user and re-authenticate
   if ($isExpired -and $script:CurrentSession.AuthMethod -ne 'OAuth') {
       Write-Warning "Token expired. MFA re-authentication required."
       Clear-IdentitySession
       # Fall through to normal authentication flow
   }
   ```

4. **Add Clear-IdentitySession Function**
   ```powershell
   function Clear-IdentitySession {
       <#
       .SYNOPSIS
           Clears the current Identity authentication session.
       .DESCRIPTION
           Clears the stored session from memory, optionally calling the Identity logout endpoint.
       .PARAMETER NoLogout
           Skip calling the logout API endpoint.
       .EXAMPLE
           Clear-IdentitySession
       #>
       [CmdletBinding()]
       param(
           [switch]$NoLogout
       )
       
       if ($script:CurrentSession) {
           if (-not $NoLogout) {
               try {
                   Write-Verbose "Logging out of Identity session"
                   $logoutUrl = "$($script:CurrentSession.IdentityURL)/Security/logout"
                   $headers = @{
                       'Authorization' = "Bearer $($script:CurrentSession.Token)"
                       'X-IDAP-NATIVE-CLIENT' = 'true'
                   }
                   $logoutParams = @{
                       Uri = $logoutUrl
                       Method = 'Post'
                       Headers = $headers
                       ErrorAction = 'SilentlyContinue'
                   }
                   Invoke-RestMethod @logoutParams | Out-Null
               } catch {
                   Write-Verbose "Logout call failed: $($_.Exception.Message)"
               }
           }
           
           # Clear session
           $script:CurrentSession = $null
           Write-Verbose "Session cleared"
       }
   }
   ```

5. **Add Get-IdentitySession Function**
   ```powershell
   function Get-IdentitySession {
       <#
       .SYNOPSIS
           Returns the current Identity authentication session.
       .DESCRIPTION
           Returns details about the current stored session including token expiry, authentication method, and metadata.
       .EXAMPLE
           Get-IdentitySession
       .OUTPUTS
           IdentitySession object (PS7) or hashtable (PS5.1)
       #>
       [CmdletBinding()]
       param()
       
       if ($script:CurrentSession) {
           return $script:CurrentSession
       } else {
           Write-Warning "No active session"
           return $null
       }
   }
   ```

#### Success Criteria
- ✅ OAuth tokens refresh automatically when expired
- ✅ MFA tokens prompt for re-authentication
- ✅ Expiry warnings shown 60 seconds before expiration
- ✅ Clear-IdentitySession removes session cleanly
- ✅ Get-IdentitySession shows current session details
- ✅ ForceNewSession bypasses existing session

---

### Step 7: Create VS Code Tasks and Testing Infrastructure
**Duration**: 2-3 days

#### Tasks
1. **Create .vscode/tasks.json**
   ```json
   {
       "version": "2.0.0",
       "tasks": [
           {
               "label": "Format PowerShell Files (Identity Auth)",
               "type": "shell",
               "command": "pwsh",
               "args": [
                   "-NoProfile",
                   "-Command",
                   "Get-ChildItem -Path '${workspaceFolder}\\Identity Authentication\\*.psm1','${workspaceFolder}\\Identity Authentication\\*.ps1' -Recurse | ForEach-Object { Invoke-Formatter -ScriptDefinition (Get-Content $_.FullName -Raw) -Settings ${workspaceFolder}\\Identity Authentication\\PSScriptAnalyzerSettings.psd1 | Set-Content $_.FullName -Encoding UTF8 }"
               ],
               "problemMatcher": [],
               "group": "build"
           },
           {
               "label": "Analyze PS5.1 Module (IdentityAuth.psm1)",
               "type": "shell",
               "command": "pwsh",
               "args": [
                   "-NoProfile",
                   "-Command",
                   "Invoke-ScriptAnalyzer -Path '${workspaceFolder}\\Identity Authentication\\IdentityAuth.psm1' -Settings '${workspaceFolder}\\Identity Authentication\\PSScriptAnalyzerSettings.psd1' -ReportSummary"
               ],
               "problemMatcher": [],
               "group": "test"
           },
           {
               "label": "Analyze PS7 Module (IdentityAuth7.psm1)",
               "type": "shell",
               "command": "pwsh",
               "args": [
                   "-NoProfile",
                   "-Command",
                   "Invoke-ScriptAnalyzer -Path '${workspaceFolder}\\Identity Authentication\\IdentityAuth7.psm1' -Settings '${workspaceFolder}\\Identity Authentication\\PSScriptAnalyzerSettings.psd1' -ReportSummary"
               ],
               "problemMatcher": [],
               "group": "test"
           },
           {
               "label": "Debug: OOBAUTHPIN Flow",
               "type": "shell",
               "command": "pwsh",
               "args": [
                   "-NoProfile",
                   "-NoExit",
                   "-Command",
                   "Import-Module '${workspaceFolder}\\Identity Authentication\\IdentityAuth7.psm1' -Force; Write-Host 'Module loaded. Test OOBAUTHPIN:' -ForegroundColor Green; Write-Host 'Example: $headers = Get-IdentityHeader -IdentityUserName \"user@domain.com\" -PCloudURL \"https://tenant.cyberark.cloud\" -Verbose' -ForegroundColor Yellow"
               ],
               "problemMatcher": [],
               "group": "none"
           },
           {
               "label": "Debug: OAuth Flow",
               "type": "shell",
               "command": "pwsh",
               "args": [
                   "-NoProfile",
                   "-NoExit",
                   "-Command",
                   "Import-Module '${workspaceFolder}\\Identity Authentication\\IdentityAuth7.psm1' -Force; Write-Host 'Module loaded. Test OAuth:' -ForegroundColor Green; Write-Host 'Example: $creds = Get-Credential -Message \"ClientID (Username) and ClientSecret (Password)\"; $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL \"https://tenant.cyberark.cloud\" -Verbose' -ForegroundColor Yellow"
               ],
               "problemMatcher": [],
               "group": "none"
           },
           {
               "label": "Debug: Standard Challenges",
               "type": "shell",
               "command": "pwsh",
               "args": [
                   "-NoProfile",
                   "-NoExit",
                   "-Command",
                   "Import-Module '${workspaceFolder}\\Identity Authentication\\IdentityAuth7.psm1' -Force; Write-Host 'Module loaded. Test Standard Challenges (UP/OTP/Push):' -ForegroundColor Green; Write-Host 'Example: $headers = Get-IdentityHeader -IdentityUserName \"user@domain.com\" -IdentityTenantURL \"https://tenant.id.cyberark.cloud\" -Verbose' -ForegroundColor Yellow"
               ],
               "problemMatcher": [],
               "group": "none"
           }
       ]
   }
   ```

2. **Create .vscode/settings.json**
   ```json
   {
       "powershell.codeFormatting.preset": "Custom",
       "powershell.codeFormatting.openBraceOnSameLine": true,
       "powershell.codeFormatting.newLineAfterOpenBrace": true,
       "powershell.codeFormatting.newLineAfterCloseBrace": true,
       "powershell.codeFormatting.whitespaceBeforeOpenBrace": true,
       "powershell.codeFormatting.whitespaceBeforeOpenParen": true,
       "powershell.codeFormatting.whitespaceAroundOperator": true,
       "powershell.codeFormatting.whitespaceAfterSeparator": true,
       "powershell.codeFormatting.ignoreOneLineBlock": true,
       "powershell.codeFormatting.alignPropertyValuePairs": true,
       "powershell.codeFormatting.useCorrectCasing": true,
       "powershell.scriptAnalysis.enable": true,
       "powershell.scriptAnalysis.settingsPath": "Identity Authentication/PSScriptAnalyzerSettings.psd1",
       "editor.formatOnSave": true,
       "editor.tabSize": 4,
       "editor.insertSpaces": true,
       "files.encoding": "utf8bom",
       "files.eol": "\r\n"
   }
   ```

3. **Create Test-IdentityAuthManual.ps1**
   ```powershell
   <#
   .SYNOPSIS
       Interactive testing menu for Identity Authentication module
   .DESCRIPTION
       Provides interactive menu for testing all authentication flows and validation
   #>
   param(
       [ValidateSet('5.1', '7')]
       [string]$PSVersion = '7'
   )
   
   $modulePath = if ($PSVersion -eq '7') {
       "$PSScriptRoot\IdentityAuth7.psm1"
   } else {
       "$PSScriptRoot\IdentityAuth.psm1"
   }
   
   Import-Module $modulePath -Force
   
   function Show-Menu {
       Clear-Host
       Write-Output @"
   
   ============================================================
   Identity Authentication Module - Manual Testing
   ============================================================
   PowerShell Version: $($PSVersionTable.PSVersion)
   Module: $modulePath
   ============================================================
   
   1. Test OOBAUTHPIN Authentication
   2. Test OAuth Authentication
   3. Test Standard Challenges (UP/OTP/Push)
   4. Test Token Refresh
   5. Validate Return Structure
   6. Run PSScriptAnalyzer
   7. View Current Session
   8. Clear Session
   9. Exit
   
   ============================================================
   "@
       Write-Host "Select option (1-9): " -NoNewline -ForegroundColor Yellow
   }
   
   do {
       Show-Menu
       $choice = Read-Host
       
       switch ($choice) {
           '1' {
               # Test OOBAUTHPIN
               $username = Read-Host "Enter username"
               $pcloudUrl = Read-Host "Enter PCloud URL (e.g., https://tenant.cyberark.cloud)"
               
               Write-Output "`nTesting OOBAUTHPIN flow...`n"
               $headers = Get-IdentityHeader -IdentityUserName $username -PCloudURL $pcloudUrl -Verbose
               Write-Output "`nResult:"
               $headers | ConvertTo-Json -Depth 5
               Read-Host "`nPress Enter to continue"
           }
           '2' {
               # Test OAuth
               $pcloudUrl = Read-Host "Enter PCloud URL"
               $creds = Get-Credential -Message "OAuth Credentials (ClientID as Username, ClientSecret as Password)"
               
               Write-Output "`nTesting OAuth flow...`n"
               $headers = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $pcloudUrl -Verbose
               Write-Output "`nResult:"
               $headers | ConvertTo-Json -Depth 5
               Read-Host "`nPress Enter to continue"
           }
           '3' {
               # Test Standard Challenges
               $username = Read-Host "Enter username"
               $identityUrl = Read-Host "Enter Identity URL (e.g., https://tenant.id.cyberark.cloud)"
               
               Write-Output "`nTesting standard challenge flow...`n"
               $headers = Get-IdentityHeader -IdentityUserName $username -IdentityTenantURL $identityUrl -Verbose
               Write-Output "`nResult:"
               $headers | ConvertTo-Json -Depth 5
               Read-Host "`nPress Enter to continue"
           }
           '4' {
               # Test Token Refresh
               Write-Output "`nTesting token refresh...`n"
               $session = Get-IdentitySession
               if ($session) {
                   Write-Output "Current session:"
                   $session | ConvertTo-Json -Depth 5
                   Write-Output "`nAttempting refresh..."
                   # Force expiry for testing
                   $session.TokenExpiry = (Get-Date).AddSeconds(-10)
                   $headers = Get-IdentityHeader -Verbose
                   Write-Output "`nRefreshed:"
                   $headers | ConvertTo-Json -Depth 5
               } else {
                   Write-Warning "No active session"
               }
               Read-Host "`nPress Enter to continue"
           }
           '5' {
               # Validate Return Structure
               Write-Output "`nValidating return structure...`n"
               $session = Get-IdentitySession
               if ($session) {
                   $headers = Get-IdentityHeader
                   
                   Write-Output "Checking required keys..."
                   $hasAuth = $headers.ContainsKey('Authorization')
                   $hasNative = $headers.ContainsKey('X-IDAP-NATIVE-CLIENT')
                   
                   Write-Output "Authorization: $hasAuth"
                   Write-Output "X-IDAP-NATIVE-CLIENT: $hasNative"
                   
                   if ($hasAuth -and $hasNative) {
                       Write-Output "`nValidation PASSED" -ForegroundColor Green
                   } else {
                       Write-Output "`nValidation FAILED" -ForegroundColor Red
                   }
               } else {
                   Write-Warning "No active session. Authenticate first."
               }
               Read-Host "`nPress Enter to continue"
           }
           '6' {
               # Run PSScriptAnalyzer
               Write-Output "`nRunning PSScriptAnalyzer...`n"
               $results = Invoke-ScriptAnalyzer -Path $modulePath -Settings "$PSScriptRoot\PSScriptAnalyzerSettings.psd1"
               if ($results) {
                   Write-Output "Issues found:"
                   $results | Format-Table -AutoSize
               } else {
                   Write-Output "No issues found. Module passes all checks." -ForegroundColor Green
               }
               Read-Host "`nPress Enter to continue"
           }
           '7' {
               # View Current Session
               Write-Output "`nCurrent Session:`n"
               $session = Get-IdentitySession
               if ($session) {
                   $session | ConvertTo-Json -Depth 5
               } else {
                   Write-Warning "No active session"
               }
               Read-Host "`nPress Enter to continue"
           }
           '8' {
               # Clear Session
               Write-Output "`nClearing session...`n"
               Clear-IdentitySession -Verbose
               Write-Output "Session cleared"
               Read-Host "`nPress Enter to continue"
           }
           '9' {
               Write-Output "`nExiting..."
               break
           }
           default {
               Write-Warning "Invalid selection"
               Start-Sleep -Seconds 1
           }
       }
   } while ($choice -ne '9')
   ```

4. **Create Capture-CurrentModuleOutput.ps1**
   ```powershell
   <#
   .SYNOPSIS
       Captures output from current IdentityAuth module for compatibility testing
   .DESCRIPTION
       Runs existing module against live environment and captures return structure
   #>
   param(
       [Parameter(Mandatory)]
       [string]$TestType  # 'OAuth', 'UP', 'MFA', 'SAML'
   )
   
   # Import current module
   Import-Module "$PSScriptRoot\IdentityAuth.psm1" -Force
   
   Write-Output "Testing $TestType authentication flow..."
   Write-Output "This will capture the CURRENT module output for comparison"
   Write-Output ""
   
   switch ($TestType) {
       'OAuth' {
           $creds = Get-Credential -Message "OAuth Credentials"
           $pcloudUrl = Read-Host "PCloud URL"
           $result = Get-IdentityHeader -OAuthCreds $creds -PCloudURL $pcloudUrl
       }
       # Add other types as needed
   }
   
   # Serialize and save
   $outputPath = "$PSScriptRoot\baseline_$TestType.json"
   $result | ConvertTo-Json -Depth 10 | Set-Content $outputPath -Encoding UTF8
   Write-Output "Baseline saved to: $outputPath"
   ```

#### Success Criteria
- ✅ VS Code tasks format PowerShell files correctly
- ✅ PSScriptAnalyzer tasks run and report results
- ✅ Debug tasks launch with proper module and examples
- ✅ Manual test script provides interactive testing
- ✅ Baseline capture script works with live environment
- ✅ Alt+Shift+F formats without creating violations

---

### Step 8: Create Dual README Documentation
**Duration**: 2-3 days

#### Tasks
1. **Create README.md (End User Documentation)**
   - Quick start guide with simple examples
   - Authentication method comparison table
   - Common scenarios and solutions
   - Troubleshooting section
   - Module selection guide (PS5.1 vs PS7)

2. **Create README-Developer.md (Developer Documentation)**
   - Architecture overview
   - Class and enum documentation
   - Process flow diagrams
   - API endpoint mappings
   - Security considerations
   - Contributing guidelines

3. **Update Existing README in Identity Authentication Directory**
   - Add links to new documentation
   - Mark SAML as deprecated
   - Add OOBAUTHPIN documentation
   - Update examples

#### Success Criteria
- ✅ README.md clear for non-technical users
- ✅ README-Developer.md comprehensive for developers
- ✅ All examples tested and working
- ✅ Migration guidance from v1 to v2
- ✅ Module selection guidance clear

---

### Step 9: Final Testing and Validation
**Duration**: 3-4 days

#### Tasks
1. **Manual Testing Against Live Environment**
   - Test OAuth flow with valid credentials
   - Test OOBAUTHPIN flow end-to-end
   - Test standard challenges (UP, OTP, Push)
   - Test token refresh for OAuth
   - Test with Accounts_Onboard_Utility.ps1

2. **PSScriptAnalyzer Validation**
   - Run on both IdentityAuth.psm1 and IdentityAuth7.psm1
   - Verify zero Info/Warning/Error violations
   - Fix any issues found
   - Document any suppressed rules with justification

3. **PowerShell Version Testing**
   - Test IdentityAuth.psm1 on PowerShell 5.1
   - Test IdentityAuth7.psm1 on PowerShell 7.4
   - Verify feature parity between versions
   - Document any version-specific behaviors

4. **Integration Testing**
   - Test with actual scripts from epv-api-scripts
   - Verify return structure compatibility
   - Test session persistence across multiple script calls
   - Validate error handling in real scenarios

5. **Documentation Review**
   - Verify all examples work
   - Check for typos and formatting
   - Validate all links
   - Ensure migration guide is complete

#### Success Criteria
- ✅ All authentication methods work in live environment
- ✅ Zero PSScriptAnalyzer violations
- ✅ Compatible with PowerShell 5.1 and 7.4
- ✅ Integration with existing scripts works
- ✅ Documentation complete and accurate

---

## Timeline Summary

| Step | Duration | Cumulative |
|------|----------|------------|
| 1. Dual Module Structure | 3-5 days | 5 days |
| 2. OOBAUTHPIN Implementation | 3-4 days | 9 days |
| 3. OAuth Modernization | 2-3 days | 12 days |
| 4. Replace Write-LogMessage | 2-3 days | 15 days |
| 5. Error Handling & Parameters | 3-4 days | 19 days |
| 6. Token Refresh Logic | 3-4 days | 23 days |
| 7. VS Code Tasks & Testing | 2-3 days | 26 days |
| 8. Dual README Documentation | 2-3 days | 29 days |
| 9. Final Testing & Validation | 3-4 days | 33 days |

**Total Estimated Duration**: 26-33 days (approximately 5-7 weeks)

---

## Success Criteria

### Functional Requirements
- ✅ OOBAUTHPIN replaces SAML completely
- ✅ OAuth supports PSCredential, plain text, and SecureString
- ✅ Automatic token refresh for OAuth
- ✅ Manual re-auth prompt for MFA when expired
- ✅ Session persistence with `$script:CurrentSession`
- ✅ Transcript logging support

### Code Quality Requirements
- ✅ Zero PSScriptAnalyzer Info/Warning/Error violations
- ✅ Zero Write-Host calls (use Write-Output/Write-Verbose/Write-Warning)
- ✅ Zero backticks (use splatting exclusively)
- ✅ All multi-parameter calls use splatting
- ✅ UTF-8 with BOM encoding
- ✅ Proper error handling with ErrorRecord
- ✅ Sensitive data cleanup in finally blocks

### PowerShell Standards Compliance
- ✅ Named parameters used throughout
- ✅ `$null` on left side of comparisons
- ✅ Approved PowerShell verbs
- ✅ Parameter ordering: Auth → Switches → Config
- ✅ Comprehensive comment-based help
- ✅ Parameter validation attributes

### Platform Requirements
- ✅ IdentityAuth.psm1 works on PowerShell 5.1
- ✅ IdentityAuth7.psm1 works on PowerShell 7.0+
- ✅ PS7 version uses classes, enums, modern operators
- ✅ Both versions return identical structures
- ✅ Feature parity between versions

### Integration Requirements
- ✅ Compatible with Accounts_Onboard_Utility.ps1
- ✅ Token reusable across multiple scripts
- ✅ Return structure matches current expectations

### User Experience Requirements
- ✅ Single-step interactive authentication
- ✅ Clear OOBAUTHPIN instructions displayed
- ✅ Helpful error messages
- ✅ Verbose output provides operational context
- ✅ Transcript support for troubleshooting

### Documentation Requirements
- ✅ README.md for end users
- ✅ README-Developer.md for developers
- ✅ IMPLEMENTATION-PLAN.md (this document)
- ✅ ARCHITECTURE-DESIGN.md with diagrams
- ✅ Comment-based help on all functions
- ✅ VS Code tasks documented

---

## Risk Mitigation

### Identified Risks

1. **API Compatibility**
   - **Risk**: Identity API changes breaking functionality
   - **Mitigation**: Version API calls, extensive testing, monitor CyberArk release notes

2. **Token Refresh Limitations**
   - **Risk**: Unable to auto-refresh MFA tokens
   - **Mitigation**: Clear documentation, graceful degradation, helpful error messages

3. **PowerShell Version Differences**
   - **Risk**: Behavior differences between PS 5.1 and 7+
   - **Mitigation**: Extensive cross-version testing, conditional code paths, clear documentation

4. **Breaking Changes**
   - **Risk**: New module incompatible with existing scripts
   - **Mitigation**: Maintain return structure compatibility, provide migration guide, version properly

5. **OOBAUTHPIN Availability**
   - **Risk**: Not all tenants support OOBAUTHPIN
   - **Mitigation**: Fallback to standard challenge flow, clear error messages, detect capability

---

## Next Actions

After implementation plan approval:

1. **Create Baseline Capture**
   - Run current module against live environment
   - Capture OAuth output structure
   - Capture standard auth output structure
   - Save as JSON for comparison

2. **Begin Implementation**
   - Start with Step 1 (Dual Module Structure)
   - Create PSScriptAnalyzerSettings.psd1 first
   - Create VS Code settings.json
   - Implement classes/enums for PS7
   - Create PS5.1 hashtable equivalents

3. **Iterative Testing**
   - Test after each step
   - Run PSScriptAnalyzer continuously
   - Compare output with baseline
   - Fix issues immediately

4. **Documentation**
   - Update docs as features are implemented
   - Keep README.md and README-Developer.md in sync
   - Document any deviations from plan

---

## Maintenance Plan

### Post-Implementation
- Monitor for CyberArk API changes
- Address bug reports promptly
- Review security advisories
- Update dependencies

### Versioning
- Use Semantic Versioning (MAJOR.MINOR.PATCH)
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

### Support Channels
- GitHub Issues for bug reports
- Discussions for questions
- Pull requests for contributions

---

## Conclusion

This implementation plan provides a comprehensive roadmap for modernizing the IdentityAuth module. The phased approach ensures each component is thoroughly tested before moving to the next, while maintaining backward compatibility and following PowerShell best practices.

The estimated 5-7 week timeline accounts for development, testing, and documentation, with flexibility for unforeseen challenges. The dual-module approach (PS5.1 and PS7) ensures broad compatibility while leveraging modern PowerShell features where available.

Key focus areas:
1. **Standards Compliance**: Zero PSScriptAnalyzer violations, proper parameter usage, comprehensive error handling
2. **User Experience**: Single-step authentication, clear instructions, helpful error messages
3. **Security**: Sensitive data masking, automatic cleanup, secure token storage
4. **Compatibility**: Works with existing scripts, maintains return structure, supports both PS versions

Upon completion, the module will provide a robust, secure, and user-friendly authentication experience for CyberArk Identity, supporting all modern authentication methods including the new OOBAUTHPIN flow.
