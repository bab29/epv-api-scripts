# Developer Guide: IdentityAuth Module v2

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Development Setup](#development-setup)
- [Code Structure](#code-structure)
- [Adding New Authentication Methods](#adding-new-authentication-methods)
- [Testing Guidelines](#testing-guidelines)
- [Build Process](#build-process)
- [Coding Standards](#coding-standards)
- [Troubleshooting](#troubleshooting)

## Architecture Overview

### Module Structure

```
v2-Modernized/
├── PS5.1/                      # PowerShell 5.1 version
│   ├── Private/                # Internal helper functions
│   ├── Public/                 # Exported functions
│   ├── IdentityAuth.psm1      # Module script
│   └── IdentityAuth.psd1      # Module manifest
├── PS7/                        # PowerShell 7+ version
│   ├── Classes/                # PowerShell classes
│   ├── Enums/                  # PowerShell enums
│   ├── Private/                # Internal helper functions
│   ├── Public/                 # Exported functions
│   ├── IdentityAuth.psm1      # Module script
│   └── IdentityAuth.psd1      # Module manifest
├── Build/                      # Build scripts
├── Tests/                      # Pester tests
├── Tools/                      # Diagnostic/utility tools
├── Examples/                   # Usage examples
└── Documentation/              # Project documentation
```

### Design Principles

1. **Dual Version Support:** Maintain compatibility with PS5.1 while leveraging PS7 features
2. **Separation of Concerns:** Private helpers vs public API
3. **Parameter Sets:** Different auth methods via parameter sets
4. **Token Caching:** Automatic OAuth token management
5. **Structured Logging:** Consistent logging infrastructure
6. **Error Handling:** Detailed errors with troubleshooting hints

## Development Setup

### Prerequisites

```powershell
# Required
PowerShell 5.1 or 7+

# Optional but recommended
Install-Module -Name Pester -MinimumVersion 5.0.0 -Scope CurrentUser
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
```

### Clone and Build

```powershell
# Navigate to module directory
Set-Location 'g:\epv-api-scripts\Identity Authentication\v2-Modernized'

# Build PS5.1 version
.\Build\Build-PS51Module.ps1

# Build PS7 version (requires PS7+)
pwsh .\Build\Build-PS7Module.ps1

# Or use VS Code task
Ctrl+Shift+B
```

### Load for Development

```powershell
# Import from source (for debugging)
Import-Module .\PS5.1\IdentityAuth.psd1 -Force

# Import from distribution (after build)
Import-Module .\Distribution\IdentityAuth\IdentityAuth.psd1 -Force
```

## Code Structure

### Private Functions (PS5.1/Private/)

**Authentication:**
- `Get-OAuthToken.ps1` - OAuth client credentials
- `Start-OOBAUTHPINAuthentication.ps1` - Start OOBAUTHPIN session
- `Get-OOBAUTHPINMechanism.ps1` - Find OOBAUTHPIN mechanism
- `Send-OOBAUTHPIN.ps1` - Send PIN to user
- `Submit-OOBAUTHPINCode.ps1` - Verify PIN
- `Invoke-UsernamePasswordAuth.ps1` - Username/password flow
- `Get-AuthenticationMechanism.ps1` - Generic mechanism finder
- `Submit-OTPCode.ps1` - OTP verification
- `Start-PushAuthentication.ps1` - Push notification flow

**Infrastructure:**
- `Format-IdentityHeaders.ps1` - Create PCloud headers
- `Get-NormalizedPCloudURL.ps1` - URL normalization
- `Get-IdentityURLFromPCloud.ps1` - Derive Identity URL
- `Test-TokenExpired.ps1` - Token expiry check
- `Write-IdentityLog.ps1` - Structured logging
- `New-IdentityErrorRecord.ps1` - Enhanced errors
- `Test-AuthenticationResponse.ps1` - Response validation
- `Hide-SensitiveData.ps1` - Data masking

### Public Functions (PS5.1/Public/)

- `Get-IdentityHeader.ps1` - Main authentication function
  - Parameter Sets: OAuth, OOBAUTHPIN, UsernamePassword, OTP, Push

### PS7 Enhancements (PS7/Classes/, PS7/Enums/)

**Classes:**
- `IdentitySession.ps1` - Session object with methods
- `OAuthTokenResponse.ps1` - Token response with validation

**Enums:**
- `AuthenticationMethod.ps1` - Type-safe auth methods

## Adding New Authentication Methods

### Step 1: Create Private Helper

Create `PS5.1/Private/New-AuthMethod.ps1`:

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Brief description

.DESCRIPTION
    Detailed description
#>

function Invoke-NewAuthMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,
        
        [Parameter(Mandatory)]
        [string]$MechanismId,
        
        [Parameter(Mandatory)]
        [string]$IdentityTenantURL
    )
    
    Write-IdentityLog -Message "Starting new auth method" -Level Verbose -Component 'NewAuth'
    
    try {
        # Implementation
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType 'application/json'
        
        # Validate response
        $null = Test-AuthenticationResponse -Response $response -AuthMethod 'NewAuth'
        
        if ($response.Result.Auth) {
            Write-IdentityLog -Message "New auth successful" -Level Verbose -Component 'NewAuth'
            return $response.Result.Auth
        }
    } catch {
        $safeMessage = Get-SafeErrorMessage -ErrorRecord $_
        Write-IdentityLog -Message "New auth failed: $safeMessage" -Level Error -Component 'NewAuth'
        throw
    }
}
```

### Step 2: Update Get-IdentityHeader

Add parameter set:

```powershell
[Parameter(Mandatory, ParameterSetName = 'NewAuth')]
[string]$NewAuthParameter,
```

Add process block logic:

```powershell
if ($PSCmdlet.ParameterSetName -eq 'NewAuth') {
    Write-Verbose "Authenticating with NewAuth"
    
    $authSession = Start-OOBAUTHPINAuthentication -Username $Username -IdentityTenantURL $IdentityURL
    $mechanism = Get-AuthenticationMechanism -Challenges $authSession.Challenges -AnswerType 'NewType'
    $authToken = Invoke-NewAuthMethod -SessionId $authSession.SessionId -MechanismId $mechanism.MechanismId -IdentityTenantURL $IdentityURL
    
    $headers = Format-IdentityHeaders -AccessToken $authToken
    return $headers
}
```

### Step 3: Copy to PS7

```powershell
Copy-Item PS5.1\Private\New-AuthMethod.ps1 -Destination PS7\Private\
Copy-Item PS5.1\Public\Get-IdentityHeader.ps1 -Destination PS7\Public\
```

### Step 4: Add Tests

Create test in `Tests/Pester/Get-IdentityHeader.Tests.ps1`:

```powershell
Context 'NewAuth Authentication' {
    BeforeAll {
        Mock Invoke-RestMethod { @{ Result = @{ Auth = 'test_token' } } } -ModuleName IdentityAuth
    }
    
    It 'Should authenticate with NewAuth' {
        $result = Get-IdentityHeader -NewAuthParameter "value" -PCloudURL $url
        $result | Should -Not -BeNullOrEmpty
    }
}
```

### Step 5: Build and Test

```powershell
.\Build\Build-PS51Module.ps1
Invoke-Pester -Path .\Tests\Pester\
```

## Testing Guidelines

### Unit Tests

Focus on mocking external API calls:

```powershell
Describe 'Function' {
    BeforeAll {
        Mock Invoke-RestMethod { @{ success = $true } } -ModuleName IdentityAuth
    }
    
    It 'Should work' {
        $result = Test-Function
        $result | Should -Not -BeNullOrEmpty
    }
}
```

### Integration Tests

Use environment variables for credentials:

```powershell
BeforeAll {
    $env:TEST_OAUTH_CLIENTID = "client_id"
    $env:TEST_OAUTH_SECRET = "secret"
    $env:TEST_PCLOUD_URL = "https://tenant.cyberark.cloud"
}
```

### Running Tests

```powershell
# All tests
Invoke-Pester

# Unit tests only
Invoke-Pester -Tag 'Unit'

# Integration tests only
Invoke-Pester -Tag 'Integration'

# Specific file
Invoke-Pester -Path .\Tests\Pester\Get-IdentityHeader.Tests.ps1
```

## Build Process

### Manual Build

```powershell
# PS5.1
.\Build\Build-PS51Module.ps1

# PS7 (requires PS7+)
pwsh .\Build\Build-PS7Module.ps1
```

### VS Code Tasks

- `Ctrl+Shift+B` - Build PS5.1 (default)
- `Tasks: Run Task` → `Build: All Modules`
- `Tasks: Run Task` → `Deploy: Install to User Modules`

### Build Output

```
Distribution/
├── IdentityAuth/        # PS5.1 version
└── IdentityAuth-PS7/    # PS7 version
```

## Coding Standards

### PSScriptAnalyzer Compliance

```powershell
# Check compliance
Invoke-ScriptAnalyzer -Path .\PS5.1 -Settings .\PSScriptAnalyzerSettings.psd1 -Recurse

# Zero violations required!
```

### Naming Conventions

- Functions: `Verb-Noun` (approved verbs only)
- Parameters: `PascalCase`
- Variables: `$camelCase` (private), `$PascalCase` (public)
- No aliases in code

### Comment-Based Help

Every public function must have:

```powershell
<#
.SYNOPSIS
    Brief description

.DESCRIPTION
    Detailed description

.PARAMETER ParameterName
    Description

.EXAMPLE
    Example usage

.NOTES
    Version, author, etc.
#>
```

### Error Handling

```powershell
try {
    # Operation
} catch {
    $safeMessage = Get-SafeErrorMessage -ErrorRecord $_
    Write-IdentityLog -Message $safeMessage -Level Error -Component 'ComponentName'
    throw
}
```

### Logging

```powershell
Write-IdentityLog -Message "Operation started" -Level Verbose -Component 'ComponentName'
Write-IdentityLog -Message "Operation failed" -Level Error -Component 'ComponentName' -AdditionalData @{Detail="value"}
```

## Troubleshooting

### Module Not Loading

```powershell
# Check syntax
Test-ModuleManifest .\PS5.1\IdentityAuth.psd1

# Check for errors
Import-Module .\PS5.1\IdentityAuth.psd1 -Force -Verbose
```

### Function Not Found

```powershell
# Verify function is exported
(Get-Module IdentityAuth).ExportedFunctions.Keys

# Check manifest
$manifest = Import-PowerShellDataFile .\PS5.1\IdentityAuth.psd1
$manifest.FunctionsToExport
```

### PSScriptAnalyzer Failures

```powershell
# Get detailed output
Invoke-ScriptAnalyzer -Path .\PS5.1\Private\Function.ps1 -Settings .\PSScriptAnalyzerSettings.psd1

# Fix common issues:
# - Use Write-Verbose instead of Write-Host
# - Place $null on left: $null -ne $var
# - No positional parameters
# - Full cmdlet names (no aliases)
```

### Test Failures

```powershell
# Run with verbose output
Invoke-Pester -Output Detailed

# Debug specific test
$config = New-PesterConfiguration
$config.Run.Path = '.\Tests\Pester\Get-IdentityHeader.Tests.ps1'
$config.Output.Verbosity = 'Detailed'
$config.Debug.WriteDebugMessages = $true
Invoke-Pester -Configuration $config
```

## Contributing

1. Create feature branch from `main`
2. Make changes following coding standards
3. Add tests for new functionality
4. Run PSScriptAnalyzer (zero violations)
5. Run all tests
6. Build both PS5.1 and PS7 versions
7. Update documentation
8. Submit pull request

---

**Questions?** See [README-MODULE.md](README-MODULE.md) or open an issue.
