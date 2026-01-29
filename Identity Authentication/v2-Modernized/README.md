# Identity Authentication Module v2 - Modernized

**Status:** 📋 Planning & Design Phase  
**Target Release:** TBD  
**PowerShell Compatibility:** 5.1+ (IdentityAuth.psm1) and 7.0+ (IdentityAuth7.psm1)

---

## Overview

This is a **complete rewrite** of the Identity Authentication module with modern PowerShell standards, OOBAUTHPIN support (replacing deprecated SAML), and enhanced OAuth capabilities.

### Key Improvements Over v1

✅ **OOBAUTHPIN Flow** - Modern SAML replacement with PIN-based authentication  
✅ **Automatic OAuth Token Refresh** - No manual re-authentication needed  
✅ **Zero PSScriptAnalyzer Violations** - Strict code quality standards  
✅ **Dual PowerShell Versions** - PS5.1 baseline + PS7 with classes/enums/modern features  
✅ **No Write-Host** - Proper output streams (Write-Output, Write-Verbose, Write-Warning)  
✅ **Session State Management** - `$script:CurrentSession` with automatic expiry detection  
✅ **Comprehensive Logging** - Transcript support with sensitive data masking  
✅ **Simplified Return Value** - Returns Bearer token string (not hashtable)

---

## Module Structure

```
v2-Modernized/
├── README.md                           # This file
├── Documentation/
│   ├── IMPLEMENTATION-PLAN.md          # 9-step implementation roadmap (5-7 weeks)
│   ├── ARCHITECTURE-DESIGN.md          # Architecture with Mermaid diagrams
│   ├── PLANNING-SUMMARY.md             # Planning phase summary
│   └── DESIGN-CHANGES.md               # Design decisions and feedback
│
├── PS5.1/                              # 🚧 PowerShell 5.1 module (Step 1)
│   ├── IdentityAuth.psm1               # Main module (hashtables, traditional logic)
│   ├── IdentityAuth.psd1               # Module manifest
│   ├── Private/                        # Private helper functions
│   └── Public/                         # Exported public functions
│
├── PS7/                                # 🚧 PowerShell 7+ module (Step 1)
│   ├── IdentityAuth7.psm1              # Main module (classes, enums, ternary)
│   ├── IdentityAuth7.psd1              # Module manifest
│   ├── Classes/                        # Class definitions
│   ├── Enums/                          # Enum definitions
│   ├── Private/                        # Private helper functions
│   └── Public/                         # Exported public functions
│
├── Build/                              # 🚧 Build automation (Step 8)
│   ├── Build-Module.ps1                # Combines .ps1 → single .psm1
│   ├── Test-BeforeBuild.ps1            # Pre-build validation
│   └── Publish-Module.ps1              # PowerShell Gallery publish
│
├── Distribution/                       # 📦 OUTPUT - Built modules
│   ├── IdentityAuth.psm1               # SINGLE FILE for end users (PS5.1)
│   ├── IdentityAuth.psd1               # Manifest
│   ├── IdentityAuth7.psm1              # SINGLE FILE for end users (PS7+)
│   ├── IdentityAuth7.psd1              # Manifest
│   └── README.md                       # End-user quick start
│
├── Tests/                              # 🚧 Test infrastructure (Step 7)
│   ├── Test-IdentityAuthManual.ps1     # Interactive testing menu
│   └── Pester/                         # Pester v5 tests
│
├── .vscode/                            # ✅ VS Code configuration
│   ├── settings.json                   # PowerShell formatting rules
│   ├── tasks.json                      # Build/test/format tasks
│   └── extensions.json                 # Recommended extensions
│
└── PSScriptAnalyzerSettings.psd1       # 🚧 Strict analysis rules (Step 1)
```

---

## Build & Distribution Workflow

### For Developers 🛠️

**Work in organized source structure:**
```
PS5.1/
├── Private/     # Helper functions
└── Public/      # Exported functions

PS7/
├── Classes/     # Class definitions
├── Enums/       # Enum definitions
├── Private/     # Helper functions
└── Public/      # Exported functions
```

**Build single-file modules:**
```powershell
# Run build script (combines all .ps1 into one .psm1)
.\Build\Build-Module.ps1 -Version All

# Or use VS Code: Press Ctrl+Shift+B
```

**Output in Distribution/ folder:**
```
Distribution/
├── IdentityAuth.psm1      # SINGLE FILE (PS5.1)
├── IdentityAuth.psd1
├── IdentityAuth7.psm1     # SINGLE FILE (PS7+)
├── IdentityAuth7.psd1
└── README.md
```

### For End Users 📦

**Receive Distribution/ folder contents:**
- `IdentityAuth.psm1` + `IdentityAuth.psd1` (PowerShell 5.1+)
- `IdentityAuth7.psm1` + `IdentityAuth7.psd1` (PowerShell 7+)

**Simple import:**
```powershell
# PowerShell 5.1+
Import-Module .\IdentityAuth.psm1

# PowerShell 7+
Import-Module .\IdentityAuth7.psm1
```

**No setup required!** Just import the .psm1 file.

---

## Documentation

### 📖 [IMPLEMENTATION-PLAN.md](Documentation/IMPLEMENTATION-PLAN.md)
**Comprehensive 9-step implementation plan** with:
- Detailed task breakdowns for each step
- 5-7 week timeline with dependencies
- Success criteria and testing strategies
- Risk mitigation and maintenance plan
- Complete code examples and patterns

### 🏗️ [ARCHITECTURE-DESIGN.md](Documentation/ARCHITECTURE-DESIGN.md)
**Architecture documentation with Mermaid diagrams** including:
- **4 Process Flow Diagrams:**
  - OOBAUTHPIN Authentication Flow
  - OAuth Authentication Flow with Auto-Refresh
  - Standard Challenge Flow (UP/OTP/Push)
  - Token Refresh Logic Flow
- **3 Class Structure Diagrams:**
  - Core Classes (IdentitySession, IdentityAuthResponse, etc.)
  - Enum Definitions (AuthenticationMechanism, ChallengeType, etc.)
  - Private Function Organization
- Module structure and exports
- Session state management (PS7 classes vs PS5.1 hashtables)
- Return value structure and compatibility
- Security architecture with defense-in-depth layers
- API integration details

---

## Quick Start (After Implementation)

### PowerShell 5.1 or 7+
```powershell
# Import module
Import-Module .\IdentityAuth.psm1  # PS 5.1
# OR
Import-Module .\IdentityAuth7.psm1  # PS 7+ (recommended)

# OAuth Authentication (recommended for automation)
$creds = Get-Credential -Message "ClientID (Username) and ClientSecret (Password)"
$token = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://tenant.cyberark.cloud"

# Use with Accounts_Onboard_Utility.ps1
.\Accounts_Onboard_Utility.ps1 -PVWAURL "https://tenant.privilegecloud.cyberark.cloud" -logonToken $token

# Interactive with MFA
$token = Get-IdentityHeader -IdentityUserName "admin@company.com" -PCloudURL "https://tenant.cyberark.cloud" -Verbose

# With OOBAUTHPIN
$token = Get-IdentityHeader -IdentityUserName "admin@company.com" -PCloudURL "https://tenant.cyberark.cloud"
# Follow the displayed URL instructions, complete SAML auth, enter PIN when prompted
```

### Direct REST API Usage
```powershell
$token = Get-IdentityHeader -OAuthCreds $creds -PCloudURL "https://tenant.cyberark.cloud"

# Call any PCloud API
$headers = @{
    Authorization = $token
    'X-IDAP-NATIVE-CLIENT' = 'true'
}
$accounts = Invoke-RestMethod -Uri "https://tenant.privilegecloud.cyberark.cloud/PasswordVault/API/Accounts" -Headers $headers
```

---

## Authentication Methods Supported

| Method | Description | Auto-Refresh | Use Case |
|--------|-------------|--------------|----------|
| **OAuth** | Client ID + Client Secret | ✅ Yes | Automation, scripts, CI/CD |
| **Username/Password (UP)** | Interactive or PSCredential | ❌ Manual re-auth | User sessions |
| **Email OTP** | One-time code via email | ❌ Manual re-auth | MFA with email |
| **SMS OTP** | One-time code via SMS | ❌ Manual re-auth | MFA with phone |
| **Push Notification** | Mobile app approval | ❌ Manual re-auth | MFA with CyberArk app |
| **OOBAUTHPIN** | SAML + PIN code | ❌ Manual re-auth | Federated identity |

---

## Implementation Status

### ✅ Completed
- [x] Implementation plan (9 steps, 5-7 weeks)
- [x] Architecture design with Mermaid diagrams
- [x] Documentation structure
- [x] Requirements gathering
- [x] API flow analysis

### 🚧 In Progress
- [ ] Step 1: Create dual module structure (PS5.1 + PS7)
- [ ] Step 2: Implement OOBAUTHPIN flow
- [ ] Step 3: Modernize OAuth with multi-format credentials
- [ ] Step 4: Replace Write-LogMessage with standard streams
- [ ] Step 5: Comprehensive error handling
- [ ] Step 6: Automatic token refresh
- [ ] Step 7: VS Code tasks and testing infrastructure
- [ ] Step 8: User and developer README documentation
- [ ] Step 9: Final testing and validation

---

## Key Design Decisions

### Return Value: Token String (Not Hashtable)
**Decision:** Return the Bearer token as a plain string  
**Rationale:**
- Matches existing Accounts_Onboard_Utility.ps1 usage: `-logonToken $token`
- Simpler for users: `$token = Get-IdentityHeader ...`
- PCloud-specific (on-prem uses different auth)
- Easy to add to headers: `@{Authorization = $token}`

### Dual Module Approach
**Decision:** Separate modules for PS5.1 and PS7+  
**Rationale:**
- PS7 module uses classes, enums, ternary operators, null-coalescing
- PS5.1 module uses hashtables and traditional logic
- Same functionality, optimized for each version
- Users choose based on their environment

### Session State Management
**Decision:** `$script:CurrentSession` with automatic OAuth refresh  
**Rationale:**
- OAuth can auto-refresh (stored credentials)
- MFA requires manual re-authentication (security)
- Session persists across multiple function calls
- Expiry detection with 60-second warning

### No Write-Host
**Decision:** Zero Write-Host calls, use proper streams  
**Rationale:**
- PSScriptAnalyzer compliance
- PowerShell best practices
- Automation-friendly (Write-Host breaks pipelines)
- Use Write-Output for data, Write-Verbose for details

---

## PowerShell Version Comparison

| Feature | PS 5.1 Module | PS 7+ Module |
|---------|---------------|--------------|
| **Classes** | ✅ Hashtables | ✅ Full classes |
| **Enums** | ✅ Strings | ✅ Typed enums |
| **Ternary Operator** | ❌ if/else | ✅ `$x ? $a : $b` |
| **Null Coalescing** | ❌ Explicit checks | ✅ `$x ?? $default` |
| **Pipeline Chain** | ❌ Separate statements | ✅ `cmd1 && cmd2` |
| **Splatting** | ✅ Yes | ✅ Yes |
| **SecureString** | ✅ DPAPI (Windows) | ✅ Less secure non-Windows |
| **Functionality** | ✅ 100% feature parity | ✅ 100% feature parity |

---

## Security Highlights

🔐 **Credential Handling:**
- PSCredential with SecureString (DPAPI encrypted on Windows)
- No plaintext password storage
- Automatic cleanup in finally blocks (ZeroFreeBSTR)

🔐 **Token Storage:**
- In-memory only (`$script:CurrentSession`)
- Never written to disk
- Script scope isolation (not global)

🔐 **Transport Security:**
- HTTPS only
- TLS 1.2+ required
- Certificate validation (disable only for testing with warning)

🔐 **Logging:**
- Sensitive data masked by default
- Opt-in transcript logging
- No credentials in logs

---

## Contributing

This module is currently in the planning phase. Once implementation begins:

1. Follow [IMPLEMENTATION-PLAN.md](Documentation/IMPLEMENTATION-PLAN.md) for step-by-step guidance
2. All code must pass PSScriptAnalyzer with zero violations
3. Use splatting exclusively (no backticks)
4. Test on both PS5.1 and PS7+
5. Update documentation with any deviations from plan

---

## FAQ

**Q: When will this be ready?**  
A: Estimated 5-7 weeks for full implementation (9 steps)

**Q: Can I use this now?**  
A: No, still in planning phase. Use the current IdentityAuth.psm1 (v1) for production.

**Q: Will this break existing scripts?**  
A: Return value changes from hashtable to string. Migration path documented in implementation plan.

**Q: Why two modules (PS5.1 and PS7)?**  
A: Maximum compatibility (PS5.1) + maximum modern features (PS7 classes/enums). Choose based on your environment.

**Q: What about on-premises PVWA?**  
A: This module is for **Privilege Cloud only** (Identity authentication). On-prem uses CyberArk Authentication, not Identity.

**Q: Why remove psPAS support?**  
A: Simplifies the module. Direct API calls or psPAS module can still be used, just needs manual header construction: `@{Authorization = $token}`.

---

## Contact

Questions or feedback during implementation? Open an issue in the epv-api-scripts repository.

---

**Last Updated:** 2026-01-28  
**Version:** 2.0.0-planning
