#Requires -Version 5.1
@{
    # Module manifest for IdentityAuth (PowerShell 5.1)
    RootModule = 'IdentityAuth.psm1'
    ModuleVersion = '2.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'CyberArk'
    CompanyName = 'CyberArk Software Ltd.'
    Copyright = '(c) 2026 CyberArk Software Ltd. All rights reserved.'
    Description = 'CyberArk Identity Authentication Module for Privilege Cloud (PowerShell 5.1)'
    PowerShellVersion = '5.1'

    # Functions to export
    FunctionsToExport = @('Get-IdentityHeader', 'Set-IdentityLogFile', 'Disable-IdentityLogFile')

    # Cmdlets to export
    CmdletsToExport = @()

    # Variables to export
    VariablesToExport = @()

    # Aliases to export
    AliasesToExport = @()

    # Private data
    PrivateData = @{
        PSData = @{
            Tags = @('CyberArk', 'Identity', 'Authentication', 'PrivilegeCloud', 'OAuth', 'MFA')
            LicenseUri = 'https://github.com/cyberark/epv-api-scripts/blob/main/LICENSE'
            ProjectUri = 'https://github.com/cyberark/epv-api-scripts'
            ReleaseNotes = 'v2.0.0: Complete rewrite with OOBAUTHPIN support, OAuth token refresh, dual PS5.1/PS7 versions'
        }
    }
}
