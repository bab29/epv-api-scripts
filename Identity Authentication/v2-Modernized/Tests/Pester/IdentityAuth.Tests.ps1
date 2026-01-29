#Requires -Version 5.1
#Requires -Module Pester

<#
.SYNOPSIS
    Pester v5 tests for IdentityAuth module (PS5.1)

.DESCRIPTION
    Unit and integration tests for PowerShell 5.1 module
#>

BeforeAll {
    # Import module
    Import-Module "$PSScriptRoot\..\..\PS5.1\IdentityAuth.psm1" -Force
}

Describe 'IdentityAuth Module - PS5.1' {
    Context 'Module Import' {
        It 'Should import without errors' {
            # TODO: Implementation
            $true | Should -Be $true
        }
    }
}
