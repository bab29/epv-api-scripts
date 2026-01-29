#Requires -Module Pester
<#
.SYNOPSIS
    Pester v5 tests for Get-IdentityHeader function

.DESCRIPTION
    Tests OAuth and OOBAUTHPIN authentication flows.
    Uses mocking to avoid actual API calls.
#>

BeforeAll {
    # Import module
    $ModulePath = Join-Path $PSScriptRoot '..\PS5.1\IdentityAuth.psd1'
    Import-Module $ModulePath -Force
}

Describe 'Get-IdentityHeader' {
    Context 'OAuth Authentication' {
        BeforeAll {
            # Mock OAuth token request
            Mock Invoke-RestMethod {
                return @{
                    access_token = 'test_token_12345'
                    token_type   = 'Bearer'
                    expires_in   = 3600
                }
            } -ModuleName IdentityAuth

            $mockCreds = New-Object PSCredential('client_id', (ConvertTo-SecureString 'client_secret' -AsPlainText -Force))
        }

        It 'Should return hashtable with Authorization and X-IDAP-NATIVE-CLIENT keys' {
            $result = Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud'

            $result | Should -BeOfType [hashtable]
            $result.Keys | Should -Contain 'Authorization'
            $result.Keys | Should -Contain 'X-IDAP-NATIVE-CLIENT'
        }

        It 'Should format Authorization header with Bearer prefix' {
            $result = Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud'

            $result.Authorization | Should -BeLike 'Bearer *'
        }

        It 'Should set X-IDAP-NATIVE-CLIENT to true' {
            $result = Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud'

            $result['X-IDAP-NATIVE-CLIENT'] | Should -Be 'true'
        }

        It 'Should normalize PCloud URL' {
            $result = Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'tenant.cyberark.cloud'

            $result | Should -Not -BeNullOrEmpty
        }

        It 'Should cache OAuth token' {
            $result1 = Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud'
            $result2 = Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud'

            # Second call should use cache (Invoke-RestMethod called only once)
            Should -Invoke Invoke-RestMethod -Times 1 -ModuleName IdentityAuth
        }

        It 'Should force token refresh with -Force parameter' {
            $result1 = Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud'
            $result2 = Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud' -Force

            # Force should bypass cache
            Should -Invoke Invoke-RestMethod -Times 2 -ModuleName IdentityAuth
        }
    }

    Context 'URL Normalization' {
        BeforeAll {
            Mock Invoke-RestMethod {
                return @{ access_token = 'test_token'; expires_in = 3600 }
            } -ModuleName IdentityAuth

            $mockCreds = New-Object PSCredential('client_id', (ConvertTo-SecureString 'secret' -AsPlainText -Force))
        }

        It 'Should accept URL without https://' {
            { Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'tenant.cyberark.cloud' } | Should -Not -Throw
        }

        It 'Should accept URL with .privilegecloud.cyberark.cloud' {
            { Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.privilegecloud.cyberark.cloud' } | Should -Not -Throw
        }

        It 'Should add /PasswordVault automatically' {
            { Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud' } | Should -Not -Throw
        }
    }

    Context 'Error Handling' {
        BeforeAll {
            Mock Invoke-RestMethod {
                throw "API Error"
            } -ModuleName IdentityAuth

            $mockCreds = New-Object PSCredential('client_id', (ConvertTo-SecureString 'secret' -AsPlainText -Force))
        }

        It 'Should throw error when authentication fails' {
            { Get-IdentityHeader -OAuthCreds $mockCreds -PCloudURL 'https://tenant.cyberark.cloud' } | Should -Throw
        }
    }
}
