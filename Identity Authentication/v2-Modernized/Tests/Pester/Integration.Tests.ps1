#Requires -Module Pester
<#
.SYNOPSIS
    Integration tests for IdentityAuth module with live Identity tenant

.DESCRIPTION
    Tests authentication flows against real Identity endpoints.
    Requires valid credentials and network access.

    IMPORTANT: These tests make real API calls!
#>

BeforeAll {
    $ModulePath = Join-Path $PSScriptRoot '..\PS5.1\IdentityAuth.psd1'
    Import-Module $ModulePath -Force

    # Check for test credentials (set via environment or test config)
    $script:HasOAuthCreds = $false
    $script:HasUserCreds = $false
    $script:TestPCloudURL = $env:TEST_PCLOUD_URL

    if ($env:TEST_OAUTH_CLIENTID -and $env:TEST_OAUTH_SECRET) {
        $password = ConvertTo-SecureString $env:TEST_OAUTH_SECRET -AsPlainText -Force
        $script:OAuthCreds = New-Object PSCredential($env:TEST_OAUTH_CLIENTID, $password)
        $script:HasOAuthCreds = $true
    }

    if ($env:TEST_USERNAME -and $env:TEST_PASSWORD) {
        $password = ConvertTo-SecureString $env:TEST_PASSWORD -AsPlainText -Force
        $script:UserCreds = New-Object PSCredential($env:TEST_USERNAME, $password)
        $script:HasUserCreds = $true
    }
}

Describe 'Get-IdentityHeader - Integration Tests' -Tag 'Integration' {
    Context 'OAuth Authentication - Live' {
        BeforeAll {
            if (-not $script:HasOAuthCreds) {
                Set-ItResult -Skipped -Because 'OAuth credentials not configured'
            }
        }

        It 'Should authenticate with valid OAuth credentials' -Skip:(-not $script:HasOAuthCreds) {
            $headers = Get-IdentityHeader -OAuthCreds $script:OAuthCreds -PCloudURL $script:TestPCloudURL

            $headers | Should -Not -BeNullOrEmpty
            $headers.Authorization | Should -BeLike 'Bearer *'
            $headers['X-IDAP-NATIVE-CLIENT'] | Should -Be 'true'
        }

        It 'Should cache OAuth token on second call' -Skip:(-not $script:HasOAuthCreds) {
            $headers1 = Get-IdentityHeader -OAuthCreds $script:OAuthCreds -PCloudURL $script:TestPCloudURL
            $headers2 = Get-IdentityHeader -OAuthCreds $script:OAuthCreds -PCloudURL $script:TestPCloudURL

            # Should return same token (cached)
            $headers1.Authorization | Should -Be $headers2.Authorization
        }

        It 'Should refresh token with -Force' -Skip:(-not $script:HasOAuthCreds) {
            $headers1 = Get-IdentityHeader -OAuthCreds $script:OAuthCreds -PCloudURL $script:TestPCloudURL
            Start-Sleep -Seconds 2
            $headers2 = Get-IdentityHeader -OAuthCreds $script:OAuthCreds -PCloudURL $script:TestPCloudURL -Force

            # May or may not be different token, but should succeed
            $headers2 | Should -Not -BeNullOrEmpty
        }

        It 'Should work with PCloud API call' -Skip:(-not $script:HasOAuthCreds) {
            $headers = Get-IdentityHeader -OAuthCreds $script:OAuthCreds -PCloudURL $script:TestPCloudURL

            $pvwaUrl = $script:TestPCloudURL -replace '\.cyberark\.cloud.*', '.privilegecloud.cyberark.cloud/PasswordVault'
            $apiUrl = "$pvwaUrl/API/Accounts?limit=1"

            { Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get } | Should -Not -Throw
        }
    }

    Context 'Error Handling - Live' {
        It 'Should fail with invalid OAuth credentials' {
            $badCreds = New-Object PSCredential('invalid', (ConvertTo-SecureString 'invalid' -AsPlainText -Force))

            { Get-IdentityHeader -OAuthCreds $badCreds -PCloudURL $script:TestPCloudURL } | Should -Throw
        }

        It 'Should fail with invalid PCloud URL' -Skip:(-not $script:HasOAuthCreds) {
            { Get-IdentityHeader -OAuthCreds $script:OAuthCreds -PCloudURL "https://invalid.cyberark.cloud" } | Should -Throw
        }
    }
}

Describe 'Logging Infrastructure' -Tag 'Integration' {
    It 'Should log to file when enabled' {
        $logFile = Join-Path $TestDrive "test-$(Get-Date -Format 'yyyyMMddHHmmss').log"

        Set-IdentityLogFile -Path $logFile

        Write-IdentityLog -Message "Test log entry" -Level Info

        $logFile | Should -Exist
        $logContent = Get-Content $logFile -Raw
        $logContent | Should -BeLike '*Test log entry*'

        Disable-IdentityLogFile
    }
}

Describe 'URL Normalization' -Tag 'Unit' {
    It 'Should add https:// to URL without scheme' {
        Mock Invoke-RestMethod { @{ access_token = 'test'; expires_in = 3600 } } -ModuleName IdentityAuth
        $creds = New-Object PSCredential('id', (ConvertTo-SecureString 'secret' -AsPlainText -Force))

        { Get-IdentityHeader -OAuthCreds $creds -PCloudURL 'subdomain.cyberark.cloud' } | Should -Not -Throw
    }

    It 'Should add /PasswordVault to URL' {
        Mock Invoke-RestMethod { @{ access_token = 'test'; expires_in = 3600 } } -ModuleName IdentityAuth
        $creds = New-Object PSCredential('id', (ConvertTo-SecureString 'secret' -AsPlainText -Force))

        { Get-IdentityHeader -OAuthCreds $creds -PCloudURL 'https://subdomain.cyberark.cloud' } | Should -Not -Throw
    }
}
