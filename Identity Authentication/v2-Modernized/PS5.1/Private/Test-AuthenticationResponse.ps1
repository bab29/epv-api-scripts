#Requires -Version 5.1
<#
.SYNOPSIS
    Validates authentication response from Identity

.DESCRIPTION
    Checks if authentication response is valid and contains required fields.
    Provides detailed error messages for troubleshooting.
#>

function Test-AuthenticationResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Response,

        [Parameter(Mandatory)]
        [string]$AuthMethod
    )

    Write-IdentityLog -Message "Validating $AuthMethod response" -Level Verbose

    # Check if response is null
    if ($null -eq $Response) {
        $errorRecord = New-IdentityErrorRecord `
            -Message "$AuthMethod returned null response" `
            -ErrorId 'NullAuthResponse' `
            -Category InvalidResult `
            -RecommendedAction "Check network connectivity and Identity service status"
        throw $errorRecord
    }

    # Check for success field
    if ($Response.PSObject.Properties['success']) {
        if (-not $Response.success) {
            $message = if ($Response.Message) { $Response.Message } else { "Authentication failed" }

            $errorRecord = New-IdentityErrorRecord `
                -Message "$AuthMethod failed: $message" `
                -ErrorId 'AuthenticationFailed' `
                -Category AuthenticationError `
                -RecommendedAction "Verify credentials and user permissions"
            throw $errorRecord
        }
    }

    # Check for auth token (for completed auth)
    if ($Response.PSObject.Properties['Result']) {
        if ($Response.Result.PSObject.Properties['Auth']) {
            if (-not $Response.Result.Auth) {
                $errorRecord = New-IdentityErrorRecord `
                    -Message "$AuthMethod completed but no authentication token returned" `
                    -ErrorId 'NoAuthToken' `
                    -Category InvalidResult `
                    -RecommendedAction "This may require additional authentication steps"
                throw $errorRecord
            }
        }
    }

    Write-IdentityLog -Message "$AuthMethod response validated successfully" -Level Verbose
    return $true
}
