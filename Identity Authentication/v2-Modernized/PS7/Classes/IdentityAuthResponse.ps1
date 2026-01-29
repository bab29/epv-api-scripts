#Requires -Version 7.0
<#
.SYNOPSIS
    Identity authentication response class

.DESCRIPTION
    Represents a response from Identity authentication APIs
#>

class IdentityAuthResponse {
    [bool]$Success
    [string]$Message
    [PSCustomObject]$Result
    [hashtable]$ErrorInfo
    [int]$StatusCode
    [datetime]$Timestamp = [datetime]::Now

    # Constructor
    IdentityAuthResponse([PSCustomObject]$ApiResponse) {
        $this.Success = $ApiResponse.success ?? $false
        $this.Message = $ApiResponse.Message ?? ''
        $this.Result = $ApiResponse.Result
        $this.ErrorInfo = @{}
        $this.StatusCode = 200
    }

    # Extract token from response
    [string] ToToken() {
        if ($this.Success -and $this.Result.Token) {
            return $this.Result.Token
        }
        return $null
    }

    # Check if response contains challenges
    [bool] HasChallenges() {
        return $null -ne $this.Result.Challenges -and $this.Result.Challenges.Count -gt 0
    }
}
