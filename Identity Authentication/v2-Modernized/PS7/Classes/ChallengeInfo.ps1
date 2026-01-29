#Requires -Version 7.0
<#
.SYNOPSIS
    Challenge information class

.DESCRIPTION
    Represents an authentication challenge with multiple mechanism options
#>

class ChallengeInfo {
    [string]$ChallengeId
    [array]$Mechanisms
    [string]$Type
    [hashtable]$Metadata = @{}

    # Constructor
    ChallengeInfo([PSCustomObject]$Challenge) {
        $this.ChallengeId = $Challenge.ChallengeId ?? [guid]::NewGuid().ToString()
        $this.Mechanisms = $Challenge.Mechanisms ?? @()
        $this.Type = $Challenge.Type ?? 'Unknown'
    }

    # Get mechanism by name
    [PSCustomObject] GetMechanismByName([string]$Name) {
        return $this.Mechanisms | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    }

    # Check if challenge has multiple mechanisms
    [bool] HasMultipleMechanisms() {
        return $this.Mechanisms.Count -gt 1
    }
}
