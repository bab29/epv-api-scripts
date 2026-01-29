#Requires -Version 5.1
<#
.SYNOPSIS
    Finds authentication mechanism by type

.DESCRIPTION
    Searches challenge mechanisms for specific answer type.
    Supports UP (Username/Password), Text (OTP), StartTextOob (Push/PIN).
#>

function Get-AuthenticationMechanism {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Challenges,

        [Parameter(Mandatory)]
        [ValidateSet('UP', 'Text', 'StartTextOob', 'StartOob')]
        [string]$AnswerType
    )

    Write-Verbose "Searching for mechanism with AnswerType: $AnswerType"

    foreach ($challenge in $Challenges) {
        foreach ($mechanism in $challenge.Mechanisms) {
            if ($mechanism.AnswerType -eq $AnswerType) {
                Write-Verbose "Found mechanism: $($mechanism.Name) (MechanismId: $($mechanism.MechanismId))"
                return $mechanism
            }
        }
    }

    $availableTypes = $Challenges.Mechanisms.AnswerType | Select-Object -Unique
    throw "Mechanism with AnswerType '$AnswerType' not found. Available: $($availableTypes -join ', ')"
}
