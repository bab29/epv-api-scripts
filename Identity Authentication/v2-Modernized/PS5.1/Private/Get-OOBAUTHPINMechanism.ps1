#Requires -Version 5.1
<#
.SYNOPSIS
    Finds OOBAUTHPIN mechanism from challenge list

.DESCRIPTION
    Searches authentication challenges for OOBAUTHPIN mechanism.
    OOBAUTHPIN sends a PIN via SMS/Email that user must provide.
#>

function Get-OOBAUTHPINMechanism {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Challenges
    )

    Write-Verbose "Searching for OOBAUTHPIN mechanism in challenges"

    foreach ($challenge in $Challenges) {
        foreach ($mechanism in $challenge.Mechanisms) {
            if ($mechanism.AnswerType -eq 'StartTextOob' -and $mechanism.PromptSelectMech -match 'OOBAUTHPIN') {
                Write-Verbose "Found OOBAUTHPIN mechanism: $($mechanism.MechanismId)"
                return $mechanism
            }
        }
    }

    throw "OOBAUTHPIN mechanism not available for this user. Available mechanisms: $($Challenges.Mechanisms.AnswerType -join ', ')"
}
