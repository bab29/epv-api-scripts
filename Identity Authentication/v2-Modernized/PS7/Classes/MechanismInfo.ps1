#Requires -Version 7.0
<#
.SYNOPSIS
    Mechanism information class

.DESCRIPTION
    Represents a single authentication mechanism option
#>

class MechanismInfo {
    [string]$MechanismId
    [string]$Name
    [string]$AnswerType
    [string]$PromptMechChosen
    [hashtable]$Properties = @{}

    # Constructor
    MechanismInfo([PSCustomObject]$Mechanism) {
        $this.MechanismId = $Mechanism.MechanismId
        $this.Name = $Mechanism.Name
        $this.AnswerType = $Mechanism.AnswerType
        $this.PromptMechChosen = $Mechanism.PromptMechChosen ?? $Mechanism.PromptSelectMech
    }

    # Check if mechanism requires user input
    [bool] RequiresUserInput() {
        return $this.AnswerType -eq 'Text'
    }

    # Check if mechanism is out-of-band (push notification)
    [bool] IsOOB() {
        return $this.AnswerType -like '*Oob*'
    }
}
