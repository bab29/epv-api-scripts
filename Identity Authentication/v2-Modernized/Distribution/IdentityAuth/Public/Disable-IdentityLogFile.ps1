#Requires -Version 5.1
<#
.SYNOPSIS
    Disable file logging for IdentityAuth module

.DESCRIPTION
    Turns off file logging. Authentication operations will no longer write to log file.

.EXAMPLE
    Disable-IdentityLogFile

.NOTES
    Use Set-IdentityLogFile to enable logging again.
#>

function Disable-IdentityLogFile {
    [CmdletBinding()]
    param()

    $script:LogToFile = $false
    $script:LogFile = $null
    Write-Verbose "File logging disabled"
}

Export-ModuleMember -Function Disable-IdentityLogFile
