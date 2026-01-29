#Requires -Version 5.1
<#
.SYNOPSIS
    Clears current Identity session

.DESCRIPTION
    Clears the current session from memory and optionally calls logout endpoint
    to invalidate token on server.

.PARAMETER NoLogout
    Skip calling logout endpoint (only clear local session)

.EXAMPLE
    Clear-IdentitySession

.EXAMPLE
    Clear-IdentitySession -NoLogout

.NOTES
    Public function - Exported
#>
function Clear-IdentitySession {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$NoLogout
    )

    # TODO: Implementation
    throw "Not yet implemented"
}
