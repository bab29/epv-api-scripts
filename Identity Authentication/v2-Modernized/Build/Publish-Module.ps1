#Requires -Version 5.1

<#
.SYNOPSIS
    Publish module to PowerShell Gallery

.DESCRIPTION
    Publishes built modules to PowerShell Gallery with API key.

.PARAMETER ApiKey
    PowerShell Gallery API key

.EXAMPLE
    .\Publish-Module.ps1 -ApiKey $apiKey
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ApiKey
)

# TODO: Implementation
throw "Not yet implemented"
