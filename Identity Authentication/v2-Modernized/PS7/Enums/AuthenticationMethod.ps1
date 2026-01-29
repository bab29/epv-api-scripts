#Requires -Version 7.0
<#
.SYNOPSIS
    Authentication method enumeration

.DESCRIPTION
    Defines supported authentication methods for CyberArk Identity.
#>

enum AuthenticationMethod {
    OAuth
    OOBAUTHPIN
    UsernamePassword
    EmailOTP
    SMSOTP
    Push
}
