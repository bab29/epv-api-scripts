#Requires -Version 7.0
<#
.SYNOPSIS
    Mechanism type enumeration

.DESCRIPTION
    Defines specific mechanism types returned by Identity API
#>

enum MechanismType {
    UP = 1                      # Username/Password
    OTP = 2                     # One-time password
    EMAIL = 3                   # Email verification
    SMS = 4                     # SMS verification
    PF = 5                      # Push notification (PushFactor)
    OATH = 6                    # OATH token
    RADIUS = 7                  # RADIUS authentication
    SQ = 8                      # Security questions
    SAML = 9                    # SAML
}
