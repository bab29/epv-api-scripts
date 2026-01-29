#Requires -Version 7.0
<#
.SYNOPSIS
    Authentication mechanism enumeration

.DESCRIPTION
    Defines supported authentication mechanisms for CyberArk Identity
#>

enum AuthenticationMechanism {
    UP = 1                      # Username/Password
    OAuth = 2                   # OAuth client credentials
    EmailOTP = 3                # Email one-time password
    SMSOTP = 4                  # SMS one-time password
    PushNotification = 5        # Push notification to device
    SAML_Deprecated = 6         # Legacy SAML (deprecated)
    OOBAUTHPIN = 7              # Out-of-band authentication PIN
    PhoneCall = 8               # Phone call verification
    SecurityQuestions = 9       # Security questions
}
