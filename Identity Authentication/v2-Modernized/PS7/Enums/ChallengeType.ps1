#Requires -Version 7.0
<#
.SYNOPSIS
    Challenge type enumeration

.DESCRIPTION
    Defines types of authentication challenges from Identity API
#>

enum ChallengeType {
    Text = 1                    # Text-based answer (password, OTP, etc.)
    StartTextOob = 2            # Start text-based out-of-band (push notification)
    StartOob = 3                # Start out-of-band authentication
    Poll = 4                    # Poll for OOB completion
    Answer = 5                  # Submit answer to challenge
    SAML = 6                    # SAML redirect
}
