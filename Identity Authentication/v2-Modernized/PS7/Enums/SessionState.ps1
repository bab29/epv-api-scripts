#Requires -Version 7.0
<#
.SYNOPSIS
    Session state enumeration

.DESCRIPTION
    Defines possible states of an Identity authentication session
#>

enum SessionState {
    NotAuthenticated = 0        # No active session
    Authenticating = 1          # Authentication in progress
    Authenticated = 2           # Successfully authenticated
    Expired = 3                 # Token expired
    RefreshRequired = 4         # Token needs refresh
    Invalid = 5                 # Session is invalid
}
