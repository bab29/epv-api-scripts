#Requires -Version 5.1

@{
    # Enable all rules by default
    IncludeDefaultRules = $true
    
    # Severity levels to check
    Severity = @('Error', 'Warning', 'Information')
    
    # Rules to exclude (none - we want zero violations!)
    ExcludeRules = @()
    
    # Custom rule paths (none for now)
    CustomRulePath = @()
    
    # Rules configuration
    Rules = @{
        # Require proper use of PSCredential
        PSAvoidUsingConvertToSecureStringWithPlainText = @{
            Enable = $true
        }
        
        # Require proper cmdlet naming
        PSUseApprovedVerbs = @{
            Enable = $true
        }
        
        # Require proper use of Write-* cmdlets
        PSAvoidUsingWriteHost = @{
            Enable = $true
        }
        
        # Require proper comment-based help
        PSProvideCommentHelp = @{
            Enable = $true
            ExportedOnly = $true
            BlockComment = $true
            VSCodeSnippetCorrection = $true
            Placement = 'before'
        }
        
        # UTF-8 with BOM encoding required
        PSUseUTF8EncodingForHelpFile = @{
            Enable = $true
        }
        
        # Use ShouldProcess for system-changing functions
        PSUseShouldProcessForStateChangingFunctions = @{
            Enable = $true
        }
        
        # Proper error handling
        PSAvoidUsingPositionalParameters = @{
            Enable = $true
        }
        
        # Place $null on left side of comparisons
        PSPossibleIncorrectComparisonWithNull = @{
            Enable = $true
        }
        
        # Use full cmdlet names (no aliases)
        PSAvoidUsingCmdletAliases = @{
            Enable = $true
        }
        
        # Avoid unnecessary global variables
        PSAvoidGlobalVars = @{
            Enable = $true
        }
        
        # Proper parameter validation
        PSUseDeclaredVarsMoreThanAssignments = @{
            Enable = $true
        }
    }
}
