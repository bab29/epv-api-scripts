#Requires -Version 5.1
<parameter name="content">#Requires -Version 5.1
<#
.SYNOPSIS
    Performance measurement for authentication methods

.DESCRIPTION
    Benchmarks different authentication methods and token caching performance.
#>

function Measure-AuthenticationPerformance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCredential]$OAuthCreds,
        
        [Parameter(Mandatory)]
        [string]$PCloudURL,
        
        [Parameter()]
        [int]$Iterations = 10
    )
    
    Write-Host @"
================================================================================
Authentication Performance Benchmark
================================================================================

Testing: OAuth authentication with token caching
Iterations: $Iterations
PCloud URL: $PCloudURL

"@
    
    # Clear any cached tokens
    $null = Get-IdentityHeader -OAuthCreds $OAuthCreds -PCloudURL $PCloudURL -Force
    
    $results = @{
        FirstCall = $null
        CachedCalls = @()
        ForcedRefresh = @()
    }
    
    # Measure first call (no cache)
    Write-Host "Measuring first authentication (no cache)..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $null = Get-IdentityHeader -OAuthCreds $OAuthCreds -PCloudURL $PCloudURL -Force
    $sw.Stop()
    $results.FirstCall = $sw.ElapsedMilliseconds
    Write-Host "  First call: $($sw.ElapsedMilliseconds)ms" -ForegroundColor Cyan
    
    # Measure cached calls
    Write-Host "`nMeasuring cached authentication calls..."
    for ($i = 1; $i -le $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Get-IdentityHeader -OAuthCreds $OAuthCreds -PCloudURL $PCloudURL
        $sw.Stop()
        $results.CachedCalls += $sw.ElapsedMilliseconds
        Write-Host "  Cached call $i : $($sw.ElapsedMilliseconds)ms"
    }
    
    # Measure forced refresh
    Write-Host "`nMeasuring forced token refresh..."
    for ($i = 1; $i -le 3; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Get-IdentityHeader -OAuthCreds $OAuthCreds -PCloudURL $PCloudURL -Force
        $sw.Stop()
        $results.ForcedRefresh += $sw.ElapsedMilliseconds
        Write-Host "  Forced refresh $i : $($sw.ElapsedMilliseconds)ms"
    }
    
    # Calculate statistics
    $avgCached = ($results.CachedCalls | Measure-Object -Average).Average
    $minCached = ($results.CachedCalls | Measure-Object -Minimum).Minimum
    $maxCached = ($results.CachedCalls | Measure-Object -Maximum).Maximum
    
    $avgForced = ($results.ForcedRefresh | Measure-Object -Average).Average
    
    $speedup = [math]::Round($results.FirstCall / $avgCached, 2)
    
    Write-Host @"

================================================================================
Performance Summary
================================================================================

First Authentication: $($results.FirstCall)ms
Cached Authentication: $([math]::Round($avgCached, 2))ms (avg)
  - Minimum: $minCached ms
  - Maximum: $maxCached ms
  - Speedup: ${speedup}x faster

Forced Refresh: $([math]::Round($avgForced, 2))ms (avg)

Cache Effectiveness:
  Cache Hit Rate: 100% (after first call)
  Performance Gain: $([math]::Round((1 - $avgCached/$results.FirstCall) * 100, 1))% faster

Recommendations:
  - Use cached tokens for batch operations
  - Force refresh only when necessary
  - Token valid for ~1 hour (auto-refresh at 55 minutes)

================================================================================

"@
    
    return $results
}

# Export function
Export-ModuleMember -Function Measure-AuthenticationPerformance
