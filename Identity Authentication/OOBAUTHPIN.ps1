Function Get-IdentityURL($idURL) {
    Add-Type -AssemblyName System.Net.Http

    Function CreateHttpClient($allowAutoRedirect) {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $allowAutoRedirect
        return New-Object System.Net.Http.HttpClient($handler)
    }

    $client = CreateHttpClient($true)

    try {
        $task = $client.GetAsync($idURL)
        $task.Wait()  # Ensures the task completes and exceptions are thrown if any.

        if ($task.IsCompleted) {
            $response = $task.Result

            if (($response.StatusCode -ge 300 -and $response.StatusCode -lt 400) -or ($response.StatusCode -eq "OK")) {
                return $response.RequestMessage.RequestUri.Host
            } else {
                return "Unexpected status code: $($response.StatusCode)"
            }
        } else {
            return "Task did not complete successfully."
        }
    }
    catch {
        # Extracting detailed exception message from AggregateException
        $exception = $_.Exception
        while ($exception.InnerException) {
            $exception = $exception.InnerException
        }

        # Return the extracted exception message
        return "Error: $($exception.Message)"
    }
    finally {
        if ($client -ne $null) {
            $client.Dispose()
        }
    }
}




# PlatformParams
$PlatformTenantId = "saascorpslndn" # <<<----- Put your subdomain here.
$BasePlatformURL = "https://$PlatformTenantId.cyberark.cloud"
$BasePlatformURLPVWA = "https://$PlatformTenantId.privilegecloud.cyberark.cloud"

#Platform Identity API
$IdentityBaseURL = Get-IdentityURL -idURL $BasePlatformURL
$IdentityTenantId = $IdentityBaseURL.Split(".")[0]
$IdaptiveBasePlatformURL = "https://$IdentityBaseURL"
$IdaptiveBasePlatformSecURL = "$IdaptiveBasePlatformURL/Security"
$startPlatformAPIAuth = "$IdaptiveBasePlatformSecURL/StartAuthentication"
$startPlatformAPIAdvancedAuth = "$IdaptiveBasePlatformSecURL/AdvanceAuthentication"
$LogoffPlatform = "$IdaptiveBasePlatformSecURL/logout"
$creds = Get-Credential


$Headers = @{
    "Content-Type" = "application/json"
    "X-IDAP-NATIVE-CLIENT" = "true"
    OobIdPAuth = "true"
}

#Begin Start Authentication Process
$startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = $creds.UserName ; Version = "1.0"} | ConvertTo-Json -Compress
$IdaptiveResponse = Invoke-RestMethod -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 30 -Headers $Headers -SessionVariable WebSession
$IdaptiveResponse.Result


$IdpRedirectShortUrl = $IdaptiveResponse.Result.IdpRedirectShortUrl
$sessionID = $IdaptiveResponse.Result.SessionId
$IdpLoginSesssionID = $IdaptiveResponse.Result.IdpLoginSessionId
$IdpRedirectShortUrl
$sessionID
$IdpLoginSesssionID

if($null -eq $IdpRedirectShortUrl)
{
    Write-host "URL redirect from Identity is empty, nothing to browse to...exiting."
    break
}Else{
    $Chrome = Start-Process $IdpRedirectShortUrl
}

do {
    $inputValue = Read-Host -Prompt "Please provide PIN Code"

    # Trim spaces
    $inputValue = $inputValue.Trim()

    # Check if numeric only
    if ($inputValue -match '^\d+$') {
        $pinCode = $inputValue
        $valid = $true
    }
    else {
        Write-Host "Invalid input. Please enter numbers only." -ForegroundColor Red
        $valid = $false
    }
}
until ($valid)

Write-Host "Your PIN code is $pinCode"

$pinBodyReply = @{ TenantId = $IdentityTenantId; SessionId = $IdpLoginSesssionID; MechanismId = "OOBAUTHPIN"; Action = "Answer" ; Answer = "$pinCode" } | ConvertTo-Json -Depth 2 -Compress
$pinResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $pinBodyReply -TimeoutSec 30
$pinResponse.Result

$IdentityHeaders = @{Authorization  = "Bearer $($pinResponse.Result.Token)"}
$IdentityHeaders.Add("X-IDAP-NATIVE-CLIENT","true")


Invoke-RestMethod -Uri "$IdaptiveBasePlatformSecURL/WhoAmI" -Method Post -ContentType "application/json" -Headers $IdentityHeaders
