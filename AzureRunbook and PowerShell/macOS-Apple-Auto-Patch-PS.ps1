# PowerShell Script for macOS Update Deployment via Jamf Pro API
# Designed for use in an Azure Runbook

####################################################################################################
#
# Jamf DDM Sofa Processor (Apple Auto Patch)
#
####################################################################################################
#
# HISTORY
#
#   04.17.2025, @robjschroeder
#       - Initial version
#       - Script to process macOS updates from SOFA feed and create update plans in Jamf Pro
#       - Based on bash version of script, this will be ran from an Azure Runbook for automation. 
#
####################################################################################################

####################################################################################################
#
# Global Variables
#
####################################################################################################

$DebugPreference = "Continue"
#$VerbosePreference = "Continue"

$organisationScriptName = "Apple Auto Patch - macOS"
$scriptVersion = "1.0.0"
$scriptDate = "2025-04-17"

# Jamf Pro API Variables
$global:jamfProInformation = @{
    client_id = "04d89e21-5b7a-4d2f-8f3d-9c2f3eaf34a1"
    client_secret = "s2ryjkgiqlt34cLs4oIX_NOJRIjzO89wCwbUvRM8HXU"
    URI = 'https://rschroeder.jamfcloud.com'
}

# NVD API Variables
$global:nvdInformation = @{
    URI = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    apiKey = "2c72b83c-2ffc-42c6-85ac-4db7561761f4"
}

# Jamf Pro Smart Group IDs and SWU Deferral Days
$global:jamfProSmartGroupIDs = @{
    "AlphaGroup" = 315
    "BetaGroup" = 235
    "GammaGroup" = 326
    "ReleaseGroup" = 203
}

$global:jamfProSWUDeferralDays = @{
    "AlphaGroupDeferralDays" = 0
    "BetaGroupDeferralDays" = 3
    "GammaGroupDeferralDays" = 5
    "ReleaseGroupDeferralDays" = 10
}

$global:jamfProGroupVersionTypeOverrides = @{
    "AlphaGroup" = "LATEST_ANY"
    "BetaGroup" = "LATEST_ANY"
    "GammaGroup" = "LATEST_ANY"
    # Add more overrides as needed
}

# Software Update Variables
$updateAction = "DOWNLOAD_INSTALL_SCHEDULE"
$versionType = "LATEST_MINOR"

# SOFA Feed Variables
$global:sofaFeedInformation = @{
    URI = 'https://sofafeed.macadmins.io/v1/macos_data_feed.json'
}

####################################################################################################
#
# Functions
#
####################################################################################################

# Write Log Info
# Main logging function
# Global log level (set to "DEBUG", "INFO", "WARNING", "ERROR", or "VERBOSE")
$global:LogLevel = "DEBUG"
function Write-Log {
    param (
        [string]$Message,
        [string]$Level
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"

    # Determine if the message should be logged based on the global log level
    $logLevels = @("DEBUG", "INFO", "WARNING", "ERROR", "VERBOSE")
    if ($logLevels.IndexOf($Level) -ge $logLevels.IndexOf($global:LogLevel)) {
        # Write to console with color coding
        switch ($Level) {
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
            "INFO" { Write-Host $logEntry -ForegroundColor Green }
            "DEBUG" { Write-Host $logEntry -ForegroundColor Cyan }
            "VERBOSE" { Write-Host $logEntry -ForegroundColor Magenta }
            default { Write-Host $logEntry }
        }

        # Write to log file if enabled
        if ($global:LogFilePath) {
            Add-Content -Path $global:LogFilePath -Value $logEntry
        }
    }
}

# Write Log Info
function Write-Log-Info {
    param (
        [string]$Message
    )
    Write-Log -Message $Message -Level "INFO"
}

# Write Log Warning
function Write-Log-Warning {
    param (
        [string]$Message
    )
    Write-Log -Message $Message -Level "WARNING"
}

# Write Log Error
function Write-Log-Error {
    param (
        [string]$Message
    )
    Write-Log -Message $Message -Level "ERROR"
}

# Write Log Debug
function Write-Log-Debug {
    param (
        [string]$Message
    )
    Write-Log -Message $Message -Level "DEBUG"
}
# Write Log Verbose
function Write-Log-Verbose {
    param (
        [string]$Message
    )
    Write-Log -Message $Message -Level "VERBOSE"
}

# Get a bearer token for Jamf Pro API authentication
function Get-BearerToken {
    $global:bearerTokenInformation = @{}
    $bearerTokenAuthHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded" }
    $bodyContent = @{
        client_id = $jamfProInformation['client_id']
        client_secret = $jamfProInformation['client_secret']
        grant_type = "client_credentials"
    }
    try {
        $bearerTokenAuthResponse = Invoke-WebRequest -Uri "$($jamfProInformation['URI'])/api/oauth/token" -Headers $bearerTokenAuthHeaders -Method Post -Body $bodyContent -ContentType "application/x-www-form-urlencoded"
        if ($bearerTokenAuthResponse.StatusCode -eq 200) {
            $bearerTokenInformation.Add("Token", "$(($bearerTokenAuthResponse.Content | ConvertFrom-Json).access_token)")
            $bearerTokenInformation.Add("Expiration", "$(($bearerTokenAuthResponse.Content | ConvertFrom-Json).expires_in)")
            Write-Log-Info "Bearer token successfully generated."
            Write-Output ""
        } else {
            Write-Log-Error "Failed to generate bearer token. Status code: $($bearerTokenAuthResponse.StatusCode)"
            exit 1
        }
    } catch {
        Write-Log-Error "Error generating bearer token: $_"
        exit 1
    }
}

# Invalidate the bearer token
function Clear-BearerToken {
    $authHeaders = @{
        "accept" = "application/json"
        "Authorization" = "Bearer $($bearerTokenInformation['Token'])"
    }
    try {
        $invalidateTokenResponse = Invoke-WebRequest -Uri "$($jamfProInformation['URI'])/api/v1/auth/invalidate-token" -Method POST -Headers $authHeaders
        if ($invalidateTokenResponse.StatusCode -eq 204) {
            Write-Log-Info "Bearer token invalidated successfully."
            Write-Output ""
        } else {
            Write-Log-Error "Failed to invalidate bearer token. Status code: $($invalidateTokenResponse.StatusCode)"
        }
    } catch {
        Write-Log-Error "Error invalidating bearer token: $_"
    }
}

function Get-JsonFromUrl($url) {
    Write-Log-Info "Fetching JSON data from $url..."
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        return $response.Content | ConvertFrom-Json
    } catch {
        Write-Log-Error "Failed to fetch JSON data from $url : $($_.Exception.Message)"
        exit 1
    }
}
# Generic function to make GET requests to the Jamf Pro API
function Invoke-JamfAPIGETRequest {
    param (
        [string]$Uri,
        [hashtable]$Headers = $null,
        [int]$RetryCount = 1
    )

    # Set up headers if not provided
    $Headers = @{
        "accept" = "application/json"
        "Authorization" = "Bearer $($bearerTokenInformation['Token'])"
    }

    try {
        # Perform the GET request
        return Invoke-WebRequest -Uri $Uri -Method GET -Headers $Headers -UseBasicParsing
    } catch {
        if ($_ -match "401" -and $RetryCount -gt 0) {
            Write-Warning "Token expired or unauthorized. Generating a new token..."
            Get-BearerToken
            # Update headers with the new token
            $Headers["Authorization"] = "Bearer $($bearerTokenInformation['Token'])"
            # Retry the request
            return Invoke-JamfAPIGETRequest -Uri $Uri -Headers $Headers -RetryCount ($RetryCount - 1)
        } else {
            Write-Error "API request failed: $_"
            throw
        }
    }
}

# Check CVE severity and set deadline days
function CVESeverityCheck {
    param (
        [array]$osVersions
    )

    # Define the default deadline days for each severity level
    $standardDeadlineDays = 7
    $activeDeadlineDays = 1
    $criticalDeadlineDays = 2
    $highDeadlineDays = 3
    $mediumDeadlineDays = 4
    $lowDeadlineDays = 6

    Write-Output ""
    Write-Log-Info "Calculated deadline days for each OS version based on CVE severity"
    foreach ($os in $osVersions) {
        $deadlineDays = $standardDeadlineDays

        # Check for actively exploited CVEs
        if ($os.ActivelyExploitedCVEs.Count -gt 0) {
            $deadlineDays = $activeDeadlineDays
            Write-Log-Info "Actively exploited CVEs found for $($os.Name). Setting deadlineDays to $deadlineDays."
        } elseif ($os.CVEs.Count -gt 0) {
            # Check the severity of each CVE using the NVD API
            foreach ($cve in $os.CVEs) {
                try {
                    Write-Output "Checking severity for CVE: $cve"
                    $nvdResponse = Invoke-RestMethod -Uri "$($nvdInformation.URI)?cveId=$cve" -Headers @{ "apiKey" = $nvdInformation.apiKey } -Method GET
                    $severity = $nvdResponse.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity

                    switch ($severity) {
                        "CRITICAL" {
                            $deadlineDays = [math]::Min($deadlineDays, $criticalDeadlineDays)
                            Write-Output "CVE $cve is CRITICAL. Setting deadlineDays to $deadlineDays."
                            break
                        }
                        "HIGH" {
                            $deadlineDays = [math]::Min($deadlineDays, $highDeadlineDays)
                            Write-Output "CVE $cve is HIGH. Setting deadlineDays to $deadlineDays."
                        }
                        "MEDIUM" {
                            $deadlineDays = [math]::Min($deadlineDays, $mediumDeadlineDays)
                            Write-Output "CVE $cve is MEDIUM. Setting deadlineDays to $deadlineDays."
                        }
                        "LOW" {
                            $deadlineDays = [math]::Min($deadlineDays, $lowDeadlineDays)
                            Write-Output "CVE $cve is LOW. Setting deadlineDays to $deadlineDays."
                        }
                        default {
                            Write-Output "CVE $cve has unknown severity. Skipping..."
                        }
                    }
                } catch {
                    Write-Warning "Failed to fetch severity for CVE: $cve. Skipping..."
                }
            }
        } else {
            Write-Output "No CVEs found for $($os.Name). Using standard deadlineDays: $standardDeadlineDays."
        }

        # Set the calculated deadlineDays for the OS version
        $os.DeadlineDays = $deadlineDays
    }
}

# Create an update plan in Jamf Pro
function Create-UpdatePlan {
    param (
        [string]$DeviceID,
        [string]$VersionType,
        [string]$TargetDeadline,
        [string]$UpdateAction
    )

    $jsonBody = @{
        "devices" = @(
            @{
                "objectType" = "COMPUTER"
                "deviceId" = $DeviceID
            }
        )
        "config" = @{
            "updateAction" = $UpdateAction
            "versionType" = $VersionType
            "specificVersion" = "NO_SPECIFIC_VERSION"
            "forceInstallLocalDateTime" = $TargetDeadline
        }
    } | ConvertTo-Json -Depth 10

    $Headers = @{
        "accept" = "application/json"
        "Authorization" = "Bearer $($bearerTokenInformation['Token'])"
    }

    try {
        $softwareUpdatePlanResponse = Invoke-WebRequest -Uri "$($jamfProInformation['URI'])/api/v1/managed-software-updates/plans" -Method POST -Headers $Headers -ContentType 'application/json' -Body $jsonBody
        if ($softwareUpdatePlanResponse.StatusCode -eq 201) {
            $softwareUpdateContent = $softwareUpdatePlanResponse.Content | ConvertFrom-Json
            Write-Log-Info "Update plan created successfully. Plan ID: $($softwareUpdateContent.plans.planId)"
            Write-Log-Info "Plan URL: $($jamfProInformation['URI'])/api/v1/managed-software-updates/plans/$($softwareUpdateContent.plans.planId)"
            Start-Sleep -Seconds 40
            # Check the status of the plan
            $planStatusResponse = Invoke-JamfAPIGETRequest -Uri "$($jamfProInformation['URI'])/api/v1/managed-software-updates/plans/$($softwareUpdateContent.plans.planId)" -Headers $Headers -RetryCount 1
            $planStatusContent = $planStatusResponse.Content | ConvertFrom-Json
            #Write-Output $planStatusContent
            $planStatus = $($planStatusContent.status.state)
            $errorReasons = $($planStatusContent.status.errorReasons)

            if ($planStatus -eq "PlanFailed") {
                if ($errorReasons -eq "EXISTING_PLAN_FOR_DEVICE_IN_PROGRESS") {
                    Write-Log-Verbose "Plan Status: $($planStatus)" -Verbose
                    Write-Log-Verbose "Plan Error Reasons: $($errorReasons)" -Verbose
                } else {
                    Write-Log-Warning "Plan Status: $($planStatus)"
                    Write-Log-Warning "Plan Error Reasons: $($errorReasons)"
                }
            } else {
                Write-Log-Info "Plan Status: $($planStatus)"
            }

        } else {
            Write-Log-Warning "Failed to create update plan. Status code: $($softwareUpdatePlanResponse.StatusCode)."
        }
    } catch {
        Write-Log-Error "Error creating update plan: $_"
    }
}

# Process each smart group
function ProcessGroup {
    param (
        [string]$GroupName,
        [int]$SmartGroupID,
        [int]$SWUDeferralDays,
        [array]$osVersions
    )

    $currentDate = (Get-Date).ToUniversalTime()

    # Resolve the VersionType for the group (use override if available)
    $resolvedVersionType = if ($global:jamfProGroupVersionTypeOverrides.ContainsKey($GroupName)) {
        $global:jamfProGroupVersionTypeOverrides[$GroupName]
    } else {
        $versionType
    }

    Write-Output "======================================================"
    Write-Log-Info "Processing Smart Group: $GroupName (VersionType: $resolvedVersionType)"
    Write-Output ""

    # Evaluate which OS versions are visible based on deferral date
    foreach ($os in $osVersions) {
        $availableDate = (Get-Date $os.ReleaseDate).AddDays($SWUDeferralDays).ToUniversalTime()
        $os.ProcessOS = $currentDate -ge $availableDate
        if ($os.ProcessOS) {
            Write-Log-Info "$($os.Name) ($($os.Version)) is available and should be processed."
        } else {
            Write-Log-Info "Skipping $($os.Name) ($($os.Version)). Available date not reached. (Available: $availableDate, Current: $currentDate)"
        }
    }

    # Sort OS versions descending by version number
    $osVersions = $osVersions | Sort-Object { [version]$_.Version } -Descending

    # Get devices in the smart group
    $devices = Invoke-JamfAPIGETRequest -Uri "$($jamfProInformation['URI'])/api/v2/computer-groups/smart-group-membership/$SmartGroupID" -Headers $bearerTokenInformation -RetryCount 1
    $devices = $devices.Content | ConvertFrom-Json

    Write-Output ""
    Write-Log-Info "Processing devices in Smart Group: $GroupName"
    foreach ($device in $devices.members) {
        Write-Log-Info "Processing device: $device"

        $deviceInfo = Invoke-JamfAPIGETRequest -Uri "$($jamfProInformation['URI'])/api/v1/computers-inventory-detail/$($device)" -Headers $bearerTokenInformation -RetryCount 1
        $deviceInfo = $deviceInfo.Content | ConvertFrom-Json
        $deviceName = $deviceInfo.general.name
        $modelIdentifier = $deviceInfo.hardware.modelIdentifier
        $osVersion = $deviceInfo.operatingSystem.version
        $installedOSMajor = ($osVersion -split '\.')[0]

        # Determine supported major OS versions for the device
        $supportedOSMajors = @()
        foreach ($osName in $sofaJson.Models.$modelIdentifier.SupportedOS) {
            if ($osName -match '\s(\d+)$') {
                $supportedOSMajors += [int]$Matches[1]
            }
        }

        $bestMatch = $null
        $highestSupportedMajor = ($supportedOSMajors | Sort-Object -Descending)[0]

        foreach ($os in $osVersions) {
            $osMajor = ($os.Version -split '\.')[0]

            if (-not $os.ProcessOS) { continue }

            switch ($resolvedVersionType) {
                "LATEST_ANY" {
                    if (
                        ([version]$os.Version -gt [version]$osVersion) -and
                        ($supportedOSMajors -contains [int]$osMajor)
                    ) {
                        if (-not $bestMatch -or ([version]$os.Version -gt [version]$bestMatch.Version)) {
                            $bestMatch = $os
                        }
                    }
                }
                "LATEST_MAJOR" {
                    if (
                        ($osMajor -eq $highestSupportedMajor) -and
                        ([version]$os.Version -gt [version]$osVersion)
                    ) {
                        $bestMatch = $os
                        break
                    }
                }
                "LATEST_MINOR" {
                    if (
                        ($osMajor -eq $installedOSMajor) -and
                        ([version]$os.Version -gt [version]$osVersion)
                    ) {
                        $bestMatch = $os
                        break
                    }
                }
            }
        }

        if ($bestMatch) {
            $targetVersion = $bestMatch.Version
            $targetDeadline = (Get-Date $bestMatch.ReleaseDate).AddDays($SWUDeferralDays + $bestMatch.DeadlineDays).Date.AddHours(18).ToUniversalTime()
            Write-Log-Info "Creating update plan for $deviceName from $osVersion to $targetVersion with deadline $targetDeadline (VersionType: $resolvedVersionType)"
            try {
                Create-UpdatePlan -DeviceID $device -VersionType $resolvedVersionType -TargetDeadline $targetDeadline.ToString("yyyy-MM-ddTHH:mm:ss") -UpdateAction $updateAction
                Start-Sleep -Seconds 1
            } catch {
                Write-Warning "Failed to create update plan for $deviceName ($device). Error: $_"
            }
        } else {
            Write-Log-Warning "No eligible update plan for $deviceName ($device) with OS version $osVersion (VersionType: $resolvedVersionType)."
        }
    }
}




# Main function
function Main {
    Write-Log-Info "Starting $organisationScriptName version $scriptVersion on $scriptDate"
    $sofaJson = Get-JsonFromUrl $global:sofaFeedInformation['URI']

    $osVersions = @()
    foreach ($osVersion in $sofaJson.OSVersions) {
        $osVersions += @{
            Name = $osVersion.OSVersion
            Version = $osVersion.Latest.ProductVersion
            ReleaseDate = $osVersion.Latest.ReleaseDate
            CVEs = $osVersion.Latest.CVEs.PSObject.Properties.Name
            ActivelyExploitedCVEs = $osVersion.Latest.ActivelyExploitedCVEs
            ProcessOS = $false
        }
    }


    CVESeverityCheck -osVersions $osVersions
    Write-Output ""
    Get-BearerToken

    foreach ($group in $global:jamfProSmartGroupIDs.GetEnumerator()) {
        $groupName = $group.Key
        $smartGroupID = $group.Value
        $deferralDays = $global:jamfProSWUDeferralDays["${groupName}DeferralDays"]

        ProcessGroup -GroupName $groupName -SmartGroupID $smartGroupID -SWUDeferralDays $deferralDays -osVersions $osVersions
    }

    Clear-BearerToken
}

# Run the script
Main
