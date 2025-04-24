# PowerShell Script for iOS Update Deployment via Jamf Pro API
# Designed for use in an Azure Runbook

####################################################################################################
#
# Jamf DDM Sofa Processor (iOS)
#
####################################################################################################
#
# HISTORY
#
#   04.23.2025, 1.0.0, @robjschroeder
#       - Initial version
#       - Script to process iOS updates from SOFA feed and create update plans in Jamf Pro
#
#   04.24.2025, 1.0.1, @robjschroeder
#       - Added function to check if the Software Update feature toggle is on before continuing
#       - Added device's serial number into the output details for the device
#
####################################################################################################

####################################################################################################
#
# Global Variables
#
####################################################################################################

$DebugPreference = "Continue"
#$VerbosePreference = "Continue"

# Script Variables
$organisationScriptName = "Jamf DDM SOFA Processor - iOS"
$scriptVersion = "1.0.1"
$scriptDate = "2025-04-24"
$global:IgnoreDeferralCheck = $false

# Jamf Pro API Variables
$global:jamfProInformation = @{
    client_id = "e5b9f2cc-93c3-4f5d-96ec-3acb5d60bc62"
    client_secret = "fc77a5b1-ef48-4d25-a9b0-cb95ce2047cb"
    URI = 'https://rschroeder.jamfcloud.com'
}

# NVD API Variables
$global:nvdInformation = @{
    URI = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    apiKey = "4aeb7c91-6f45-4bdf-a3c4-4f6de758a9e1"
}

# Jamf Pro Smart Group IDs and SWU Deferral Days
$global:jamfProSmartGroupIDs = @{
    #"AlphaGroup" = 1060
    #"BetaGroup" = 1061
    #"GammaGroup" = 1062
    "ReleaseGroup" = 254
}

# Jamf Pro SWU Deferral Days
$global:jamfProSWUDeferralDays = @{
    "AlphaGroupDeferralDays" = 0
    "BetaGroupDeferralDays" = 3
    "GammaGroupDeferralDays" = 5
    "ReleaseGroupDeferralDays" = 10
}

# Jamf Pro Group Version Type Overrides
# This allows you to override the default version type for specific groups
# The keys should match the group names in $global:jamfProSmartGroupIDs
# The values should be the desired version type (e.g., "LATEST_ANY", "LATEST_MAJOR", "LATEST_MINOR")
$global:jamfProGroupVersionTypeOverrides = @{
    "AlphaGroup" = "LATEST_ANY"
    # "BetaGroup" = "LATEST_ANY"
    # "GammaGroup" = "LATEST_ANY"
    #"ReleaseGroup" = "LATEST_ANY"
    # Add more overrides as needed
}

# Software Update Variables
$updateAction = "DOWNLOAD_INSTALL_SCHEDULE"
$versionType = "LATEST_MINOR"

# SOFA Feed Variables
$global:sofaFeedInformation = @{
    URI = 'https://sofafeed.macadmins.io/v1/ios_data_feed.json'
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
            "ERROR" { Write-Output $logEntry }
            "WARNING" { Write-Output $logEntry }
            "INFO" { Write-Output $logEntry }
            "DEBUG" { Write-Output $logEntry }
            "VERBOSE" { Write-Output $logEntry }
            default { Write-Output $logEntry }
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

# Fetch JSON data from a URL
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

# Check if Software Update Feature is enabled
function Check-SoftwareUpdateFeature {

    $featureResponse = Invoke-JamfAPIGETRequest -Uri "$($jamfProInformation['URI'])/api/v1/managed-software-updates/plans/feature-toggle" -Headers $Headers -RetryCount 1

    if ($featureResponse.StatusCode -eq 200) {
        $featureContent = $featureResponse.Content | ConvertFrom-Json
        $toggleEnabled = $($featureContent.toggle)
    } else {
        Write-Log-Warning "Failed to check Software Update Feature Toggle. Status code: $($featureResponse.StatusCode)"
    }
}

# Parse the SOFA feed for iOS versions
function Parse-SOFAFeed-iOS {
    param (
        [object]$sofaJson
    )

    $osVersions = @()
    foreach ($osVersion in $sofaJson.OSVersions) {
        $iOSReleases = $osVersion.SecurityReleases | Where-Object {
            $_.UpdateName -match '^iOS'

        }

        if ($iOSReleases.Count -eq 0) { continue }

        $latestRelease = $iOSReleases | Sort-Object {[version]$_.ProductVersion} -Descending | Select-Object -First 1

        $osVersionEntry = @{
            Name = "iOS $($osVersion.OSVersion)"
            Version = [string]$latestRelease.ProductVersion
            ReleaseDate = $latestRelease.ReleaseDate
            ExpirationDate = $latestRelease.ExpirationDate
            SupportedDevices = $latestRelease.SupportedDevices
            CVEs = $latestRelease.CVEs.PSObject.Properties.Name
            ActivelyExploitedCVEs = $latestRelease.ActivelyExploitedCVEs
            UniqueCVEsCount = $latestRelease.UniqueCVEsCount
            SecurityReleases = $iOSReleases
            ProcessOS = $false
        }

        Write-Log-Debug "Parsed iOS OS Entry: $($osVersionEntry.Name) $($osVersionEntry.Version)"
        $osVersions += $osVersionEntry
    }

    return $osVersions
}

# Parse the SOFA feed for iPadOS versions
function Parse-SOFAFeed-iPadOS {
    param (
        [object]$sofaJson
    )

    $osVersions = @()
    foreach ($osVersion in $sofaJson.OSVersions) {
        $iPadReleases = $osVersion.SecurityReleases | Where-Object {
            $_.UpdateName -match 'iPadOS'
        }

        if ($iPadReleases.Count -eq 0) { continue }

        $latestRelease = $iPadReleases | Sort-Object {[version]$_.ProductVersion} -Descending | Select-Object -First 1

        $osVersionEntry = @{
            Name = "iPadOS $($osVersion.OSVersion)"
            Version = [string]$latestRelease.ProductVersion
            ReleaseDate = $latestRelease.ReleaseDate
            ExpirationDate = $latestRelease.ExpirationDate
            SupportedDevices = $latestRelease.SupportedDevices
            CVEs = $latestRelease.CVEs.PSObject.Properties.Name
            ActivelyExploitedCVEs = $latestRelease.ActivelyExploitedCVEs
            UniqueCVEsCount = $latestRelease.UniqueCVEsCount
            SecurityReleases = $iPadReleases
            ProcessOS = $false
        }

        Write-Log-Debug "Parsed iPadOS OS Entry: $($osVersionEntry.Name) $($osVersionEntry.Version)"
        $osVersions += $osVersionEntry
    }

    return $osVersions
}

# Check CVE severity and set deadline days
function Check-CVESeverity {
    param (
        [array]$osVersions
    )

    # Define the default deadline days for each severity level
    $standardDeadlineDays = 7
    $lowDeadlineDays = 6
    $mediumDeadlineDays = 4
    $highDeadlineDays = 3
    $criticalDeadlineDays = 2
    $activeDeadlineDays = 1
    
    Write-Output ""
    Write-Log-Info "Calculated deadline days for each OS version based on CVE severity"
    foreach ($os in $osVersions) {
        $deadlineDays = $standardDeadlineDays

        # Check for actively exploited CVEs
        if ($os.ActivelyExploitedCVEs.Count -gt 0) {
            $deadlineDays = $activeDeadlineDays
            Write-Log-Info "Actively exploited CVEs found for iOS $($os.Name). Setting deadlineDays to $deadlineDays."
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
            Write-Output "No CVEs found for iOS $($os.Name). Using standard deadlineDays: $standardDeadlineDays."
        }

        # Set the calculated deadlineDays for the OS version
        $os.DeadlineDays = $deadlineDays
    }
}

# Get the existing update plan for a device
function Get-ExistingPlan {
    param (
        [string]$DeviceID,
        [string]$ForceInstallLocalDateTime
    )

    $Headers = @{
        "accept" = "application/json"
        "Authorization" = "Bearer $($bearerTokenInformation['Token'])"
    }

    # Encode individual values only
    $encodedDeviceID = [System.Web.HttpUtility]::UrlEncode($DeviceID)
    $encodedDateTime = [System.Web.HttpUtility]::UrlEncode($ForceInstallLocalDateTime)

    # Construct filter without encoding the whole filter string
    $filter = "device.deviceId==$encodedDeviceID;forceInstallLocalDateTime==$encodedDateTime"
    $encodedUri = "$($jamfProInformation['URI'])/api/v1/managed-software-updates/plans?filter=$filter"

    try {
        $planExistsResponse = Invoke-JamfAPIGETRequest -Uri $encodedUri -Headers $Headers -RetryCount 1
        if (-not $planExistsResponse) {
            Write-Log-Error "No response received from the API."
            return $null
        }
        if ($planExistsResponse.StatusCode -ne 200) {
            Write-Log-Error "API request failed with status code: $($planExistsResponse.StatusCode)"
            return $null
        }

        try {
            $planExistsContent = $planExistsResponse.Content | ConvertFrom-Json
            #Write-Log-Debug "API response content: $($planExistsContent | ConvertTo-Json -Depth 10)"

            # Extract totalCount from the response
            $totalCount = $planExistsContent.totalCount
            #Write-Log-Info "Total count of existing plans: $totalCount"

            return $planExistsContent
        } catch {
            Write-Log-Error "Failed to parse JSON response: $_"
            return $null
        }
    } catch {
        Write-Log-Error "Error during API request: $_"
        return $null
    }
}

function Get-PlanStatusSummary {
    param (
        [string]$State,
        [string[]]$ErrorReasons
    )

    $planStates = @{
        "Unknown" = "The plan was either just created and could not be fully initialized yet, or the database is corrupted."
        "Init" = "Waiting for queue assignment so processing can start."
        "PendingPlanValidation" = "Processing validation logic."
        "AcceptingPlan" = "Passed all validation checks; added to planning queue."
        "ProcessingPlanType" = "Determining update action path."
        "RejectingPlan" = "Validation failed; removed from planning queue."
        "StartingPlan" = "Preparing to begin update."
        "PlanFailed" = "Validation failed or unexpected error condition."
        "SchedulingScanForOSUpdates" = "ScheduleOSUpdateScan command queued."
        "ProcessingScheduleOSUpdatesScanResponse" = "Processing scan response."
        "WaitingForScheduleOSUpdateScanToComplete" = "Waiting for scan completion."
        "CollectingAvailableOSUpdates" = "AvailableOSUpdates command queued."
        "ProcessingAvailableOSUpdatesResponse" = "Processing updates response."
        "ProcessingSchedulingType" = "Evaluating install path (MDM/DDM)."
        "SchedulingDDM" = "Queuing DeclarativeManagement command."
        "SchedulingMDM" = "Proceeding with MDM-based update."
        "WaitingToStartDDMUpdate" = "Waiting for DDM to report update start."
        "ProcessingDDMStatusResponse" = "Evaluating DDM update status."
        "CollectingDDMStatus" = "Monitoring in-progress DDM update."
        "SchedulingOSUpdate" = "ScheduleOSUpdate command queued."
        "ProcessingScheduleOSUpdateResponse" = "Processing ScheduleOSUpdate response."
        "CollectingOSUpdateStatus" = "OSUpdateStatus command queued."
        "ProcessingOSUpdateStatusResponse" = "Evaluating update status response."
        "WaitingToCollectOSUpdateStatus" = "Waiting before next status check."
        "PlanCompleted" = "Update completed successfully."
        "PlanCanceled" = "Manually canceled by user."
        "PlanException" = "Unexpected exception caused failure."
        "ProcessingPlanTypeMdm" = "Determining first MDM command."
    }

    $errorDescriptions = @{
        "APPLE_SILICON_NO_ESCROW_KEY" = "Requires escrow of the bootstrap token for M-series chips."
        "NOT_SUPERVISED" = "Device is not supervised; MDM commands fail."
        "NOT_MANAGED" = "Device is not managed; MDM commands fail."
        "NO_DISK_SPACE" = "Computer's storage is full."
        "NO_UPDATES_AVAILABLE" = "No updates available for current OS."
        "SPECIFIC_VERSION_UNAVAILABLE" = "Version not available on Apple servers."
        "ACTION_NOT_SUPPORTED_FOR_DEVICE_TYPE" = "Unsupported action for device type."
        "PLAN_NOT_FOUND" = "Plan removed manually from database."
        "APPLE_SOFTWARE_LOOKUP_SERVICE_ERROR" = "Apple update servers are offline and not cached."
        "EXISTING_PLAN_FOR_DEVICE_IN_PROGRESS" = "Device already has a plan in progress."
        "DECLARATIVE_DEVICE_MANAGEMENT_SOFTWARE_UPDATES_NOT_SUPPORTED_FOR_DEVICE_OS_VERSION" = "DDM updates require newer OS versions (macOS 14+, iOS 17+)."
        "DOWNGRADE_NOT_SUPPORTED" = "OS downgrades are not supported."
        "DECLARATIVE_SERVICE_ERROR" = "Communication failure with declarative server."
        "UNABLE_TO_FIND_UPDATES_AND_OUT_OF_RETRIES" = "Exceeded retries collecting update info."
        "DATA_INTEGRITY_VIOLATION_EXCEPTION" = "Database integrity violation detected."
        "ILLEGAL_ARGUMENT_EXCEPTION" = "Illegal argument received in update status."
        "MDM_EXCEPTION" = "Unexpected error queuing MDM commands."
        "ACCEPT_PLAN_FAILURE" = "Unexpected error accepting plan."
        "SCHEDULE_PLAN_FAILURE" = "Unexpected error scheduling plan."
        "REJECT_PLAN_FAILURE" = "Unexpected error rejecting plan."
        "START_PLAN_FAILURE" = "Unexpected error starting plan."
        "QUEUE_SCHEDULED_OS_UPDATE_SCAN_FAILURE" = "Error queuing ScheduleOSUpdateScan."
        "SCAN_WAIT_FINISHED_FAILURE" = "Error completing update scan step."
        "QUEUE_AVAILABLE_OS_UPDATE_COMMAND_FAILURE" = "Error queuing AvailableOsUpdates."
        "MDM_CLIENT_EXCEPTION" = "MDM client failed during ScheduleOSUpdate."
        "QUEUE_SCHEDULE_OS_UPDATE_FAILURE" = "Failed to queue ScheduleOSUpdate."
        "QUEUE_OS_UPDATE_STATUS_COMMAND_FAILURE" = "Failed to queue OsUpdateStatus command."
        "STILL_IN_PROGRESS_FAILURE" = "Error checking in-progress status."
        "WAIT_TO_COLLECT_OS_UPDATE_STATUS_FAILURE" = "Error waiting for update status."
        "IS_DOWNLOADED_AND_NEEDS_INSTALL_FAILURE" = "Error checking if download completed."
        "IS_INSTALLED_FAILURE" = "Error checking installation success."
        "IS_DOWNLOAD_ONLY_AND_DOWNLOADED_FAILURE" = "Download-only command validation failed."
        "VERIFY_INSTALLATION_FAILURE" = "Update installation verification failed."
        "IS_MAC_OS_UPDATE_FAILURE" = "Could not determine if update was for macOS."
        "IS_LATEST_FAILURE" = "Error starting plan with LATEST_* version type."
        "IS_SPECIFIC_VERSION_FAILURE" = "Error starting specific version plan."
        "HANDLE_COMMAND_QUEUE_FAILURE" = "Failure queuing core update commands."
        "SPECIFIC_VERSION_UNAVAILABLE_FOR_DEVICE_MODEL" = "Version not compatible with device model."
        "INVALID_CONFIGURATION_DECLARATION" = "Device returned invalid configuration declaration."
        "UNKNOWN" = "Database corrupted or undefined error occurred."
    }

    # Status output
    $description = $planStates[$State]
    if (-not $description) { $description = "Unknown plan state: $State" }

    Write-Log-Info "Plan Status: $State"
    Write-Log-Info "Description: $description"

    if ($ErrorReasons) {
        foreach ($error in $ErrorReasons) {
            $errorText = $errorDescriptions[$error]
            if (-not $errorText) { $errorText = "Unknown error: $error" }
            Write-Log-Warning "Error Reason: $error"
            Write-Log-Warning "Description: $errorText"
        }
    }
}

# Create an update plan for a device
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
                "objectType" = "MOBILE_DEVICE"
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

            Get-PlanStatusSummary -State $planStatus -ErrorReasons $errorReasons

        } else {
            Write-Log-Warning "Failed to create update plan. Status code: $($softwareUpdatePlanResponse.StatusCode)."
        }
    } catch {
        Write-Log-Error "Error creating update plan: $_"
    }
}

# Normalize version string to ensure it has three components
# This is important for proper version comparison
function Normalize-VersionString {
    param (
        [string]$v
    )
    if ($v -match '^\d+\.\d+$') {
        return "$v.0"
    }
    return $v
}

# Process iPad devices
function ProcessDevice-iPad {
    param (
        [int]$deviceID,
        [object]$deviceInfo,
        [array]$iPadOSVersions,
        [int]$SWUDeferralDays,
        [string]$resolvedVersionType
    )

    Write-Log-Info "Processing iPad device ID: $deviceID"

    # Store device information
    $deviceName = $deviceInfo.name
    $deviceSerialNumber = $deviceInfo.serialNumber
    $modelIdentifier = $deviceInfo.ios.modelIdentifier
    $osVersion = $deviceInfo.osVersion
    $installedOSMajor = [int]($osVersion -split '\.')[0]
    $latestOSVersion = Get-LatestOSVersion -sofaFeed $sofaJson -modelIdentifier $modelIdentifier

    Write-Log-Info "Device: $deviceName | Model: $modelIdentifier | Serial Number: $deviceSerialNumber | OS: $osVersion | Latest: $latestOSVersion"

    # Check the SOFA feed for supported OS versions
    $supportedOSMajors = @()
    foreach ($osEntry in $sofaJson.OSVersions) {
        if ($osEntry.Latest.SupportedDevices -contains $modelIdentifier) {
            $supportedOSMajors += [int]$osEntry.OSVersion
        }
        foreach ($sr in $osEntry.SecurityReleases) {
            if ($sr.SupportedDevices -contains $modelIdentifier) {
                $supportedOSMajors += [int]$osEntry.OSVersion
            }
        }
    }
    $supportedOSMajors = $supportedOSMajors | Sort-Object -Unique
    $highestSupportedMajor = ($supportedOSMajors | Sort-Object -Descending)[0]

    $bestMatch = $null

    # Find the best match for the iPadOS version
    foreach ($os in $iPadOSVersions) {
        if (-not $os.ProcessOS) {
            #Write-Log-Debug "Skipping $($os.Name) ($($os.Version)) — ProcessOS=False"
            continue
        }

        $osParsedVersion = $null
        $deviceParsedVersion = $null

        # Check if the OS version and device version are valid
        if (-not [version]::TryParse($os.Version, [ref]$osParsedVersion)) {
            Write-Log-Debug "Skipping $($os.Name) ($($os.Version)) — Invalid OS version format"
            continue
        }
        if (-not [version]::TryParse($osVersion, [ref]$deviceParsedVersion)) {
            Write-Log-Debug "Skipping $deviceName due to invalid current OS version format: $osVersion"
            continue
        }

        # Extract the major version from the OS version
        $osMajor = [int]($os.Version -split '\.')[0]

        # Determine the best match based on the resolved version type
        switch ($resolvedVersionType) {
            "LATEST_ANY" {
                if (($osParsedVersion -gt $deviceParsedVersion) -and ($supportedOSMajors -contains $osMajor)) {
                    if (-not $bestMatch -or ($osParsedVersion -gt [version]$bestMatch.Version)) {
                        $bestMatch = $os
                    }
                }
            }
            "LATEST_MAJOR" {
                if (($osMajor -eq $highestSupportedMajor) -and ($osParsedVersion -gt $deviceParsedVersion)) {
                    $bestMatch = $os
                    break
                }
            }
            "LATEST_MINOR" {
            if (($osMajor -eq $installedOSMajor) -and ($osParsedVersion -gt $deviceParsedVersion)) {
                if (-not $bestMatch -or ($osParsedVersion -gt [version]$bestMatch.Version)) {
                    $bestMatch = $os
                }
            }
        }
        }
    }

    if ($bestMatch) {
        $targetVersion = $bestMatch.Version
        $targetDeadline = (Get-Date $bestMatch.ReleaseDate).AddDays($SWUDeferralDays + $bestMatch.DeadlineDays).Date.AddHours(18).ToUniversalTime()

        # Check for existing update plans
        Write-Log-Info "Checking for existing plan for $deviceID with Install Local DateTime $($targetDeadline.ToString("yyyy-MM-ddTHH:mm:ss"))"
        $existingPlan = Get-ExistingPlan -DeviceID $deviceId -ForceInstallLocalDateTime $targetDeadline.ToString("yyyy-MM-ddTHH:mm:ss")

        if ($existingPlan -and $existingPlan.totalCount -gt 0) {
            Write-Log-Warning "Existing plan(s) found for $deviceName. Skipping update."
            return
        }

        # Prevent unintentional upgrade across major versions for LATEST_ANY / LATEST_MAJOR
        if (($resolvedVersionType -eq "LATEST_ANY" -or $resolvedVersionType -eq "LATEST_MAJOR") -and
        ($installedOSMajor -lt $highestSupportedMajor)) {

            Write-Log-Info "$deviceName is on iPadOS $osVersion but supports iPadOS $highestSupportedMajor. Change plan creation to avoid major version upgrade with $resolvedVersionType."
            Write-Log-Info "Setting versionType to LATEST_MINOR for $deviceName."
            $resolvedVersionType = "LATEST_MINOR"
            Write-Log-Info "Creating update plan for $deviceName : $osVersion to $targetVersion (Deadline: $targetDeadline, Type: $resolvedVersionType)"
        } else {
            Write-Log-Info "Creating update plan for $deviceName : $osVersion to $targetVersion (Deadline: $targetDeadline, Type: $resolvedVersionType)"
        }

        try {
            Create-UpdatePlan -DeviceID $deviceID -VersionType $resolvedVersionType -TargetDeadline $targetDeadline.ToString("yyyy-MM-ddTHH:mm:ss") -UpdateAction $updateAction
            Start-Sleep -Seconds 10
        } catch {
            Write-Warning "Failed to create update plan for $deviceName ($deviceID). Error: $_"
        }
    } else {
        Write-Log-Warning "No eligible update found for $deviceName (OS: $osVersion, Type: $resolvedVersionType)"
    }

    Write-Output ""
}

function ProcessDevice-iPhone {
    param (
        [int]$deviceID,
        [object]$deviceInfo,
        [array]$iOSVersions,
        [int]$SWUDeferralDays,
        [string]$resolvedVersionType
    )

    Write-Log-Info "Processing iPhone device ID: $deviceID"

    # Store device information
    $deviceName = $deviceInfo.name
    $deviceSerialNumber = $deviceInfo.serialNumber
    $modelIdentifier = $deviceInfo.ios.modelIdentifier
    $osVersion = $deviceInfo.osVersion
    $installedOSMajor = [int]($osVersion -split '\.')[0]
    $latestOSVersion = Get-LatestOSVersion -sofaFeed $sofaJson -modelIdentifier $modelIdentifier

    Write-Log-Info "Device: $deviceName | Model: $modelIdentifier | Serial Number: $deviceSerialNumber | OS: $osVersion | Latest: $latestOSVersion"

    # Check the SOFA feed for supported OS versions
    $supportedOSMajors = @()
    foreach ($osEntry in $sofaJson.OSVersions) {
        if ($osEntry.Latest.SupportedDevices -contains $modelIdentifier) {
            $supportedOSMajors += [int]$osEntry.OSVersion
        }
        foreach ($sr in $osEntry.SecurityReleases) {
            if ($sr.SupportedDevices -contains $modelIdentifier) {
                $supportedOSMajors += [int]$osEntry.OSVersion
            }
        }
    }
    $supportedOSMajors = $supportedOSMajors | Sort-Object -Unique
    $highestSupportedMajor = ($supportedOSMajors | Sort-Object -Descending)[0]

    $bestMatch = $null

    # Find the best match for the iOS version
    foreach ($os in $iOSVersions) {
        if (-not $os.ProcessOS) {
            #Write-Log-Debug "Skipping $($os.Name) ($($os.Version)) — ProcessOS=False"
            continue
        }

        $osParsedVersion = $null
        $deviceParsedVersion = $null

        if (-not [version]::TryParse($os.Version, [ref]$osParsedVersion)) {
            Write-Log-Debug "Skipping $($os.Name) ($($os.Version)) — Invalid OS version format"
            continue
        }
        if (-not [version]::TryParse($osVersion, [ref]$deviceParsedVersion)) {
            Write-Log-Debug "Skipping $deviceName due to invalid current OS version format: $osVersion"
            continue
        }

        # Extract the major version from the OS version
        $osMajor = [int]($os.Version -split '\.')[0]

        # Determine the best match based on the resolved version type
        switch ($resolvedVersionType) {
            "LATEST_ANY" {
                if (($osParsedVersion -gt $deviceParsedVersion) -and ($supportedOSMajors -contains $osMajor)) {
                    if (-not $bestMatch -or ($osParsedVersion -gt [version]$bestMatch.Version)) {
                        $bestMatch = $os
                    }
                }
            }
            "LATEST_MAJOR" {
                if (($osMajor -eq $highestSupportedMajor) -and ($osParsedVersion -gt $deviceParsedVersion)) {
                    $bestMatch = $os
                    break
                }
            }
            "LATEST_MINOR" {
            if (($osMajor -eq $installedOSMajor) -and ($osParsedVersion -gt $deviceParsedVersion)) {
                if (-not $bestMatch -or ($osParsedVersion -gt [version]$bestMatch.Version)) {
                    $bestMatch = $os
                }
            }
        }
        }
    }

    if ($bestMatch) {
        $targetVersion = $bestMatch.Version
        $targetDeadline = (Get-Date $bestMatch.ReleaseDate).AddDays($SWUDeferralDays + $bestMatch.DeadlineDays).Date.AddHours(18).ToUniversalTime()

        # Check for existing update plans
        Write-Log-Info "Checking for existing plan for $deviceID with Install Local DateTime $($targetDeadline.ToString("yyyy-MM-ddTHH:mm:ss"))"
        $existingPlan = Get-ExistingPlan -DeviceID $deviceId -ForceInstallLocalDateTime $targetDeadline.ToString("yyyy-MM-ddTHH:mm:ss")

        if ($existingPlan -and $existingPlan.totalCount -gt 0) {
            Write-Log-Warning "Existing plan(s) found for $deviceName. Skipping update."
            return
        }

        
        # Prevent unintentional upgrade across major versions for LATEST_ANY / LATEST_MAJOR
        if (($resolvedVersionType -eq "LATEST_ANY" -or $resolvedVersionType -eq "LATEST_MAJOR") -and
        ($installedOSMajor -lt $highestSupportedMajor)) {

        Write-Log-Info "$deviceName is on iOS $osVersion but supports iOS $highestSupportedMajor. Change plan creation to avoid major version upgrade with $resolvedVersionType."
        Write-Log-Info "Setting versionType to LATEST_MINOR for $deviceName."
        $resolvedVersionType = "LATEST_MINOR"
        Write-Log-Info "Creating update plan for $deviceName : $osVersion to $targetVersion (Deadline: $targetDeadline, Type: $resolvedVersionType)"
        } else {
            Write-Log-Info "Creating update plan for $deviceName : $osVersion to $targetVersion (Deadline: $targetDeadline, Type: $resolvedVersionType)"
        }
        try {
            Create-UpdatePlan -DeviceID $deviceID -VersionType $resolvedVersionType -TargetDeadline $targetDeadline.ToString("yyyy-MM-ddTHH:mm:ss") -UpdateAction $updateAction
            Start-Sleep -Seconds 10
        } catch {
            Write-Warning "Failed to create update plan for $deviceName ($deviceID). Error: $_"
        }
    } else {
        Write-Log-Warning "No eligible update found for $deviceName (OS: $osVersion, Type: $resolvedVersionType)"
    }

    Write-Output ""
}

# Process each group
function ProcessGroup {
    param (
        [string]$GroupName,
        [int]$SmartGroupID,
        [int]$SWUDeferralDays,
        [array]$iOSVersions,
        [array]$iPadOSVersions
    )

    $currentDate = (Get-Date).ToUniversalTime()

    Write-Log-Info "====================================================="
    Write-Log-Info "Processing group: $GroupName (ID: $SmartGroupID) with deferral days: $SWUDeferralDays"

    # Check if the group has a version type override
    $resolvedVersionType = if ($global:jamfProGroupVersionTypeOverrides.ContainsKey($GroupName)) {
        $global:jamfProGroupVersionTypeOverrides[$GroupName]
    } else {
        $versionType
    }

    Write-Log-Info "VersionType for this group: $resolvedVersionType"
    Write-Output ""

    foreach ($os in $iOSVersions + $iPadOSVersions) {
        $releaseDate = Get-Date $os.ReleaseDate
        $availableDate = $releaseDate.AddDays($SWUDeferralDays).ToUniversalTime()

        if ($IgnoreDeferralCheck) {
            $os.ProcessOS = $true
        } elseif ($currentDate -ge $availableDate) {
            $os.ProcessOS = $true
            Write-Log-Info "$($os.Name) ($($os.Version)) is available and should be processed."
        } else {
            $os.ProcessOS = $false
            Write-Log-Info "Skipping $($os.Name) ($($os.Version)). Available date not reached. (Available: $availableDate, Current: $currentDate)"
        }
    }
    Write-Output ""

    $iOSVersions = $iOSVersions | Sort-Object { [version](Normalize-VersionString $_.Version) } -Descending
    $iPadOSVersions = $iPadOSVersions | Sort-Object { [version](Normalize-VersionString $_.Version) } -Descending
    $devicesResponse = Invoke-JamfAPIGETRequest -Uri "$($jamfProInformation['URI'])/JSSResource/mobiledevicegroups/id/$SmartGroupID" -RetryCount 1
    $devicesJson = $devicesResponse.Content | ConvertFrom-Json
    $deviceIDs = $devicesJson.mobile_device_group.mobile_devices | ForEach-Object { $_.id }

    Write-Log-Info "Found $($deviceIDs.Count) devices in group $GroupName."

    foreach ($deviceID in $deviceIDs) {
        # Get device information
        $deviceInfoResponse = Invoke-JamfAPIGETRequest -Uri "$($jamfProInformation['URI'])/api/v2/mobile-devices/$deviceID/detail" -RetryCount 1
        $deviceInfo = $deviceInfoResponse.Content | ConvertFrom-Json
        $modelIdentifier = $deviceInfo.ios.modelIdentifier
        $deviceIsIPad = $modelIdentifier -like "iPad*"

        if ($deviceIsIPad) {
            #Write-Output "Processing iPad"
            ProcessDevice-iPad -deviceID $deviceID -deviceInfo $deviceInfo -iPadOSVersions $iPadOSVersions -SWUDeferralDays $SWUDeferralDays -resolvedVersionType $resolvedVersionType
        } else {
            #Write-Output "Processing iPhone"
            ProcessDevice-iPhone -deviceID $deviceID -deviceInfo $deviceInfo -iOSVersions $iOSVersions -SWUDeferralDays $SWUDeferralDays -resolvedVersionType $resolvedVersionType
        }
    }
}
# Get the latest OS version from the SOFA feed
function Get-LatestOSVersion {
    param (
        [object] $sofaFeed,
        [string] $modelIdentifier
    )

    # Check all OS versions
    foreach ($osVersion in $sofaFeed.OSVersions) {
        $latest = $osVersion.Latest
        # Verbose output
        Write-Verbose "Checking OS Version: $($latest.ProductVersion) for model: $modelIdentifier"
        Write-Verbose "Supported Devices: $($latest.SupportedDevices -join ', ')"
        if ($latest.SupportedDevices -contains $modelIdentifier) {
            # Verbose output
            Write-Verbose "Found model $modelIdentifier in OS Version: $($latest.ProductVersion)"
            return $latest.ProductVersion
        }

        # Check security releases within the OS version
        foreach ($securityRelease in $osVersion.SecurityReleases) {
            # Verbose output
            Write-Verbose "Checking Security Release: $($securityRelease.ProductVersion) for model: $modelIdentifier"
            Write-Verbose "Supported Devices: $($securityRelease.SupportedDevices -join ', ')"
            if ($securityRelease.SupportedDevices -contains $modelIdentifier) {
                # Verbose output
                Write-Verbose "Found model $modelIdentifier in Security Release: $($securityRelease.ProductVersion)"
                return $securityRelease.ProductVersion
            }
        }
    }

    Write-Verbose "Model $modelIdentifier not found in any OS Version or Security Release"
    return $null
}

# Main Function
function Main {
    Write-Log-Info "Starting $organisationScriptName - Version $scriptVersion - Date $scriptDate"

    # Ensure the Software Update Feature is enabled
    Get-BearerToken
    Check-SoftwareUpdateFeature
    if ($toggleEnabled -eq $false) {
        Write-Log-Error "Software Update Feature is not enabled. Exiting script."
        exit 1
    } else {
        Write-Log-Info "Software Update Feature is enabled."
    }

    # Fetch the SOFA feed
    $sofaJson = Get-JsonFromUrl $global:sofaFeedInformation['URI']
    if (-not $sofaJson) {
        Write-Log-Error "Failed to fetch SOFA feed. Exiting script."
        exit 1
    }

    # Parse the SOFA feed for iOS and iPadOS versions
    $osVersionsiOS = Parse-SOFAFeed-iOS -sofaJson $sofaJson
    $osVersionsiPadOS = Parse-SOFAFeed-iPadOS -sofaJson $sofaJson

    # Log the parsed versions for debugging
    Write-Output ""
    Write-Log-Info "iOS Versions:"
    foreach ($os in $osVersionsiOS) {
        Write-Log-Info "OS Version: $($os.Name), Latest Version: $($os.Version), Release Date: $($os.ReleaseDate)"
        Write-Log-Info "Actively Exploited CVEs: $($os.ActivelyExploitedCVEs -join ', ')"
        Write-Log-Info "All CVEs: $($os.CVEs -join ', ')"
        Write-Output ""
    }

    Write-Output ""
    Write-Log-Info "iPadOS Versions"
    foreach ($os in $osVersionsiPadOS) {
        Write-Log-Info "OS Version: $($os.Name), Latest Version: $($os.Version), Release Date: $($os.ReleaseDate)"
        Write-Log-Info "Actively Exploited CVEs: $($os.ActivelyExploitedCVEs -join ', ')"
        Write-Log-Info "All CVEs: $($os.CVEs -join ', ')"
        Write-Output ""
    }

    # Check CVE severity and set deadline days
    Check-CVESeverity -osVersions $osVersionsiOS
    Check-CVESeverity -osVersions $osVersionsiPadOS
    Write-Output ""

    # Process each group
    foreach ($group in $global:jamfProSmartGroupIDs.GetEnumerator()) {
        $groupName = $group.Key
        $smartGroupID = $group.Value
        $deferralDays = $global:jamfProSWUDeferralDays["${groupName}DeferralDays"]
        # Call ProcessGroup function
        ProcessGroup -GroupName $groupName -SmartGroupID $smartGroupID -SWUDeferralDays $deferralDays -iOSVersions $osVersionsiOS -iPadOSVersions $osVersionsiPadOS
        }

    # Clear the bearer token
    Clear-BearerToken
}

# Run it!
Main
