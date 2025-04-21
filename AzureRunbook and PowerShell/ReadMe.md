# Apple Auto Patch - Azure Runbook and PowerShell


## 🧠 Overview

This script automates the creation of macOS update plans in Jamf Pro using:

- **SOFA feed** for available macOS updates  
- **Smart group logic** for staged rollouts  
- **CVE evaluation** to prioritize security fixes  
- **Azure Runbook** for scheduled execution

---

## ⚙️ Requirements

- Azure Automation Account  
- Jamf Pro API access (with a token-based API user)  
- PowerShell 7+ Runtime  
- Environment variables for:
  - `JAMF_BASE_URL`
  - `JAMF_API_USER`
  - `JAMF_API_PASSWORD`
  - `JAMF_SMART_GROUPS`
  - `JAMF_VERSION_OVERRIDES`
 
---

## 📋 What It Does

1. **Authenticates** with Jamf Pro API and fetches an access token.  
2. **Fetches the SOFA feed** and parses available macOS updates.  
3. **Determines the latest version** to deploy based on group-defined version types:
   - `LATEST_ANY`
   - `LATEST_MAJOR`
   - `LATEST_MINOR`  
4. **Fetches smart group members** and their macOS versions.  
5. **Evaluates each group** to determine if an update is needed.  
6. **Creates a software update plan** in Jamf Pro via the API.

---

## 📊 Smart Group Evaluation

Each group is evaluated using ProcessGroup, which:
- Determines the availble date of the macOS releases based on your Software Udpate Deferals from Jamf Pro configuration profiles
- Checks current macOS versions of members
- Determines the latest OS supported based on the hardware of the device
- Evaluates which release will be applied by the DDM update command
- Skips if device is on a higher or equal to version than that being applied
- Creates a Software Update Plan for those needing updates
