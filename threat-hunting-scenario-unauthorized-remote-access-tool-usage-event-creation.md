# Threat Event (Unauthorized Remote Access Tool Usage)
**Suspicious AnyDesk Execution and Connection Attempt**

## Steps the "Bad Actor" Took to Create Logs and IoCs:
1. Download the AnyDesk executable: https://download.anydesk.com/AnyDesk.exe
2. Launch the executable
3. Simulate a connection attempt using a fake ID:  
In the Remote Desk input box, enter: 123 456 789
6. Create a file on your desktop called ```important-documents.txt``` and add some fake entries
7. Move the file to simulate internal staging of exfiltration:  
Copy or move it to: C:\Users\Public\
8. Close AnyDesk and delete the executable

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect the download, file creation, movement, and deletion actions. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect the launch and runtime of AnyDesk.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| 	Log AnyDesk’s outbound connection attempt. |

---

## Related Queries:
```kql
// Detect download of AnyDesk.exe
DeviceFileEvents
| where DeviceName == "apoy-threat-hun"
| where FileName contains "AnyDesk.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, FileOriginUrl, SHA256

// Detect execution of AnyDesk.exe
DeviceProcessEvents
| where FileName contains "AnyDesk.exe"
| where DeviceName  == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ActionType, SHA256

// Detect outbound connection attempt by AnyDesk
DeviceNetworkEvents
| where InitiatingProcessFileName contains "AnyDesk.exe"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, LocalIP, ActionType, RemoteIP 

// Detect creation or movement of sensitive-looking file
DeviceFileEvents
| where FileName contains "important-documents"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName,  ActionType, FileName, FolderPath, SHA256

// Detect deletion of AnyDesk
DeviceFileEvents
| where FileName contains "AnyDesk.exe" and ActionType contains "FileDeleted"
| where DeviceName == "apoy-threat-hun" 
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName,  ActionType, FileName, FolderPath, SHA256
```

---

## Created By:
- **Author Name**: Nick Pamatian
- **Author Contact**: https://www.linkedin.com/in/nick-pamatian-b8828b28a/
- **Date**: April 16, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 16, 2025`  | `Nick Pamatian`    
