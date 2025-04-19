![image](https://github.com/user-attachments/assets/03615dcb-d060-4ff3-bed6-35eb53d56fd5)


# Threat Hunt Report: Unauthorized Remote Access Tool Usage
- [Scenario Creation](https://github.com/nickpamatian/threat-hunting-scenario-unauthorized-remote-access-tool-usage/blob/main/threat-hunting-scenario-unauthorized-remote-access-tool-usage-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- AnyDesk

##  Scenario

A recent cybersecurity bulletin from CISA warned of increased abuse of legitimate remote access tools like AnyDesk and TeamViewer by threat actors to maintain persistence on compromised systems. Management has requested a proactive hunt to identify unauthorized usage of such tools across all endpoints, especially those without documented remote support activity.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** to detect the launch and runtime of AnyDesk.
- **Check `DeviceNetworkEvents`** to log AnyDesk’s outbound connection attempt.
- **Check `DeviceFileEvents`** to detect the download, file creation, movement, and deletion actions.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` table to detect download of AnyDesk.exe

AnyDesk.exe was discovered being downloaded to the endpoint “apoy-threat-hun” from the user “apoy”. The user downloaded AnyDesk.exe at 2025-04-17T01:21:17.3156655Z, from URL: “https://download.anydesk.com/AnyDesk.exe”, then deleted AnyDesk.exe at 2025-04-17T01:25:56.3192816Z, approximately 4 minutes later. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "apoy-threat-hun"
| where FileName contains "AnyDesk.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, FileOriginUrl, SHA256

```
![image](https://github.com/user-attachments/assets/f835f4b6-d5a0-4f2d-85f3-9e5fb2123e9f)

---

### 2. Searched the `DeviceProcessEvents` table to detect execution of AnyDesk.exe

AnyDesk.exe was found launched at 2025-04-17T01:21:40.6850481Z on the endpoint “apoy-threat-hun”, user “apoy”. 

**Query used to locate event:**

```kql

DeviceProcessEvents
| where FileName contains "AnyDesk.exe"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ActionType, SHA256


```
![image](https://github.com/user-attachments/assets/50a3730e-05d0-4f14-b2d0-271b3bd4a47d)

---

### 3. Searched the `DeviceNetworkEvents` table to detect outbound connection attempt by AnyDesk

Successful connections were discovered from the endpoint “apoy-threat-hun” and remote IP addresses 57.129.37.75 and 5.188.124.23 being made by AnyDesk. The two IP addresses were confirmed to be associated with AnyDesk, indicating successful outbound connections to remote servers. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName contains "AnyDesk.exe"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, LocalIP, ActionType, RemoteIP 

```
![image](https://github.com/user-attachments/assets/e7e49083-5fe4-4e62-ac9c-dc20dd5c508a)

---

### 4. Searched the `DeviceNetworkEvents` table to detect creation or movement of a potentially sensitive file

A text document titled "Important-Documents.txt" was created at 2025-04-17T01:24:35.7554876Z. The contents of the document are currently unknown. While no direct evidence of data exfiltration was observed following the document's creation, the activity suggests data staging in preparation for potential future exfiltration. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "important-documents"
| where DeviceName == "apoy-threat-hun"
| order by Timestamp desc
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256

```
![image](https://github.com/user-attachments/assets/65999846-b26f-44d3-bdaa-1d2ae57b2865)

---

## Chronological Event Timeline

### 1. File Download - AnyDesk Installer

- **Timestamp:** `2025-04-16T20:21:17.315Z`  
- **Event:** User "apoy" downloaded `AnyDesk.exe` from `https://download.anydesk.com/AnyDesk.exe` to the Downloads folder on endpoint `apoy-threat-hun`.  
- **Action:** File download detected.  
- **File Path:** `C:\Users\apoy\Downloads\AnyDesk.exe`

---

### 2. AnyDesk Execution

- **Timestamp:** `2025-04-16T20:21:40.685Z`  
- **Event:** The `AnyDesk.exe` file was executed by user "apoy" on endpoint `apoy-threat-hun`, initiating the AnyDesk process.  
- **Action:** Remote access tool executed.  
- **File Path:** `C:\Users\apoy\Downloads\AnyDesk.exe`

---

### 3. Network Connection to Remote IP #1

- **Timestamp:** `2025-04-16T20:21:50.000Z`  
- **Event:** The `AnyDesk.exe` process established a network connection to remote IP address `57.129.37.75`, confirming outbound remote access activity.  
- **Action:** Network connection established.  
- **Remote IP:** `57.129.37.75`

---

### 4. Network Connection to Remote IP #2

- **Timestamp:** `2025-04-16T20:21:51.000Z`  
- **Event:** The `AnyDesk.exe` process established a network connection to remote IP address `5.188.124.23`, indicating further remote access attempts.  
- **Action:** Network connection established.  
- **Remote IP:** `5.188.124.23`

---

### 5. File Creation - Important Document

- **Timestamp:** `2025-04-16T20:24:35.755Z`  
- **Event:** User "apoy" created a file named `Important-Documents.txt` on the desktop of endpoint `apoy-threat-hun`. The contents and purpose of the file are currently unknown.  
- **Action:** File creation detected.  
- **File Path:** `C:\Users\apoy\Desktop\Important-Documents.txt`

---

### 6. Shortcut Creation - Recent Files

- **Timestamp:** `2025-04-16T20:24:36.000Z`  
- **Event:** A shortcut to `Important-Documents.txt` was created in the Recent folder, potentially indicating that the document was staged for easy access or future manipulation.  
- **Action:** Shortcut created.  
- **File Path:** `C:\Users\apoy\AppData\Roaming\Microsoft\Windows\Recent`

---

### 7. File Modification - Important Document

- **Timestamp:** `2025-04-16T20:24:48.000Z`  
- **Event:** User "apoy" modified the contents of `Important-Documents.txt`. The document's contents remain unknown but could be related to data staging for future exfiltration.  
- **Action:** File modified.  
- **File Path:** `C:\Users\apoy\Desktop\Important-Documents.txt`

---

### 8. File Deletion - AnyDesk

- **Timestamp:** `2025-04-16T20:25:56.319Z`  
- **Event:** The `AnyDesk.exe` file was deleted by user "apoy" from the Downloads folder on endpoint `apoy-threat-hun`, which could be an attempt to remove evidence of unauthorized remote access.  
- **Action:** File deletion detected.  
- **File Path:** `C:\Users\apoy\Downloads\AnyDesk.exe`


---

## Summary

On April 16, 2025, user "apoy" on the device "apoy-threat-hun" initiated activities involving AnyDesk. The user downloaded AnyDesk.exe from the official AnyDesk website and launched the application shortly thereafter. The AnyDesk process then established successful outbound connections to remote IP addresses 57.129.37.75 and 5.188.124.23, indicating remote access attempts. Additionally, a file titled Important-Documents.txt was created and modified on the desktop. The purpose of the document remains unclear, but these actions suggest data staging, potentially in preparation for future exfiltration. The AnyDesk application was later deleted, likely in an attempt to remove traces of the remote access activity.

---

## Response Taken

Unauthorized RAT use was confirmed on endpoint “apoy-threat-hun”. The device was isolated and the user's direct manager was notified.

---
