<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/TonyRamos1982/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

First we checked the DeviceFileEvents table for any files with the “tor” string in the file name. Upon our search we have discovered several “tor-related”  files including a shopping-list.txt file. The user also downloaded a tor installer file. These events were mark at 2025-04-30T05:50:59.4333664Z 

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "tony-mde-lab"
| where FileName startswith "tor"
| where Timestamp >= datetime(2025-04-30T05:50:59.4333664Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/f141bd42-e6fd-4f3e-800c-9c23eddd1697)


---

### 2. Searched the `DeviceProcessEvents` Table

Next, based on our findings in the DeviceFileEvents table we checked the DeviceProcessEvents table for any processes with the string "tor-browser-windows-x86_64-portable-14.5.1.exe  /S" in the ProcessCommandLine field.
We discovered at Timestamp of  2025-04-30T05:55:19.3436207Z the file was ran from the Downloads folder using a command that triggered a silent installation:

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "tony-mde-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath

```
![image](https://github.com/user-attachments/assets/36c75bc2-8145-4055-8d9c-74d08651cced)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Next, we searched the DeviceFileEvents table to verify if the user open the tor browser. We found evidence at 2025-04-30T05:55:57.9558248Z. We also found the file “firefox.exe” was opened. Query used is the following:

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "tony-mde-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine

```
![image](https://github.com/user-attachments/assets/0bcafef7-8e72-4a00-905b-69b458dd32c0)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Next, we searched the DeviceNetworkEvents to verify if the user navigated websites using the Tor Browser. We searched the following common tor browser ports for any activity(9001, 9030, 9040, 9050, 9051, 9150).
We found the user established a connection using port 9001 to remote IP-73.61.87.62 at 2025-04-30T05:56:04.6413394Z. We have verified the user was browsing web pages using the tor browser.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "tony-mde-lab"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
, InitiatingProcessFolderPath
| order by Timestamp desc

```
![image](https://github.com/user-attachments/assets/a67df9e2-2802-4403-bbc7-6bb0503a79e8)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-30T05:50:59.4333664Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\tony-vm1982\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-30T05:55:19.3436207Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe /S`
- **File Path:** `C:\Users\tony-vm1982\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-30T05:55:57.9558248Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\tony-vm1982\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-30T05:56:04.6413394Z`
- **Event:** A network connection to IP `73.61.87.62` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\tony-vm1982\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-30T05:56:25.019564Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
