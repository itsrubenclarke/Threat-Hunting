# Threat Event (Unauthorised Software Download)

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Downloaded the outdated version of Apache 2.4.39 from the official Apache archives to the local machine: `wget https://archive.apache.org/dist/httpd/httpd-2.4.39.tar.gz`

2. Install the outdated software silently:
`tar -xzvf httpd-2.4.39.tar.gz
cd httpd-2.4.39
./configure --prefix=/usr/local/apache2
make
sudo make install`

3. Executed the Outdated Software:
- Started the Apache service to verify that it was functioning properly using:
`sudo /usr/local/apache2/bin/apachectl start`

4. Verified the Apache service status and verified that it was working by accessing the local server and reviewing the logs:
`ps aux | grep apache2
tail -f /usr/local/apache2/logs/access_log`

## Tables Used to Detect IoCs:

| **Parameter Name**     | **Info** | **Description**                                                                                                             
|------------------------|----------|--------------------------------------------------------------------------------------------------------------------------|
| DeviceProcessEvents       | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)       | Used to detect execution of Trojanized commands, privilege escalation attempts, and service creation.                                           |
| DeviceFileEvents    | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)       | Used to detect the creation and modification of system files, including systemd services and backdoor binaries.                                                       |
| DeviceLogonEvents    | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) | Used to detect unauthorised remote logins or unusual authentication patterns.                     |

---

## Related Queries:

```kql
// Detect execution of a Trojanized administrative command
DeviceProcessEvents
| where ProcessCommandLine contains "ls"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect execution of a SUID backdoor shell
DeviceProcessEvents
| where ProcessCommandLine contains "rootbash"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect potential unauthorised logins
DeviceLogonEvents
| where AccountName contains "root"
| where LogonType in ("RemoteInteractive", "Interactive")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
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
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 26, 2025`  | `Ruben Clarke` 
