# AD PowerShell FixTools
> This project is provided **AS IS**, without warranty of any kind. Use these scripts at your own risk and always review the code before running it in a production environment.  
> The author is not responsible for service outages, data loss, broken domains, failed replications, lost SYSVOL content, angry users, unexpected side effects, thermonuclear war, or any other consequence caused directly or indirectly by the use or misuse of these tools.

A practical collection of PowerShell tools for checking, troubleshooting, and fixing common Active Directory, Domain Controller, Group Policy, SYSVOL, DFSR, and Windows Domain issues.  
These scripts are intended for experienced Windows Server and Active Directory administrators.  

## Available scripts
| Script | Description |
|---|---|
| `Invoke-SysvolAuthoritativeSingleDC.ps1` | Checks and fixes supported DFSR SYSVOL issues on a single remaining Domain Controller, including Content Freshness failures and stale/orphaned Domain Controller references. |
| `Invoke-SysvolAuthoritativeMultiDC.ps1` | **Experimental.** Checks and, when explicitly requested, performs a controlled authoritative DFSR SYSVOL re-initialization for domains with two or more reachable Domain Controllers. This script is not fully tested on real multi-DC environments. |

## Usage
Open an elevated PowerShell session and run the selected script with `--help`.  
```powershell
.\{script}.ps1 --help
```

If PowerShell script execution is blocked by the local execution policy, run it with a temporary bypass:  
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\{script}.ps1 --help
```

Each script provides its own help page with supported parameters, examples, safety notes, and a more complete explanation of what it does.  

## Before running any script

Read the script help first.  
Review the code before using it in production.  
Make sure you have a valid backup before running any operation that may change Active Directory, SYSVOL, DFSR, Group Policy, services, or system configuration.  
**For any operation that may change DFSR synchronization, SYSVOL, Active Directory metadata, Domain Controller services, or related configuration, it is strongly recommended to have an up-to-date image-level backup and/or System State backup of each affected Domain Controller before running the script. These backups are not created by the scripts.**    
**Any SYSVOL copy or backup created by a script is only a copy of SYSVOL content for that script workflow. It is not a full Domain Controller backup, not a System State backup, not an Active Directory backup, and not a complete rollback mechanism.**  
Run scripts only in scenarios that match their documented purpose.  
Review the output carefully before approving or starting any fix operation.  

## Notes
Some scripts may perform only checks. Others may also provide repair actions.  

The SYSVOL authoritative scripts may create SYSVOL content backups as part of their documented workflow, but they do not create image-level backups, System State backups, Active Directory backups, or full disaster-recovery restore points. Prepare those backups separately before using any repair action.

`Invoke-SysvolAuthoritativeMultiDC.ps1` is currently experimental and not fully tested because the author does not currently have access to multi-DC test systems. As stated in the general project disclaimer, review the code carefully and use it at your own risk.

The exact behavior, parameters, logs, requirements, and safety gates are documented inside each script and shown with `--help`.

