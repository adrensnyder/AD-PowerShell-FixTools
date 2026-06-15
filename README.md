# AD PowerShell FixTools
> This project is provided **AS IS**, without warranty of any kind. Use these scripts at your own risk and always review the code before running it in a production environment.  
> The author is not responsible for service outages, data loss, broken domains, failed replications, lost SYSVOL content, angry users, unexpected side effects, thermonuclear war, or any other consequence caused directly or indirectly by the use or misuse of these tools.

A practical collection of PowerShell tools for checking, troubleshooting, and fixing common Active Directory, Domain Controller, Group Policy, SYSVOL, DFSR, and Windows Domain issues.  
These scripts are intended for experienced Windows Server and Active Directory administrators.  

## Available scripts
| Script | Description |
|---|---|
| `Invoke-SysvolAuthoritativeSingleDC.ps1` | Checks and fixes supported DFSR SYSVOL issues on a single remaining Domain Controller, including Content Freshness failures and stale/orphaned Domain Controller references. |

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
Run scripts only in scenarios that match their documented purpose.  
Review the output carefully before approving or starting any fix operation.  

## Notes
Some scripts may perform only checks. Others may also provide repair actions.  

The exact behavior, parameters, logs, requirements, and safety gates are documented inside each script and shown with `--help`.

