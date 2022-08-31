# Nessus_report_downloader_PowerShell
Powershell script to download and parse through nessus reports

A short script to bulk download nessus reports and parse through them with PowerShell.
Remember to generate an API key for the user that is going to be used for this task.


# Syntax
    
    # Download nessus scans (if parameter switch -SelectScans is not present, it will download all scans available that is not empty)
    # If parameter -Format is not present it defaults to CSV
    # Modify the -ServerName parameter  to set a default nessus host instead of using the parameter.
    
        Get-NessusReports
            [-List] [-Folder <int32>] [-SelectScans] [-Format [csv|html](Default:csv)] [-ServerName <nessusserver>]
    
    # PS! Only CSV. Collects all CSV reports available in the folder and writes it to console and makes them parsable with powershell
    
        NessusQuery 
            [-WindowsPatch] [-Vulnerabilities] [-CVEScore <int32>] [-CVE <CVE>] [-Risk [Critical|High|Medium|Low|None]]
            [-HostName <Hostname>] [-Date <string>] [-Sort [Host|Name|Title...](Default:'CVSS v2.0 Base Score')] [-Exclude <string>]
               
    # Get differences between current reports and last reports
    
        Nessus-Diff
    
    # Exports all nessus reports in to one signle CSV
    
        Export-Nessusreports
            [-Path <path> [Default($HOME)]]
    
    # Add API keys. It generates key files in the script location that the script use. (keys are encrypted to the user adding them)
    
        Add-NessusAPIkeys
