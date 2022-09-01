# Nessus_report_downloader_PowerShell
Powershell script to download and parse through nessus reports

A short script to bulk download nessus reports and parse through them with PowerShell.
Remember to generate an API key for the user that is going to be used for this task.

# Examples
    -To view a list over available scans completed
        $> Get-NessusReports -list
        
    -To download all reports from scan(s) in folder 3
        $> Get-NessusReports -Folder 3
        
    -Select individual scans to download reports from in out-gridview
        $> Get-NessusReports -SelectScans
        
    -Addin new API keys for nessus server(s)
        $> Get-NessusReports -AddAPIkeys
        
    -Parsing through all nessus reports for any CVE score grater than 7.9 and a risk of Critical with august in it's name for missing windows patches.
        $> NessusQuery -CVEScore 7.9 -Risk Critical -Name August
        
    -Comparing previous downloaded reports with a current to see any changes made. In this case only added changes.
        $> Nessus-Diff -Added
        
    -Exporting all downloaded CVS reports in to one single CVS. Handy for exporting to excel or sending a complete report.
        $> Export-Nessusreports -Path $HOME\Downloads


# Syntax
    
    # Download nessus scans (if parameter switch -SelectScans is not present, it will download all scans available that is not empty)
    # If parameter -Format is not present it defaults to CSV
    # Modify the -ServerName parameter  to set a default nessus host instead of using the parameter.
    
        Get-NessusReports
            [-List] [-AddAPIkeys] [-Folder <int32>] [-SelectScans] [-Format [csv|html](Default:csv)] [-ServerName <nessusserver>]
    
    # PS! Only CSV. Collects all CSV reports available in the folder and writes it to console and makes them parsable with powershell
    
        NessusQuery 
            [[-CVEScore] <string[]>] [[-CVE] <string[]>] [[-Risk] <string[]>] [[-HostName] <string[]>] [[-Description] <string[]>] [[-Name] <string[]>] 
            [[-PluginOutput] <string[]>] [[-Solution] <string[]>] [[-Synopsis] <string[]>] [[-Protocol] <string[]>] [[-PluginID] <string[]>] 
            [[-Exclude] <string[]>] [[-Sort] <string[]>] [-OutputFull]
               
    # Get differences between current reports and last reports
    
        Nessus-Diff [-Added] [-Removed]
    
    # Exports all nessus reports in to one signle CSV
    
        Export-Nessusreports
            [-Path <path> [Default($HOME)]]
