<#
.SYNOPSIS
    Nessus script
.DESCRIPTION
    Script to download single nessusreport(s) or in bulk and parse through them all.
.PARAMETER Get-NessusReports
    [-SelectScans] [-Format [csv|html|pdf](Default:csv)]
.PARAMETER NessusQuery
     [-WindowsPatch] [-Vulnerabilities] [-CVEScore <int32>] [-CVE <CVE>] [-Risk [Critical|High|Medium|Low|None]]
     [-HostName <Hostname>] [-Date <string>] [-Sort [Host|Name|Title...](Default:'CVSS v2.0 Base Score')]
.PARAMETER Nessus-Diff
    None
.PARAMETER Export-Nessusreports
    [-Path <path> [Default($HOME)]]
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    Version:        1.0
    Author:         Trond Weiseth
    Creation Date:  29.08.2022
    Purpose/Change: Initial script development
.EXAMPLE
    None
#>

# Setting variable for scipt path
$Global:scriptpath = $PSScriptRoot

Function Get-NessusReports {
    param
    (
        [Parameter(Mandatory=$false)]
        [switch]$List,

        [Parameter(Mandatory=$false)]
        [switch]$SelectScans,

        [Parameter(Mandatory=$false)]
        [validateset('csv','html')]
        [string]$Format = 'csv',

        [Parameter(Mandatory=$false)]
        [string]$ServerName = 'nessusserver.net',

        [Parameter(Mandatory=$false)]
        [validateset('vuln_by_host','vuln_hosts_summary','vuln_by_plugin','remediations')]
        [string]$Chapter = 'vuln_hosts_summary'
    )

    if (!(Test-Path $scriptpath\key.txt) -or !(Test-Path $scriptpath\secret.txt)) {
        Write-Host -ForegroundColor Red -BackgroundColor Black "Missing Nessus API keys! Run Add-NessusAPIkeys to add new pair."
        break
    }

# Disable ssl validation
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12


    # Global parameters
    $Global:FileFormat = $Format
    $Global:Base_URL   = "https://${ServerName}:8834"
    $Global:BasePath   = "$env:HOMEPATH\NessusReports"
    $Global:path       = "$BasePath\CurrentNessusScan"
    $Global:prevpath   = "$BasePath\PreviousNessusScan"

    # Nessus Authentication
    $AccessKey = $($key = get-content $scriptpath\key.txt | ConvertTo-SecureString ; [pscredential]::new('user',$key).GetNetworkCredential().Password)
    $SecretKey = $($secret = get-content $scriptpath\secret.txt | ConvertTo-SecureString ; [pscredential]::new('user',$secret).GetNetworkCredential().Password)

    # File structuring for diff comparison
    if (!$List -and $Format -ne 'html') {
        if (!(Test-Path $BasePath)) {[void](New-Item -Path $HOME -Name NessusReports -ItemType Directory)}
        if (!(Test-Path $BasePath\CurrentNessusScan)) {[void](New-Item -Path $BasePath -Name CurrentNessusScan -ItemType Directory)}
        if (!(Test-Path $BasePath\PreviousNessusScan)) {[void](New-Item -Path $BasePath -Name PreviousNessusScan -ItemType Directory)}
        [void](Remove-Item -Path $BasePath\PreviousNessusScan\* -Force -Recurse)
        [void](Move-Item $BasePath\CurrentNessusScan\* -Destination $BasePath\PreviousNessusScan -Force)
    }

    # Fetching Nessus scan(s)
    function scans {
        # Parameters
        $scans = @{
            "Uri"     = "$Base_URL/scans"
            "Method"  = "GET"
            "Headers" = @{
                "Accept" = "application/json"
                "Content-Type" = "application/json"
                "X-ApiKeys" = "accessKey=$($AccessKey); secretKey=$($SecretKey)"

            }
        }
        try {
            $scansres = Invoke-WebRequest @scans -ErrorAction Stop
            while ($null -eq $scansres) {Start-Sleep 1}
            $Json = $scansres | ConvertFrom-Json
            if ($SelectScans) {
                $Json.scans | Select-Object folder_id,name,status,id | Where-Object {$_.status -ne 'empty'} | Out-GridView -PassThru
            }
            else {
                $Json.scans | Select-Object folder_id,name,status,id | Where-Object {$_.status -ne 'empty'}
            }
        }
        catch {
            if ($Error[0] -imatch 'Invalid Credentials') {
                Write-Host -ForegroundColor Red -BackgroundColor Black "Wrong credentials! Run Add-NessusAPIkeys to generate new key pair"
            }
            else {
                Write-Output $Error[0]
            }
        }
    }

    # Exporting Nessus scan(s)
    function export {
        # Parameters
        $BodyParams = @{
            "format"="$FileFormat"
            "chapters"="$Chapter"
            } | ConvertTo-Json
        $export = @{
            "Uri"     = "$Base_URL/scans/$ScanID/export"
            "Method"  = "POST"
            "Headers" = @{
                "format" = "csv"
                "Accept" = "application/json"
                "Content-Type" = "application/json"
                "X-ApiKeys" = "accessKey=$($AccessKey); secretKey=$($SecretKey)"
            }
        }
        $exportres = Invoke-WebRequest @export -Body $BodyParams
        $Json = $exportres | ConvertFrom-Json
        $Global:FileID = $Json.file
    }

    # Downloads Nessus scan(s)
    function download {
        $download = @{
            "Uri"     = "$Base_URL/scans/$ScanID/export/$FileID/download"
            "Method"  = "GET"
            "Headers" = @{
                "Accept" = "application/octet-stream"
                "X-ApiKeys" = "accessKey=$($AccessKey); secretKey=$($SecretKey)"
            }
        }
        try {
            $download = Invoke-WebRequest @download -ErrorAction Stop
            $content = [System.Net.Mime.ContentDisposition]::new($download.Headers["Content-Disposition"])
            $fileName = $content.FileName
            $fullPath = Join-Path -Path $path -ChildPath $fileName
            $file = [System.IO.FileStream]::new($fullPath, [System.IO.FileMode]::Create)
            $file.Write($download.Content, 0, $download.RawContentLength)
            $file.Close()
        }
        catch {
            if ($error[0] -imatch "Report is still being generated") {Start-Sleep 1} else {$error[0]}
            download
        }
    }

    # Main execution
    if ($list) {
        scans
    }
    else {
        Write-Host -ForegroundColor Yellow "Downloading report(s)..."
        foreach ($Global:ScanID in (scans).id) {
            export
            download
        }
        Write-Host -ForegroundColor Green "Done! Reports are saved in $path"
        Write-Host -ForegroundColor Green "Run Nessus-Diff to see if there is any changes since last download."
    }
}

# Importing downloaded nessus scan(s) to funtion Nessusreport
Function Import-NessusReports {
    param
    ([switch]$Previous)
    $path = "$HOME\NessusReports\CurrentNessusScan"
    $prevpath = "$HOME\NessusReports\PreviousNessusScan"
    if($Previous) {$Global:NessusReports = Import-Csv -Path $prevpath (Get-ChildItem -Path $prevpath -Filter '*.csv').FullName}
    else {$Global:NessusReports = Import-Csv -Path (Get-ChildItem -Path $path -Filter '*.csv').FullName}
    Write-Host -ForegroundColor Cyan 'Nessusreports imported to function Nessusreport'
}

# Output nessusreport(s)
Function Nessusreport {
    if (!$NessusReports) {Import-NessusReports}
    Write-Output $NessusReports
}

Function NessusQuery {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [String]$CVEScore,

        [Parameter()]
        [String]$CVE,

        [Parameter()]
        [validateset('Critical','High','Medium','Low','None')]
        [String]$Risk,

        [Parameter()]
        [String]$HostName,

        [Parameter()]
        [String]$Date,

        [Parameter()]
        [String]$Name,

        [Parameter()]
        [String]$Exclude = '!#¤%&/()=',

        [Parameter()]
        [validateset('Host','Name','Title','risk','CVE','CVSS v2.0 Base Score')]
        [String]$Sort = 'CVSS v2.0 Base Score'
    )

    $res = Nessusreport | 
    Where-Object {$_.name -imatch "$Date" -and $_.host -imatch $HostName -and $_.name -imatch "$Name" -and $_.'CVSS v2.0 Base Score' -gt "$CVEScore" -and $_.cve -imatch $CVE -and $_.risk -imatch $Risk -and $_ -notmatch "$Exclude"}
    $res | Select-Object Host,Name,Title,CVE,'CVSS v2.0 Base Score',risk -Unique | Sort-Object $sort -Descending
}

# Comparing previous downloaded report(s) with last.
Function Nessus-Diff {
    $Current = Import-Csv -Path (Get-ChildItem -Path $HOME\NessusReports\CurrentNessusScan -Filter '*.csv').FullName
    $Previous = Import-Csv -Path (Get-ChildItem -Path $HOME\NessusReports\PreviousNessusScan -Filter '*.csv').FullName
    $diff = Compare-Object -ReferenceObject $Previous -DifferenceObject $Current -Property Host,Name,Title,'plugin id',CVE,'CVSS v2.0 Base Score',port,protocol,risk | Sort-Object Host,'Plugin ID',Name | Format-Table * -AutoSize
    if ($diff) {
        Write-Host -ForegroundColor Yellow -BackgroundColor Black "Previous scan(s) to the left & current scan(s) to the rigth"
        Write-Output $diff
    }
    else {
        Write-Host -ForegroundColor Yellow -BackgroundColor Black "No difference from last download."
    }
}

# Adding nessus API keys for the script to use
Function Add-NessusAPIkeys {
    $key = Read-Host -Prompt "Accesskey" -AsSecureString
    $key | ConvertFrom-SecureString > $scriptpath\key.txt
    $secret = Read-Host -Prompt "Secret" -AsSecureString
    $secret | ConvertFrom-SecureString > $scriptpath\secret.txt
}

# Exporting all nessus reports in to one single CSV file.
Function Export-Nessusreports {
    param([string]$Path = "$HOME")
    $date = get-date -Format "dd_MM_yyyy"
    if (!$NessusReports) {Import-NessusReports}
    $NessusReports | Export-Csv $Path\fullreport_$date.csv
}
