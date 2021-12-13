<#
Name: Log4jScan.ps1
Author: Joshua Romkes
Forked From: https://github.com/N-able/ScriptsAndAutomationPolicies/blob/master/Vulnerability%20-%20CVE-2021-44228%20(Log4j)/get-log4jrcevulnerability.ps1
Purpose: Detection of jar files vulnerable to log4j RCE vulnerability (CVE-2021-44228)
Utilizing JNDILookup detection method posted to https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b with some slight modifications to make it more RMM friendly

Modified for RMM Check with needed returns for dashboard
#>

function Clear-FileScan {
    if ($robocopycsv -eq $true) {
        start-sleep 5
        remove-item "$env:temp\log4jfilescan.csv" -force
    }
}

$Version = "0.1.6" # 13th December 2021
Write-Host "get-log4jrcevulnerability $version" -foregroundcolor Green
$robocopycsv = $null


try {
    Write-Host "Attempting to use Robocopy to scan for JAR files.."
    $robocopyexitcode = (start-process robocopy  -argumentlist "c:\ c:\DOESNOTEXIST *.jar /S /XJ /L /FP /NS /NC /NDL /NJH /NJS /r:0 /w:0 /LOG:$env:temp\log4jfilescan.csv" -wait).exitcode
    if ($? -eq $True) {
        $robocopycsv = $true
        $log4jfilescan = import-csv "$env:temp\log4jfilescan.csv" -header FilePath        
        $log4jfilenames = $log4jfilescan
    }
}
catch {
    Write-Host "WARNING: Robocopy Scan failed. Falling back to GCI.."
    $log4jfilescan = get-childitem 'C:\' -rec -force -include *.jar -ea 0
    if ($? -eq $true) {
        $log4jfilenames = ($log4jfilescan).fullname 
    }
    else { #Scan Failed
        $log4jfiles = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: Unable to scan files"
        $log4jvulnerable = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: Unable to scan files"
        $log4jvulnerablefilecount = '-1'
        Write-Host $log4jfiles -ForegroundColor Red
        Exit 1 #Tell RMM The Check Faileds
    }
}

#No Jar Files Found
if ($log4jfilescan -eq $null) {
    $log4jfiles = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') OK - No JAR Files were found on this device"
    $log4jvulnerable = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') OK - No JAR Files were found on this device"
    $log4jvulnerablefilecount = '0'
    Clear-FileScan #Cleanup All CSV Files If Generated From Robocopy Tool
    Write-Host "$log4jvulnerable" -ForegroundColor Green
}
#JAR Files Found, Check For Vulnerable Class
else {
    Write-Host "Determining whether any of the $(($log4jfilenames).count) found .jar files are vulnerable to CVE-2021-44228 due to being capable of JNDI lookups..."
    if ($robocopycsv -eq $true) {
        $log4jvulnerablefiles = $log4jfilescan | foreach-object { select-string "JndiLookup.class" $_.FilePath } | select-object -exp Path | sort-object -unique
    }
    else {
        $log4jvulnerablefiles = $log4jfilescan | foreach-object { select-string "JndiLookup.class" $_ } | select-object -exp Path | sort-object -unique
    }
    $log4jvulnerablefilecount = ($log4jvulnerablefiles).count
    if ($log4jvulnerablefiles -eq $null) {
        $log4jvulnerable = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') OK - 0 Vulnerable JAR files were found"
        write-host "Log4J CVE-2021-44228 Vulnerable Files:`n$log4jvulnerable" -ForegroundColor Green
        Clear-FileScan #Cleanup All CSV Files If Generated From Robocopy Tool
        exit 0 #Tell RMM The Check Passed
    }
    else {
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') WARNING - $log4jvulnerablefilecount Vulnerable JAR file(s) were found" -foregroundcolor Red
        write-host "Log4J CVE-2021-44228 Vulnerable Files:`n$log4jvulnerablefiles" -ForegroundColor Red
        $log4jvulnerable = $log4jvulnerablefiles -join '<br>'
        Clear-FileScan #Cleanup All CSV Files If Generated From Robocopy Tool
        exit 1 #Tell RMM The Check Failed
    }
    # Write-Host "Log4j Files found:`n$log4jfiles"
    $log4jfiles = $log4jfilenames -join '<br>'
}


