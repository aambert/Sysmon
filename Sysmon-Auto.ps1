$Path_sysmon = "$env:SystemDrive\ProgramData\sysmon"
$Config_sysmon = "\\linx\it\deploy\ALL\sysmon\sysmonconfig-export.xml"
$ExeDownload64_sysmon = "\\linx\it\deploy\ALL\sysmon\sysmon64.exe"
$ExeDownload32_sysmon = "\\linx\it\deploy\ALL\sysmon\sysmon.exe"

$Path_winlog = "$env:SystemDrive\ProgramData\winlogbeat"                   
$Config_winlog = "\\linx\it\deploy\ALL\winlogbeat\winlogbeat.yml"
$ExeDownload64_winlog = "\\linx\it\deploy\ALL\winlogbeat\winlogbeat64.exe"
$ExeDownload32_winlog = "\\linx\it\deploy\ALL\winlogbeat\winlogbeat.exe"

If (-not (Test-Path C:\ProgramData)) { New-Item -Path C:\ProgramData -ItemType Directory }

#Install sysmon and hide service    
    New-Item -Path $Path_sysmon -ItemType Directory
    Set-Location -Path "$Path_sysmon"

    Copy-Item -Path "$Config_sysmon" -Destination "$Path_sysmon\sysmonconfig-export.xml" -Force

    if ( ((Get-WmiObject Win32_OperatingSystem).OSArchitecture) -eq "64-bit") {
        Copy-Item -Path "$ExeDownload64_sysmon" -Destination "$Path_sysmon\sysmon64.exe" -Force
        & .\sysmon64.exe -accepteula -i sysmonconfig-export.xml
    }
    else {
        Copy-Item -Path "$ExeDownload32_sysmon" -Destination "$Path_sysmon\sysmon.exe" -Force
        & .\sysmon.exe -accepteula -i sysmonconfig-export.xml
    }

    Invoke-Command -ScriptBlock {
        sc.exe failure Sysmon actions= restart/10000/restart/10000// reset= 120
    }

    $sddlset =  Invoke-Command -ScriptBlock {
        sc.exe sdset Sysmon 'D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
    }


#Install winlogbeat and hide service
    
    New-Item -Path $Path_winlog -ItemType Directory
    Set-Location -Path "$Path_winlog"

    Copy-Item -Path "$Config_winlog" -Destination "$Path_winlog\winlogbeat.yml" -Force

    if ( ((Get-WmiObject Win32_OperatingSystem).OSArchitecture) -eq "64-bit") {
        Copy-Item -Path "$ExeDownload64_winlog" -Destination "$Path_winlog\winlogbeat.exe" -Force
    }
    else {
        Copy-Item -Path "$ExeDownload32_winlog" -Destination "$Path_winlog\winlogbeat.exe" -Force
    }

    if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
    	$service = Get-WmiObject -Class Win32_Service -Filter "name='winlogbeat'"
        $service.StopService()
        Start-Sleep -Seconds 1
        $service.delete()
    }

	New-Service -Name winlogbeat -DisplayName winlogbeat -BinaryPathName "`"$Path_winlog\\winlogbeat.exe`" -c `"$Path_winlog\\winlogbeat.yml`" -path.home `"$Path_winlog`" -path.data `"C:\\ProgramData\\winlogbeat`""
    Get-Service -Name winlogbeat | Start-Service

    Invoke-Command -ScriptBlock {
        sc.exe failure winlogbeat actions= restart/10000/restart/10000// reset= 120
    }

    $sddlset =  Invoke-Command -ScriptBlock {
        sc.exe sdset winlogbeat 'D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
    }

