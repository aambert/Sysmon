function Install-Sysmon {
<#
.Synopsis
   Install Sysmon and Winlogbeat remotely

.Example 
   Invoke-Command -ComputerName COMPUTERNAME -Credential DOMAIN/user -ScriptBlock { powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/apihlak/Sysmon/master/Install-Sysmon.ps1');Install-Sysmon" }

#>
    [CmdletBinding()]
    [Alias()]
    Param (
    )

    Begin {
    }
    Process {

            $Path_sysmon = "$env:SystemDrive\ProgramData\sysmon"
            $Config_sysmon = "https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml"
            $ExeDownload64_sysmon = "https://live.sysinternals.com/Sysmon64.exe"
            $ExeDownload32_sysmon = "https://live.sysinternals.com/Sysmon.exe"

            $Path_winlog = "$env:SystemDrive\ProgramData\winlogbeat"                   
            $Config_winlog = "https://raw.githubusercontent.com/apihlak/Sysmon/master/winlogbeat.yml"
            $ExeDownload64_winlog = "https://github.com/apihlak/Sysmon/raw/master/winlogbeat64.exe"
            $ExeDownload32_winlog = "https://github.com/apihlak/Sysmon/raw/master/winlogbeat.exe"

        #Install sysmon and hide service

            New-Item -Path $Path_sysmon -ItemType Directory
            Set-Location -Path "$Path_sysmon"

            (New-Object System.Net.WebClient).DownloadFile("$Config_sysmon","$Path_sysmon\sysmonconfig-export.xml")

            if ( ((Get-WmiObject Win32_OperatingSystem).OSArchitecture) -eq "64-bit") {
                (New-Object System.Net.WebClient).DownloadFile("$ExeDownload64_sysmon","$Path_sysmon\sysmon64.exe")
                & .\sysmon64.exe -accepteula -i sysmonconfig-export.xml
            }
            else {
                (New-Object System.Net.WebClient).DownloadFile("$ExeDownload32_sysmon","$Path_sysmon\sysmon.exe")
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

            (New-Object System.Net.WebClient).DownloadFile("$Config_winlog","$Path_winlog\winlogbeat.yml")

            if ( ((Get-WmiObject Win32_OperatingSystem).OSArchitecture) -eq "64-bit") {
                (New-Object System.Net.WebClient).DownloadFile("$ExeDownload64_winlog","$Path_sysmon\winlogbeat.exe")
            }
            else {
                (New-Object System.Net.WebClient).DownloadFile("$ExeDownload64_winlog","$Path_sysmon\winlogbeat.exe")
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

      }
    End {
        }
    }
