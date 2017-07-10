function Install-Sysmon {
<#
.Synopsis
   Install Sysmon and Winlogbeat remotely

.Example 
   Invoke-Command -ComputerName COMPUTERNAME -ScriptBlock { powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/apihlak/Sysmon/master/Install-Sysmon.ps1');Install-Sysmon" }

#>
    [CmdletBinding()]
    Param (
       [Parameter(Mandatory=$false,       
               Position=0,       
               HelpMessage="Sysmon download path.")]     
       [Alias("PS")]     
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $Path_sysmon = "$env:SystemDrive\ProgramData\sysmon",     
     
       [Parameter(Mandatory=$false,      
               Position=1,       
               HelpMessage="Winlogbeat download path.")]     
       [Alias("PW")]     
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $Path_winlog = "$env:SystemDrive\ProgramData\winlogbeat",     
     
       [Parameter(Mandatory=$false,      
               Position=2,       
               HelpMessage="Sysmon configuration download path.")]       
       [Alias("CS")]     
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $Config_sysmon = "https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml",      
     
       [Parameter(Mandatory=$false,      
               Position=3,       
               HelpMessage="Winlogbeat configuration download path.")]       
       [Alias("CW")]     
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $Config_winlog = "https://raw.githubusercontent.com/apihlak/Sysmon/master/winlogbeat.yml",        
     
       [Parameter(Mandatory=$false,      
               Position=4,       
               HelpMessage="Sysmon 64 bit download path.")]      
       [Alias("ES6")]        
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $ExeDownload64_sysmon = "https://live.sysinternals.com/Sysmon64.exe",     
     
       [Parameter(Mandatory=$false,      
               Position=5,       
               HelpMessage="Winlogbeat 64 bit download path.")]      
       [Alias("EW6")]        
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $ExeDownload64_winlog= "https://github.com/apihlak/Sysmon/raw/master/winlogbeat64.exe",       
     
       [Parameter(Mandatory=$false,      
               Position=6,       
               HelpMessage="Sysmon 32 bit download path.")]      
       [Alias("ES3")]        
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $ExeDownload32_sysmon= "https://live.sysinternals.com/Sysmon.exe",        
     
       [Parameter(Mandatory=$false,      
               Position=7,       
               HelpMessage="Winlogbeat 32 bit download path.")]      
       [Alias("EW3")]        
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $ExeDownload32_winlog= "https://github.com/apihlak/Sysmon/raw/master/winlogbeat.exe"
    )

    Begin {
    }
    Process {

            If (!(Test-Path C:\ProgramData)) { New-Item -Path C:\ProgramData -ItemType Directory }
            
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

            Invoke-Command -ScriptBlock {
                sc.exe sdset Sysmon 'D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
            }

        #Install winlogbeat and hide service
            
            New-Item -Path $Path_winlog -ItemType Directory
            Set-Location -Path "$Path_winlog"

            (New-Object System.Net.WebClient).DownloadFile("$Config_winlog","$Path_winlog\winlogbeat.yml")

            if ( ((Get-WmiObject Win32_OperatingSystem).OSArchitecture) -eq "64-bit") {
                (New-Object System.Net.WebClient).DownloadFile("$ExeDownload64_winlog","$Path_winlog\winlogbeat.exe")
            }
            else {
                (New-Object System.Net.WebClient).DownloadFile("$ExeDownload64_winlog","$Path_winlog\winlogbeat.exe")
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

            Invoke-Command -ScriptBlock {
                sc.exe sdset winlogbeat 'D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
            }

      }
    End {
        }
    }

function Remove-Sysmon {
<#
.Synopsis
   Remove Sysmon and Winlogbeat remotely

.Example 
   Invoke-Command -ComputerName COMPUTERNAME -ScriptBlock { powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/apihlak/Sysmon/master/Install-Sysmon.ps1');Remove-Sysmon" }

#>
    [CmdletBinding()]
    Param (
       [Parameter(Mandatory=$false,       
               Position=0,       
               HelpMessage="Sysmon data path.")]     
       [Alias("PS")]     
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $Path_sysmon = "$env:SystemDrive\ProgramData\sysmon",     
     
       [Parameter(Mandatory=$false,      
               Position=1,       
               HelpMessage="Winlogbeat data path.")]     
       [Alias("PW")]     
       [ValidateNotNullOrEmpty()]        
       [string[]]        
       $Path_winlog = "$env:SystemDrive\ProgramData\winlogbeat"
    )

    Begin {
    }
    Process {
    
        #Remove sysmon

            Invoke-Command -ScriptBlock {
                sc.exe sdset Sysmon 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
            }        

            Set-Location -Path "$Path_sysmon"

            if (Get-Service sysmon -ErrorAction SilentlyContinue) {
              if ( ((Get-WmiObject Win32_OperatingSystem).OSArchitecture) -eq "64-bit") {
                  & .\sysmon64.exe -u
              }
              else {
                  & .\sysmon.exe -u
              }
            }

            Set-Location -Path "C:\ProgramData"
            Remove-Item -Recurse -Force $Path_sysmon

        #Remove winlogbeat
            
            Invoke-Command -ScriptBlock {
                sc.exe sdset winlogbeat 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)'
            }

            if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
              $service = Get-WmiObject -Class Win32_Service -Filter "name='winlogbeat'"
                $service.StopService()
                Start-Sleep -Seconds 1
                $service.delete()
            }

            Remove-Item -Recurse -Force $Path_winlog  

      }
    End {
        }
    }
