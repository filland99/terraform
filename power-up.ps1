#Set Windows Firewall to OFF
set-NetFirewallProfile -All -Enabled False

#enable remote desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

#Create User and Add to Local Administrator Group
$password = ConvertTo-SecureString 'fiVvH_7HCCYZvXed' -AsPlainText -Force
new-localuser -Name admin -Password $password
add-localgroupmember -Group administrators -Member admin
 
#Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
#New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
#Get-Service sshd | Set-Service -StartupType Automatic
#Start-Service sshd
 
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
#choco install cygwin cyg-get -y
#cyg-get openssh python38 python38-pip python38-devel libssl-devel libffi-devel gcc-g++
choco install 7zip -y
# This script installs IIS and the features required to
# run West Wind Web Connection.
#
# * Make sure you run this script from a Powershel Admin Prompt!
# * Make sure Powershell Execution Policy is bypassed to run these scripts:
# * YOU MAY HAVE TO RUN THIS COMMAND PRIOR TO RUNNING THIS SCRIPT!
Set-ExecutionPolicy Bypass -Scope Process

# To list all Windows Features: dism /online /Get-Features
# Get-WindowsOptionalFeature -Online 
# LIST All IIS FEATURES: 
# Get-WindowsOptionalFeature -Online | where FeatureName -like 'IIS-*'

#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment

#Enable-WindowsOptionalFeature -online -FeatureName NetFx4Extended-ASPNET45
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45

#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HealthAndDiagnostics
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-LoggingLibraries
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestMonitor
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpTracing
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-Security
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-Performance
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerManagementTools
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-IIS6ManagementCompatibility
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-Metabase
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-StaticContent
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic

#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45

# If you need classic ASP (not recommended)
#Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASP


# The following optional components require 
# Chocolatey OR Web Platform Installer to install

#Set timezone Europe/Brussels
Set-TimeZone –Name "Romance Standard Time"

# Install UrlRewrite Module for Extensionless Urls (optional)
###  & "C:\Program Files\Microsoft\Web Platform Installer\WebpiCmd-x64.exe" /install /Products:UrlRewrite2 /AcceptEULA /SuppressPostFinish
#choco install urlrewrite -y
    
# Install WebDeploy for Deploying to IIS (optional)
### & "C:\Program Files\Microsoft\Web Platform Installer\WebpiCmd-x64.exe" /install /Products:WDeployNoSMO /AcceptEULA /SuppressPostFinish
# choco install webdeploy -y

# Disable Loopback Check on a Server - to get around no local Logins on Windows Server
# New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa -Name "DisableLoopbackCheck" -Value "1" -PropertyType dword
#Disabe Windows updates
sc.exe config wuauserv start= disabled
sc.exe stop wuauserv
sc.exe start wuauserv
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
#format all disks to all size
Get-Disk | Where partitionstyle -eq 'raw' | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS
