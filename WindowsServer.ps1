##############################################################
# Kizio Developer Programe Install Script                    #
##############################################################
# Windows 10 Custom Installation Script, Using Powershell    #
##############################################################
# Instructions #
#############################################  
# 1) Run PowerShell as administrator        #
# 2) Type Set-ExecutionPolicy Unrestricted  # 
# 3) Run the script by typing ./install.ps1 #
#############################################

param (
    [string]$password = "",
    [bool]$nochecks = $false
)
function installBoxStarter() {
    try {
        Add-Type @"
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
    }
    catch {
        Write-Debug "Failed to add new type"
    }  
    try {
        $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    }
    catch {
        Write-Debug "Failed to find SSL type...1"
    }  
    try {
        $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls'
    }
    catch {
        Write-Debug "Failed to find SSL type...2"
    }  
    $prevSecProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $prevCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy  
    Write-Host "[ * ] Installing Boxstarter"
    # Become overly trusting
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy  
    # download and instal boxstarter
    iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force  
    # Restore previous trust settings for this PowerShell session
    # Note: SSL certs trusted from installing BoxStarter above will be trusted for the remaining PS session
    [System.Net.ServicePointManager]::SecurityProtocol = $prevSecProtocol
    [System.Net.ServicePointManager]::CertificatePolicy = $prevCertPolicy
    return $true
}

# Check to make sure script is run as administrator
Write-Host "[+] Checking if script is running as administrator.."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`t[ERR] Please run this script as administrator`n" -ForegroundColor Red
    Read-Host  "Press any key to continue"
    exit
}
else {
    Start-Sleep -Milliseconds 500
    Write-Host "`tRunning " -ForegroundColor Magenta -NoNewLine
    Start-Sleep -Milliseconds 500
    Write-Host "as " -ForegroundColor Cyan -NoNewLine
    Start-Sleep -Milliseconds 500
    Write-Host "administrator " -ForegroundColor Green
    Start-Sleep -Milliseconds 500
}

if ($nochecks -eq $false) {
  
    # Check to make sure host is supported
    Write-Host "[+] Checking to make sure Operating System is compatible"
    if (-Not (((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") -or ([System.Environment]::OSVersion.Version.Major -eq 10))) {
        Write-Host "`t[ERR] $((Get-WmiObject -class Win32_OperatingSystem).Caption) is not supported, please use Windows 7 Service Pack 1 or Windows 10" -ForegroundColor Red
        exit 
    }
    else {
        Write-Host "`t$((Get-WmiObject -class Win32_OperatingSystem).Caption) supported" -ForegroundColor Green
    }

    # Check to make sure host has been updated
    Write-Host "[+] Checking if host has been configured with updates"
    if (-Not (get-hotfix | where { (Get-Date($_.InstalledOn)) -gt (get-date).adddays(-30) })) {
        Write-Host "`t[ERR] This machine has not been updated in the last 30 days, please run Windows Updates to continue`n" -ForegroundColor Red
        Read-Host  "Press any key to continue"
        exit
    }
    else {
        Write-Host "`tupdates appear to be in order" -ForegroundColor Green
    }

    #Check to make sure host has enough disk space
    Write-Host "[+] Checking if host has enough disk space"
    $disk = Get-PSDrive C
    Start-Sleep -Seconds 1
    if (-Not (($disk.used + $disk.free) / 1GB -gt 80)) {
        Write-Host "`t[ERR] This install requires a minimum of at least 80 GB on the hard drive, please increase the hard drive space to continue`n" -ForegroundColor Red
        Read-Host "Press any key to continue"
        exit
    }
    else {
        Write-Host "`t> 80 GB hard drive. looks good" -ForegroundColor Green
    }

    # Get user credentials for autologin during reboots
    Write-Host "[ * ] Getting user credentials ..."
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True

    if ([string]::IsNullOrEmpty($password)) {
        $cred = Get-Credential $env:username
    }
    else {
        $spasswd = ConvertTo-SecureString -String $password -AsPlainText -Force
        $cred = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $env:username, $spasswd
    }
    # TO DO - Verify credentials before continuing

    # Install Boxstarter
    Write-Host "[ * ] Installing Boxstarter"
    try {
        iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
    }
    catch {
        $rc = installBoxStarter
        if (-Not $rc) {
            Write-Host "[ERR] Failed to install BoxStarter. Internet dropped out?"
            Read-Host  "      Press ANY key to continue..."
            exit
        }
    }

    # Boxstarter options
    $Boxstarter.RebootOk = $true    # Allow reboots?
    $Boxstarter.NoPassword = $false # Is this a machine with no login password?
    $Boxstarter.AutoLogin = $true # Save my password securely and auto-login after a reboot
}

# --- Windows Desktop Experience Settings  ---
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar

tzutil /s "AUS Eastern Standard Time"

# Show Task Manager details - Applicable to 1607 and later - Although this functionality exist even in earlier versions, the Task Manager's behavior is different there and is not compatible with this tweak
Function ShowTaskManagerDetails {
    Write-Output "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
}

# Show file operations details
Function ShowFileOperationsDetails {
    Write-Output "Showing file operations details..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

# Better File Explorer
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1		
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1		
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name MMTaskbarMode -Value 2

# Install Custom Software
Write-Host "[ * ] Installing Software"

#--- Tools ---
choco install nuget.commandline --pre -y
choco install powershell-core -y
choco install git -params '"/GitAndUnixToolsOnPath /WindowsTerminal"' -y
choco install hyper -y

choco install chocolatey -y
choco install googlechrome -y
choco install glasswire -y
choco install firefox -y
choco install malwarebytes -y
choco install adwcleaner -y
choco install glasswire -y
choco install slack -y
choco install microsoft-teams -y
choco install filezilla -y
choco install qbittorrent -y
choco install transmission -y
choco install ccleaner -y
choco install windirstat -y
choco install imgburn -y
choco install winrar -y
choco install winscp -y
choco install putty.install -y
choco install 7zip.install -y
choco install steam -y
choco install greenshot -y
choco install mysql.workbench -y
choco install vmwarevsphereclient -y
choco install intel-xtu -y
choco install coretemp -y
choco install cpu-z.install -y
choco install kodi -y
choco install dropbox -y
choco install google-drive-file-stream -y
choco install megasync -y
choco install blender -y
choco install vlc -y
choco install itunes -y
choco install handbrake.install -y
choco install openvpn -y
choco install office365business -y
choco install thunderbird -y
choco install vmwareworkstation -y
Choco install vmware-workstation-player -y
choco install virtualbox -y
choco install docker -y
Install-Module -Name posh-docker -Force
choco install kubernetes-cli -y
choco install rufus -y
choco install win32diskimager.install -y
choco install unetbootin -y
choco install yumi-uefi -y
choco install bitnami-xampp -y
choco install obs-studio -y
choco install fraps -y
choco install wireshark -y
choco install nmap -y
choco install cheatengine -y
choco install cura-new -y
choco install vscode -y
choco install brackets -y
choco install atom -y
choco install sublimetext3 -y
choco install notepadplusplus.install -y
choco install arduino -y
choco install postman -y
choco install gitlab-runner -y
choco install git.install -y
choco install sourcetree -y
choco install github -y
choco install gitkraken -y
choco install intellijidea-ultimate -y
choco install webstorm -y
choco install phpstorm -y
choco install datagrip -y
choco install jetbrainstoolbox -y
choco install pycharm -y
choco install rubymine -y
choco install goland -y
choco install cmder -y
choco install vagrant -y
choco install vagrant-vmware-utility -y

Write-Host "[ * ] Done"

if (Test-PendingReboot) { Invoke-Reboot }