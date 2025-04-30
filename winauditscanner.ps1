<#
    WinAuditScanner v1.0
    Author: [NoWa-FTN]
    Description: Windows machine security audit script
    Objective: Quickly collect useful information for a local audit (reconnaissance, post-exploitation, light forensics)
#>

$reportPath = ".\Audit-$(hostname).html"
$reportTitle = "WinAuditScanner Report - $(hostname)"

# Create HTML header
$htmlHeader = @"
<html>
<head>
    <title>$reportTitle</title>
<style>
    body { 
        font-family: 'Arial', sans-serif; 
        background-color: #333; 
        color: #f8f8f8; 
        margin: 0; 
        padding: 0;
    }

    h1 { 
        color: #f8f8f8; 
        text-align: center; 
        margin-top: 20px; 
        margin-bottom: 20px;
        font-size: 2.5em; 
        text-transform: uppercase;
    }

    h2 { 
        color: #4CAF50; 
        margin-top: 20px; 
        margin-bottom: 20px; 
        font-size: 1.5em;
        text-align: center;
    }

    h2 {
        animation: fadeIn 1s ease-in-out;
    }

    @keyframes fadeIn {
        0% { opacity: 0; }
        100% { opacity: 1; }
    }

    table { 
        width: 100%; 
        border-collapse: collapse; 
        margin-top: 10px;
    }

    table, th, td { 
        border: 1px solid #555; 
        border-radius: 8px;
    }

    th { 
        background-color: #4CAF50; 
        color: white; 
        padding: 10px; 
        text-align: center;
    }

    td { 
        padding: 8px; 
        text-align: center;
    }

    pre { 
        background-color: #444; 
        padding: 10px; 
        border-radius: 5px; 
        overflow-x: auto; 
        margin: 0;
    }

    .section { 
        margin-top: 20px; 
        padding: 20px; 
        border-radius: 10px; 
        background-color: #222; 
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        transition: all 0.3s ease-in-out;
    }

    .section:hover {
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
    }

    .footer { 
        text-align: center; 
        font-size: 14px; 
        color: #777; 
        margin-top: 30px; 
        margin-bottom: 20px;
    }

    .highlight { 
        font-weight: bold; 
        color: #e74c3c; 
        animation: pulse 1.5s infinite alternate;
    }

    @keyframes pulse {
        0% { opacity: 0.8; }
        50% { opacity: 1; }
        100% { opacity: 0.8; }
    }
</style>

</head>
<body>
    <h1>$reportTitle</h1>
    <h2>Audit performed on $(Get-Date)</h2>
"@

# Add audit data to the HTML report
$htmlContent = ""

# System Information
$htmlContent += "<div class='section'><h2>System Information</h2><pre>$(Get-ComputerInfo | Select-Object OSName, OSArchitecture, CsName, WindowsVersion, WindowsBuildLabEx, BiosManufacturer, BiosVersion | Out-String)</pre></div>"

# Local Users
$htmlContent += "<div class='section'><h2>Local Users</h2><pre>$(Get-LocalUser | Select Name, Enabled, LastLogon | Out-String)</pre></div>"

# Administrators Group Members
$htmlContent += "<div class='section'><h2>Members of the 'Administrators' Group</h2><pre>$(Get-LocalGroupMember -Group 'Administrators' | Select Name, ObjectClass | Out-String)</pre></div>"

# Installed Software
$htmlContent += "<div class='section'><h2>Installed Software</h2><pre>$(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, Publisher, InstallDate | Sort-Object InstallDate -Descending | Format-Table -AutoSize | Out-String)</pre></div>"

# Active Services
$htmlContent += "<div class='section'><h2>Active Services</h2><pre>$(Get-Service | Where-Object {$_.Status -eq 'Running'} | Sort-Object DisplayName | Select Status, DisplayName, StartType | Out-String)</pre></div>"

# Scheduled Tasks
$htmlContent += "<div class='section'><h2>Custom Scheduled Tasks</h2><pre>$(Get-ScheduledTask | Where-Object {$_.TaskName -notlike 'Microsoft*'} | Select TaskName, TaskPath, State | Out-String)</pre></div>"

# Security Settings
$uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\' -Name "fDenyTSConnections"
$htmlContent += "<div class='section'><h2>Security Settings</h2><pre>UAC: $(if ($uac.EnableLUA -eq 1) { 'Enabled' } else { 'Disabled' })</pre>"
$htmlContent += "<pre>RDP: $(if ($rdp.fDenyTSConnections -eq 0) { 'Allowed' } else { 'Blocked' })</pre></div>"

# Firewall and Windows Defender
$htmlContent += "<div class='section'><h2>Firewall and Windows Defender</h2><pre>$(Get-NetFirewallProfile | Select Name, Enabled | Out-String)</pre>"
$htmlContent += "<pre>$(Get-MpComputerStatus | Select AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled | Out-String)</pre></div>"

# Security Logs
$htmlContent += "<div class='section'><h2>Security Logs (Login Failures)</h2><pre>$(Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 5 | Select TimeCreated, Message | Out-String)</pre></div>"

# Network Information
$htmlContent += "<div class='section'><h2>Network Information</h2><pre>$(Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1'} | Select InterfaceAlias, IPAddress, PrefixLength | Out-String)</pre>"
$htmlContent += "<pre>$(Get-DnsClientServerAddress | Select InterfaceAlias, ServerAddresses | Out-String)</pre>"
$htmlContent += "<pre>$(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select InterfaceAlias, NextHop | Out-String)</pre></div>"

# Recent Connections
$htmlContent += "<div class='section'><h2>Recent Connections</h2><pre>$(Get-NetTCPConnection -State Established | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Out-String)</pre></div>"

# Recently Opened Files
$htmlContent += "<div class='section'><h2>Recently Opened Files</h2><pre>$(Get-ChildItem -Path \"$env:APPDATA\Microsoft\Windows\Recent\" | Select Name, LastWriteTime | Out-String)</pre></div>"

# PowerShell command history
$htmlContent += "<div class='section'><h2>PowerShell History</h2><pre>$(Get-Content (Get-PSReadlineOption).HistorySavePath | Out-String)</pre></div>"

# Office Recent Files (registry)
$htmlContent += "<div class='section'><h2>Office MRU (Recent Documents)</h2><pre>$(Get-ItemProperty 'HKCU:\Software\Microsoft\Office\*\*\File MRU' -ErrorAction SilentlyContinue | Out-String)</pre></div>"

# Mounted drives and mapped volumes
$htmlContent += "<div class='section'><h2>Mounted Drives</h2><pre>$(Get-PSDrive | Where-Object {$_.Provider -like '*FileSystem*'} | Out-String)</pre></div>"

# Registry persistence - RunOnce
$htmlContent += "<div class='section'><h2>Registry Persistence (RunOnce)</h2><pre>$(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Out-String)</pre></div>"

# WMI Event subscriptions
$htmlContent += "<div class='section'><h2>WMI Event Filters</h2><pre>$(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Out-String)</pre></div>"

# AppLocker Policies
$htmlContent += "<div class='section'><h2>AppLocker Policy (Effective)</h2><pre>$(Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RuleCollections | Out-String)</pre></div>"

# SMBv1 Protocol
$htmlContent += "<div class='section'><h2>SMBv1 Status</h2><pre>$(Get-WindowsOptionalFeature -Online -FeatureName \"SMB1Protocol\" | Out-String)</pre></div>"

# TLS 1.0/1.1 Status
$htmlContent += "<div class='section'><h2>TLS Configuration</h2><pre>$(Get-ItemProperty -Path \"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\" -ErrorAction SilentlyContinue | Out-String)</pre></div>"

# Credential Guard
$htmlContent += "<div class='section'><h2>Credential Guard Status</h2><pre>$(Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue | Out-String)</pre></div>"

# Inactive local users (last 90 days)
$htmlContent += "<div class='section'><h2>Inactive Local Users (&gt; 90 days)</h2><pre>`$threshold = (Get-Date).AddDays(-90); Get-LocalUser | Where-Object {`$_.LastLogon -lt `$threshold -and `$_.Enabled -eq `$true} | Out-String</pre></div>"

# Suspicious admin group members (for manual check)
$htmlContent += "<div class='section'><h2>Shadow Admins Check</h2><pre>Compare the list of Administrators to known authorized users.</pre></div>"

# Hidden/System files
$htmlContent += "<div class='section'><h2>Suspicious Files (Hidden/System)</h2><pre>$(Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.Attributes -match 'Hidden|System'} | Select FullName, Attributes | Out-String)</pre></div>"

# Executables in TEMP folder
$htmlContent += "<div class='section'><h2>Executables in TEMP</h2><pre>$(Get-ChildItem -Path $env:TEMP -Recurse -Include *.exe,*.ps1,*.bat -ErrorAction SilentlyContinue | Select FullName, LastWriteTime | Out-String)</pre></div>"

# Active RDP sessions
$htmlContent += "<div class='section'><h2>Active RDP Sessions</h2><pre>$(quser 2>&1 | Out-String)</pre></div>"

# BitLocker and SmartScreen
$htmlContent += "<div class='section'><h2>BitLocker and SmartScreen</h2><pre>$(Get-BitLockerVolume | Select MountPoint, VolumeStatus, ProtectionStatus | Out-String)</pre>"
$htmlContent += "<pre>$(Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name SmartScreenEnabled | Out-String)</pre></div>"

# SCAN GPO (Group Policy Objects) security
$htmlContent += "<div class='section'><h2>Scan Security GPOs</h2>"

# Essential Security GPO Settings
$htmlContent += "<h3>Local Security Settings</h3><pre>$(secpol.msc /s | Out-String)</pre>"

# Password and Audit Policy Information
$htmlContent += "<h3>Audit and Password Policies</h3><pre>$(gpresult /scope:computer /v | Select-String -Pattern 'Audit|Password' | Out-String)</pre>"

# Account Lockout Policies
$htmlContent += "<h3>Account Lockout Policies</h3><pre>$(gpresult /scope:computer /v | Select-String -Pattern 'Lockout' | Out-String)</pre>"

# User Security Policies
$htmlContent += "<h3>User Security Policies</h3><pre>$(gpresult /scope:user /v | Select-String -Pattern 'User Rights Assignment' | Out-String)</pre>"

$htmlContent += "</div>"

$htmlContent += "<div class='section'><h2>Startup Applications (Registry)</h2><pre>$(Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | Out-String)</pre></div>"
$htmlContent += "<div class='section'><h2>Startup Applications (User)</h2><pre>$(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Permissions on Sensitive Files</h2><pre>$(Get-Acl "C:\Windows\System32\config\*").Access | Out-String</pre></div>"

$htmlContent += "<div class='section'><h2>UAC (User Account Control) Configuration</h2><pre>$(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' | Select-Object EnableLUA, ConsentPromptBehaviorAdmin | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Network Shares</h2><pre>$(Get-WmiObject -Class Win32_Share | Select-Object Name, Path, Type, Description | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Processes with Administrative Rights</h2><pre>$(Get-WmiObject -Class Win32_Process | Where-Object {$_.ExecutablePath -ne $null -and $_.GetOwner().User -eq 'SYSTEM'} | Select-Object ProcessId, Name, ExecutablePath | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>RDP and Firewall Settings</h2><pre>$(Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*RDP*'} | Select-Object DisplayName, Enabled, Direction, Action | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>BIOS/UEFI Configuration</h2><pre>$(Get-WmiObject -Class Win32_BIOS | Select-Object Manufacturer, Version, ReleaseDate | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Active Directory Groups</h2><pre>$(Get-ADUser -Identity $(whoami) -Properties memberOf | Select-Object -ExpandProperty memberOf | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Security Policies (gpresult)</h2><pre>$(gpresult /r | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Privileges and User Tokens</h2><pre>$(whoami /priv | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>System Environment Variables</h2><pre>$(Get-ChildItem Env: | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Service Accounts</h2><pre>$(Get-WmiObject -Class Win32_Service | Where-Object {$_.StartName -ne 'LocalSystem'} | Select-Object Name, StartName | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Login Failure Logs</h2><pre>$(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} | Select-Object TimeCreated, Message | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Network Shares and Permissions</h2><pre>$(Get-WmiObject -Class Win32_Share | Select-Object Name, Path, Type, Description | Out-String)</pre></div>"

$htmlContent += "<div class='section'><h2>Open Ports and Network Services</h2><pre>$(Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort | Out-String)</pre></div>"


$htmlContent += "<div class='section'><h2>Search password in register</h2>"

$keywords = "password", "pwd", "cred", "login", "pass", "userpwd", "credential", "key"

$htmlContent += "<h3>HKEY_CURRENT_USER</h3><pre>"
$foundResults = Get-ChildItem -Path Registry::HKEY_CURRENT_USER -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            Get-ItemProperty -Path $_.PSPath | ForEach-Object {
                $_.PSObject.Properties | Where-Object {
                    $keywords -contains $_.Name.ToLower() -or
                    ($_.Value -is [string] -and $keywords | ForEach-Object { $_.ToLower() } | Where-Object { $_ -in $_.Value.ToLower() })
                }
            }
        } catch {}
    }

if ($foundResults) {
    Write-Host "`n[!] Mots de passe ou informations sensibles trouvées dans HKEY_CURRENT_USER :"
    $foundResults | ForEach-Object { Write-Host $_.PSObject.Properties.Name ": " $_.PSObject.Properties.Value }
} else {
    Write-Host "`n[+] Aucun mot de passe trouvé dans HKEY_CURRENT_USER."
}

$htmlContent += "</pre>"

$htmlContent += "<h3>Search in NTUSER.DAT users profils</h3><pre>"
$profilePaths = Get-ChildItem -Path "C:\Users" -Directory | Where-Object { $_.Name -ne 'Default' -and $_.Name -ne 'All Users' }
foreach ($profile in $profilePaths) {
    $userHivePath = "C:\Users\$($profile.Name)\NTUSER.DAT"
    if (Test-Path $userHivePath) {
        try {
            reg load HKU\TempHive $userHivePath
            $userRegSearch = reg query HKU\TempHive /f "password" /s

            if ($userRegSearch) {
                Write-Host "`n[!] Mots de passe ou informations sensibles trouvées dans NTUSER.DAT de $($profile.Name):"
                $userRegSearch | ForEach-Object { Write-Host $_ }
            }
            reg unload HKU\TempHive
        } catch {
            Write-Host "Impossible de charger le registre de $($profile.Name)"
        }
    }
}
$htmlContent += "</pre>"

$htmlContent += "</div>"

# Add the HTML footer
$htmlFooter = @"
    <div class='footer'>
        <p>Audit performed by WinAuditScanner NoWa-FTN</p>
    </div>
</body>
</html>
"@

# Combine header, content, and footer
$htmlReport = $htmlHeader + $htmlContent + $htmlFooter

# Save the HTML report
$htmlReport | Out-File -FilePath $reportPath

Write-Host "`nAudit completed. HTML report saved to: $reportPath" -ForegroundColor Green
