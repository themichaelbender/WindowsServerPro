<# Notes:

Authors: Greg Shields

Goal - Complete the standard series of post-install configurations on
a Server Core instance.

Disclaimers

!!!!!!!!!!
This script is provided primarily as an example series of cmdlets and
is not directly intended to be run as-is.
!!!!!!!!!!

This example code is provided without copyright and AS IS.  It is free for you to use and modify.
Note: These demos should not be run as a script. These are the commands that I use in the 
demonstrations and would need to be modified for your environment.

#>

Set-DisplayResolution 1280 720
tzutil /l
Set-Timezone "mountain standard time"
Set-Date -date "10/19/2016 11:30 AM"
Get-NetIPAddress -interfacealias ethernet0
New-NetIPAddress -interfaceindex 2 -IPAddress 192.168.3.110 -Prefixlength 24 -defaultgateway 192.168.3.2

### Use this cmdlet to enable/disable DHCP
Set-NetIPInterface -interfaceindex 2 -DHCP enable

Get-NetIPConfiguration -interfaceindex 2
Set-DNSClientServerAddress -interfaceindex 2 -ServerAddress ("192.168.3.10")
hostname
Get-Content ENV:computername)
Rename-Computer -newname server1 -restart
slmgr.vbs -ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
slmgr.vbs -ato
Get-NetFirewallRule | ft
Get-NetFirewallRule -name CoreNet-IGMP-In | Enable-NetFirewallRule
Get-NetFirewallRule -name CoreNet-IGMP-Out | Enable-NetFirewallRule
Get-NetFirewallRule | ft displayname,displaygroup
Enable-NetFirewallRule -displaygroup "File and Printer Sharing"
New-NetFirewallRule -displayname "Allow All Traffic" -direction outbound -action allow
New-NetFirewallRule -displayname "Allow All Traffic" -direction inbound -action allow
Add-Computer -domainname "company.pri" -restart

### And finally, as a fun Easter Egg, hidden all the way down here,
### Use this command to set PowerShell as your Server Core instance's 
### default shell (replacing the legacy command prompt)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'PowerShell.exe -NoExit'