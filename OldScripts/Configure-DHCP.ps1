Install-WindowsFeature DHCP -IncludeAllSubFeature -IncludeManagementTools
##Complete Post Configuration 
netsh dhcp add securitygroups 
Add-DhcpServerInDC
Set-ItemProperty `
–Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 `
–Name ConfigurationState `
–Value 2 


##Create a DHCP scope for the 192.168.95.0 subnet called Main Scope w/ a range of 192.168.95.30-.40 


Add-DhcpServerv4Scope `
-Name “Demo Scope - 192.168.96.0” `
-StartRange 192.168.96.30 `
-EndRange 192.168.96.40 `
-SubnetMask 255.255.255.0 `
-ComputerName Demo1-DC `
-LeaseDuration 3:0:0:0 `
-verbose 


##Set DHCP Scope Options including DNSserver, DnsDomain, and Router (aka Default Gateway) used by your clients 


Set-DhcpServerv4OptionValue `
-ScopeId 192.168.96.0 `
-ComputerName Demo1-DC `
-DnsServer 192.168.95.10 `
-DnsDomain bentech.net `
-Router 192.168.96.2 `
-Verbose 
