##Windows PowerShell script for DHCP and DNS Deployment/Configuration on RWDC01
##This script is used to install and configure DHCP/DNS services for use in your domain
##How to run: Open PowerShell console as Administrator on RWDC01 and type c:\software\Install-DHCP.ps1
##This running of this script assumes that it is located in the c:\software directory on RWDC01

##BEFORE RUNNING SCRIPT: 
##Change all references to contosoxx.com to match the domain name used to build lab AD domain on lines 33 & 35

##Install DHCP Role with Tools
Add-WindowsFeature  -IncludeManagementTools dhcp

##Complete Post Configuration
netsh dhcp add securitygroups
Add-DhcpServerInDC
Set-ItemProperty `
    –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 `
    –Name ConfigurationState `
    –Value 2

##Create a DHCP scope for the 192.168.95.0 subnet called Main Scope w/ a range of 192.168.95.30-.40
Add-DhcpServerv4Scope `
    -Name “Main Scope” `
    -StartRange 192.168.95.100 `
    -EndRange 192.168.95.110 `
    -SubnetMask 255.255.255.0 `
    -ComputerName Demo1 `
    -LeaseDuration 8:0:0:0 `
    -verbose

##Set DHCP Scope Options including DNSserver, DnsDomain, and Router (aka Default Gateway) used by your clients
Set-DhcpServerv4OptionValue  `
    -ScopeId 192.168.95.0 `
    -ComputerName Demo1.bender.priv `
    -DnsServer 192.168.95.10 `
    -DnsDomain Bender.priv `
    -Router 192.168.95.2 `
    -Verbose

Get-DhcpServerv4Scope 

Get-DnsServerZone
#NewDNS Zone
Add-DnsServerPrimaryZone -Name Demo1.bender.priv -ReplicationScope Forest

#Ne A Record
Add-DnsServerResourceRecordA -Name Demo1 -ZoneName demo1.bender.priv -IPv4Address 192.168.95.10

Get-DnsServerResourceRecord -ZoneName demo1.bender.priv

