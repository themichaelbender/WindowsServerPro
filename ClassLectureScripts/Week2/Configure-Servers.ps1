#Disable DHCP in VMWare Workstation

#region - initial configuration On ServerA
New-Item -ItemType directory -Path c:\ClassFiles

#Add RSAT Tools
Get-WindowsFeature -Name *RSAT* | Install-WindowsFeature


#Set Trusted Hosts
get-item wsman:\localhost\Client\TrustedHosts
set-item WSMan:\localhost\Client\TrustedHosts -value *

#Set IP Address
Get-NetIPConfiguration

Get-NetIPConfiguration | New-NetIPAddress -IPAddress 192.168.95.10 -PrefixLength 24 -DefaultGateway 192.168.95.2

Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses 4.2.2.1

Get-NetIPConfiguration
Test-NetConnection microsoft.com
Test-NetConnection 4.2.2.1

#Set New Name
Rename-Computer -NewName ServerA -Restart

#endregion - initial configuration 

#region - Install AD on ServerA
        #Install ADDS Role and Mgt Tools
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools


    # Replace all references to XX with your monitor number on Lines 20 and 21

    ##Import ADDSDeployment Module
    Import-Module ADDSDeployment

    ##Install a new AD Forest
    Install-ADDSForest `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "Win2012r2" `
    -DomainName "bender.priv" `
    -DomainNetbiosName "bender" `
    -ForestMode "Win2012r2" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoRebootOnCompletion:$false `
    -SysvolPath "C:\Windows\SYSVOL" `
    -Force:$true
#endregion - Install AD on ServerA

#region - Install DHCP on ServerA
    
    #Verify AD
    Get-ADcomputer -filter *
    Get-ADDomainController -filter *
    
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
        -ComputerName ServerA `
        -LeaseDuration 8:0:0:0 `
        -verbose

    ##Set DHCP Scope Options including DNSserver, DnsDomain, and Router (aka Default Gateway) used by your clients
    Set-DhcpServerv4OptionValue  `
        -ScopeId 192.168.95.0 `
        -ComputerName ServerA.bender.priv `
        -DnsServer 192.168.95.10 `
        -DnsDomain Bender.priv `
        -Router 192.168.95.2 `
        -Verbose

    Get-DhcpServerv4Scope | FL

    
#endregion - Install DHCP on ServerA

#region - Configure DNS Records
    Get-DnsServerZone -ComputerName ServerA

    #NewDNS Zone
    Add-DnsServerPrimaryZone -Name Demo1.bender.priv -ReplicationScope Forest

    #Ne A Record
    Add-DnsServerResourceRecordA -Name Demo1 -ZoneName demo1.bender.priv -IPv4Address 192.168.95.10

    Get-DnsServerZone -Name Demo1.bender.priv
    Get-DnsServerResourceRecord -ZoneName Bender.priv
    Get-DnsServerResourceRecord -ZoneName Demo1.bender.priv
#endregion - Configure DNS 

#region - Install and Configure WDS
    ##Configure WDS##
    Install-WindowsFeature WDS -IncludeAllSubFeature -IncludeManagementTools

    get-command -Module WDS

    #verify ISO is mounted to DVD of VM

    #Initial Configuration
    WDSUTIL /Initialize-Server /RemInst:"c:\RemoteInstall" #Will error but works properly

    Get-Service *WDS*|restart-service
    Get-Service *WDS*

    #Import Boot Image
    Import-WdsBootImage -Path "d:\sources\boot.wim" `
        -NewImageName "Windows Server 2012 R2 - Eval" `
        -NewDescription "Choose this boot image to install Windows Server 2012 R2." `
        -NewFileName "boot.wim" -SkipVerify
    
    #Create an Image Group
    $ImageGroup = "Production Server Images"
    New-WDSInstallImageGroup -Name $ImageGroup

    #Import Install Image
    Get-WindowsImage -ImagePath D:\sources\install.wim

    Import-WdsInstallImage -Path D:\sources\install.wim `
        -ImageGroup $ImageGroup `
        -ImageName 'Windows Server 2012 R2 SERVERDATACENTER' `
        -SkipVerify

    #Verify
    Get-WdsBootImage | FL Name,Description,Version
    Get-WdsInstallImage | fl Name,Description,Version

    Get-WdsInstallImageGroup | fl

    #Update PowerShell Help files
    update-help -Force
#endregion

#Create VM for ServerC and Test WDS in Background

#region - Configure ServerB
    #Verify NAT is not using DHCP
   
    #Find IP Address for Client
    Get-DhcpServerv4Lease -ScopeId 192.168.95.0 
    
    #Set IP Address
    $cimsession = New-CimSession -Credential (get-credential) -ComputerName 192.168.95.101

    Get-NetIPConfiguration -CimSession $cimsession
    
    New-netIPAddress `
        -CimSession $cimsession `
        -IPAddress 192.168.95.20 `
        -PrefixLength 24 `
        -DefaultGateway 192.168.95.2 `
        -InterfaceIndex 12
        #Will freeze up since we changed IP Address
    
    #set DNS Client Server Address
    $cimsession = New-CimSession -Credential (get-credential) -ComputerName 192.168.95.20

    Get-NetIPConfiguration -CimSession $cimsession

    Set-DnsClientServerAddress `
        -CimSession $cimsession `
        -InterfaceIndex 12 `
        -ServerAddresses 192.168.95.10

    Get-NetIPConfiguration -CimSession $cimsession

    #Rename Server to Server1
    Enter-PSSession -ComputerName 192.168.95.20 -Credential (get-credential)
        Rename-Computer -NewName ServerB
    #Set Time Zone 
        Tzutil.exe /?
        Tzutil.exe /g
        Tzutil.exe /s "Central Standard Time"
        Restart-computer 

#Domain Join ServerB
    $Domaincred = Get-Credential #Domain Credentials
    Invoke-command `
        -ComputerName 192.168.95.20 `
        -Credential (Get-Credential) `
        -scriptblock {Add-Computer -DomainName bender.priv -credential $using:Domaincred -Restart}

#Verify Remote System is Domain Joined and in DNS

    Get-DnsServerResourceRecord -ZoneName Bender.priv
    Get-ADComputer -Filter *
    Test-NetConnection serverB.bender.priv #Will fail due to firewall, successful on name resolution

#Re-Set Trusted Hosts (Optional)

    Get-Item WSMan:\localhost\Client\TrustedHosts

    Set-item WSMAN:\Localhost\Client\TrustedHosts -value ''

#endregion - Configure ServerB

#region - Install DNS Secondary on ServerB
    Install-WindowsFeature -ComputerName ServerB.bender.priv -Name DNS
    
    Set-DnsServerPrimaryZone `
        -Name bender.priv `
        -ComputerName ServerA.bender.priv `
        -SecondaryServers 192.168.95.20 `
        -SecureSecondaries TransferToSecureServers

    Add-DnsServerSecondaryZone `
        -MasterServers 192.168.95.10 `
        -ComputerName ServerB.bender.priv `
        -Name bender.priv `
        -ZoneFile bender.priv.dns

    Start-DnsServerZoneTransfer `
        -ComputerName ServerB.bender.priv `
        -ZoneName bender.priv `
        -FullTransfer

    Get-DnsServerZone -Name bender.priv -ComputerName ServerB.bender.priv
    Get-DnsServerResourceRecord  -ComputerName ServerB.bender.priv -zonename bender.priv

#endregion - Install DNS Secondary on ServerB