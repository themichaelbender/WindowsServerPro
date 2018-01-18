<# Notes:

Authors: Jason Helmick, Melissa (Missy) Janusko, Greg Shields

The bulk of this DC, DHCP, ADCS config is authored by Melissa (Missy) Januszko.
Currently on her public DSC hub located here:
https://github.com/majst32/DSC_public.git

Goal - Create a domain controller and populate with OUs, Groups, and Users.
This script must be run after prepDomainController.

Disclaimer

This example code is provided without copyright and AS IS.  It is free for you to use and modify.
Note: These demos should not be run as a script. These are the commands that I use in the 
demonstrations and would need to be modified for your environment.

#>

configuration BuildDomainController
{
    Import-DscResource -ModuleName xActiveDirectory, xComputerManagement, xNetworking, xDnsServer
    Node localhost
    {

        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }
  
        xIPAddress NewIPAddress {
            IPAddress = $node.IPAddress
            InterfaceAlias = $node.InterfaceAlias
            PrefixLength = 24
            AddressFamily = "IPV4"
        }

        xDefaultGatewayAddress NewIPGateway {
            Address = $node.GatewayAddress
            InterfaceAlias = $node.InterfaceAlias
            AddressFamily = "IPV4"
            DependsOn = '[xIPAddress]NewIPAddress'
        }

        xDnsServerAddress PrimaryDNSClient {
            Address        = $node.IPAddress
            InterfaceAlias = $node.InterfaceAlias
            AddressFamily = "IPV4"
            DependsOn = '[xDefaultGatewayAddress]NewIPGateway'
        }

        User Administrator {
            Ensure = "Present"
            UserName = "Administrator"
            Password = $Cred
            DependsOn = '[xDnsServerAddress]PrimaryDNSClient'
        }

        xComputer NewComputerName {
            Name = $node.ThisComputerName
            DependsOn = '[User]Administrator'
        }

        WindowsFeature ADDSInstall {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = '[xComputer]NewComputerName'
        }

        xADDomain FirstDC {
            DomainName = $node.DomainName
            DomainAdministratorCredential = $domainCred
            SafemodeAdministratorPassword = $domainCred
            DatabasePath = $node.DCDatabasePath
            LogPath = $node.DCLogPath
            SysvolPath = $node.SysvolPath 
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        xADUser myaccount {
            DomainName = $node.DomainName
            Path = "CN=Users,$($node.DomainDN)"
            UserName = 'myaccount'
            GivenName = 'My'
            Surname = 'Account'
            DisplayName = 'My Account'
            Enabled = $true
            Password = $Cred
            DomainAdministratorCredential = $Cred
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]FirstDC'
        }

        xADUser gshields {
            DomainName = $node.DomainName
            Path = "CN=Users,$($node.DomainDN)"
            UserName = 'gshields'
            GivenName = 'Greg'
            Surname = 'Shields'
            DisplayName = 'Greg Shields'
            Enabled = $true
            Password = $Cred
            DomainAdministratorCredential = $Cred
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]FirstDC'
        }

        xADUser djones {
            DomainName = $node.DomainName
            Path = "CN=Users,$($node.DomainDN)"
            UserName = 'djones'
            GivenName = 'Donna'
            Surname = 'Jones'
            DisplayName = 'Donna Jones'
            Enabled = $true
            Password = $Cred
            DomainAdministratorCredential = $Cred
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]FirstDC'
        }

        xADUser jhelmick {
            DomainName = $node.DomainName
            Path = "CN=Users,$($node.DomainDN)"
            UserName = 'jhelmick'
            GivenName = 'Jane'
            Surname = 'Helmick'
            DisplayName = 'Jane Helmick'
            Enabled = $true
            Password = $Cred
            DomainAdministratorCredential = $Cred
            PasswordNeverExpires = $true
            DependsOn = '[xADDomain]FirstDC'
        }

        xADGroup IT {
            GroupName = 'IT'
            Path = "CN=Users,$($node.DomainDN)"
            Category = 'Security'
            GroupScope = 'Global'
            MembersToInclude = 'gshields', 'jhelmick', 'myaccount'
            DependsOn = '[xADDomain]FirstDC'
        }

        xADGroup DomainAdmins {
            GroupName = 'Domain Admins'
            Path = "CN=Users,$($node.DomainDN)"
            Category = 'Security'
            GroupScope = 'Global'
            MembersToInclude = 'gshields', 'myaccount'
            DependsOn = '[xADDomain]FirstDC'
        }

        xADGroup EnterpriseAdmins {
            GroupName = 'Enterprise Admins'
            Path = "CN=Users,$($node.DomainDN)"
            Category = 'Security'
            GroupScope = 'Universal'
            MembersToInclude = 'gshields', 'myaccount'
            DependsOn = '[xADDomain]FirstDC'
        }

        xADGroup SchemaAdmins {
            GroupName = 'Schema Admins'
            Path = "CN=Users,$($node.DomainDN)"
            Category = 'Security'
            GroupScope = 'Universal'
            MembersToInclude = 'gshields', 'myaccount'
            DependsOn = '[xADDomain]FirstDC'
        }

        xDnsServerADZone addReverseADZone {
            Name = '3.168.192.in-addr.arpa'
            DynamicUpdate = 'Secure'
            ReplicationScope = 'Forest'
            Ensure = 'Present'
            DependsOn = '[xADDomain]FirstDC'
        }
    }
}
            
$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = "localhost"
            ThisComputerName = "dc"
            IPAddress = "192.168.3.10"
            GatewayAddress = "192.168.3.2"
            InterfaceAlias = "Ethernet0"
            DomainName = "company.pri"
            DomainDN = "DC=Company,DC=Pri"
            DCDatabasePath = "C:\NTDS"
            DCLogPath = "C:\NTDS"
            SysvolPath = "C:\Sysvol"
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true
        }
    )
}

$domainCred = Get-Credential -UserName company\Administrator -Message "Please enter a new password for Domain Administrator."
$Cred = Get-Credential -UserName Administrator -Message "Please enter a new password for Local Administrator and other accounts."

BuildDomainController -ConfigurationData $ConfigData

Set-DSCLocalConfigurationManager -Path .\BuildDomainController –Verbose
Start-DscConfiguration -Wait -Force -Path .\BuildDomainController -Verbose