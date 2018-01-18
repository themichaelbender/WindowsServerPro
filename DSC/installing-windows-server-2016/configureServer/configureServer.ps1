<# Notes:

Authors: Greg Shields

Goal - Configure minimal initial settings for a server.
This script must be run after prepServer.ps1

Disclaimer

This example code is provided without copyright and AS IS.  It is free for you to use and modify.
Note: These demos should not be run as a script. These are the commands that I use in the 
demonstrations and would need to be modified for your environment.

#>

configuration configureServer
{
    Import-DscResource -ModuleName xComputerManagement, xNetworking
    Node localhost
    {

        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }
  
        xIPAddress NewIPAddress {
            IPAddress = $node.IPAddress
            InterfaceAlias = "Ethernet0"
            PrefixLength = 24
            AddressFamily = "IPV4"
        }

        xDefaultGatewayAddress NewIPGateway {
            Address = $node.GatewayAddress
            InterfaceAlias = "Ethernet0"
            AddressFamily = "IPV4"
            DependsOn = '[xIPAddress]NewIPAddress'
        }

        xDnsServerAddress PrimaryDNSClient {
            Address        = $node.DNSIPAddress
            InterfaceAlias = "Ethernet0"
            AddressFamily = "IPV4"
            DependsOn = '[xDefaultGatewayAddress]NewIPGateway'
        }

        User Administrator {
            Ensure = "Present"
            UserName = "Administrator"
            Password = $Cred
            DependsOn = '[xDnsServerAddress]PrimaryDNSClient'
        }

        xComputer ChangeNameAndJoinDomain {
            Name = $node.ThisComputerName
            DomainName    = $node.DomainName
            Credential    = $domainCred
            DependsOn = '[User]Administrator'
        }
    }
}
            
$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = "localhost"
            ThisComputerName = "server1"
            IPAddress = "192.168.3.110"
            GatewayAddress = "192.168.3.2"
            DNSIPAddress = "192.168.3.10"
            DomainName = "company.pri"
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true
        }
    )
}

$domainCred = Get-Credential -UserName company\Administrator -Message "Please enter a new password for Domain Administrator."
$Cred = Get-Credential -UserName Administrator -Message "Please enter a new password for Local Administrator and other accounts."

configureServer -ConfigurationData $ConfigData

Set-DSCLocalConfigurationManager -Path .\configureServer –Verbose
Start-DscConfiguration -Wait -Force -Path .\configureServer -Verbose