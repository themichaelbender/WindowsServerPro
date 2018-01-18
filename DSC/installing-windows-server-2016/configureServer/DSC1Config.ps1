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
            ThisComputerName = "DSC1"
            DomainName = "bender.priv"
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true
        }
    )
}

$domainCred = Get-Credential -UserName bender\Administrator -Message "Please enter a new password for Domain Administrator."
$Cred = Get-Credential -UserName Administrator -Message "Please enter a new password for Local Administrator and other accounts."

configureServer -ConfigurationData $ConfigData

Set-DSCLocalConfigurationManager -Path .\configureServer –Verbose
Start-DscConfiguration -Wait -Force -Path .\configureServer -Verbose