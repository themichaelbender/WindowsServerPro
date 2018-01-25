##Build-IISRole.ps1
##
##
##This script will create a MOF file for installing the Web Server (IIS) role
##It will also test the running of the configuration on a remote system

#Configuration Block

configuration WebServerConfig {
    Import-DscResource -moduleName xSMBShare

    ##Node Block used to determine Target
    Node $ComputerName {
        ##Import Modules (Optional)
        #Import-DscResource -ModuleName xSMBShare

        ## Resource Block used to configure resources
        ##Windows Feature is a built-in Resource Block
        WindowsFeature IIS{
            
            Name = 'web-server' ##Feature Name
            Ensure = 'Present'  ##Determines install status. To uninstall the role, set Ensure to "Absent"
        }
        ##Create c:\Scripts
        File DirScripts {
            Ensure = 'Present'
            DestinationPath = 'c:\scripts'
            Type = 'Directory'
        }
        Archive Website {
            Ensure = 'Present'
            Path = '\\dc1\apps\website.zip'
            Destination = 'c:\inetpub\wwwroot'
            DependsOn = '[windowsfeature]IIS'
        }
        Archive ADScripts {
            Ensure = 'Present'
            Path = '\\dc1\apps\adscripts.zip'
            Destination = 'c:\scripts\ADScripts\'
            DependsOn = '[file]DirScripts'
        }
        xsmbshare ScriptsShare {
            Name = 'Scripts'
            Ensure = 'Present'
            Path = 'c:\Scripts'
            Description = 'This is the Scripts share'
        }

    }
}
##Variable for Name of Computer that configuration will apply to
$computername = 'DSC1','DSC2'

#
Invoke-Command -ComputerName $computername -ScriptBlock {install-module -Name xSMBShare -Force }

#DNS
#Add-DnsServerResourceRecordA -ZoneName contosoxx.com -Name WWW -IPv4Address 192.168.95.20
#Add-DnsServerResourceRecordA -ZoneName contosoxx.com -Name WWW -IPv4Address 192.168.95.30

##Executes WebServerConfig configuration to create the MOF file 
WebServerConfig -OutputPath c:\Scripts\DSC\Config\IIS

##To run process for Configuration on DC01
Start-DscConfiguration -Path C:\scripts\dsc\config\IIS -ComputerName $computerName -Wait -Verbose

$cimsessions = New-CimSession -ComputerName $computername

foreach ($server in $cimsessions) { 
Write-Output $server
$path= $Server.ComputerName + ".txt"
Get-DscConfiguration -CimSession $server | out-file "c:\scripts\$path"
}