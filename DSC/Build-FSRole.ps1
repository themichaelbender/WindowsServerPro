##Build-FSRole.ps1
##
##This script will create a MOF file for installing the File Server role
##It will also test the running of the configuration on a remote system

#Configuration Block
configuration WebServerConfig {

    ##Node Block used to determine Target
    Node $ComputerName {

        ## Resource Block used to configure resources
        ##Windows Feature is a built-in Resource Block
        WindowsFeature FS{
            
            Name = 'FS-Server' ##Feature Name
            Ensure = 'Present'  ##Determines install status. To uninstall the role, set Ensure to "Absent"
        }
        ##Create c:\Scripts
        file Scripts {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = 'c:\scripts'
        }
        ##Copy ADScripts.zip to c:\Scripts
        file CopyScript {
            Ensure = 'Present'
            Type = "File"
            SourcePath = '\\dc1\apps\adscripts.zip'
            DestinationPath = 'c:\scripts'
        }
        ##Unzip ADSCripts to c:\scripts\ADScripts
        archive UnZip {
            Ensure = 'Present'
            Path = 'c:\scripts\adscripts.zip'
            Destination = 'c:\scripts\adscripts\'
        }

        #Create Share
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

#Install Remote Roles
Invoke-Command -ComputerName $computername -ScriptBlock {install-module -Name xSMBShare -Force }

##Executes WebServerConfig configuration to create the MOF file 
WebServerConfig -OutputPath c:\Scripts\DSC\Config\FS

##To run process for Configuration on DC01
Start-DscConfiguration -Path C:\scripts\dsc\config\FS -ComputerName $computername -Wait

#Creates CIM sessions for communicating with Remote Servers
$cimsessions = New-CimSession -ComputerName $computername

#Uses CIM to run Get-DSCConfiguration remotely
#Required as -computername is not supported
foreach ($server in $cimsessions) { Get-DscConfiguration -CimSession $server | out-file c:\scripts\$Server.txt}