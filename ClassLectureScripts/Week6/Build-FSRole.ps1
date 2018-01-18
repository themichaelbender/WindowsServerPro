##Build-FSRole.ps1
##
##This script will create a MOF file for installing the File Server role
##It will also test the running of the configuration on a remote system
##Requirements: All Servers running WMF 5.1 
##To Verify use $psVersiontable

#Define Parameter for inputting servers when script runs
[cmdletbinding()]
param (
    [string[]]$Target= "localhost"
)
#Configuration Block
configuration FileServerConfig {
    ##Parameter for ComputerName
        param(
        [string[]]$ComputerName="localhost"
        )
    ##Add SMBShare DSC resource
    Import-DscResource -moduleName xSMBShare
    ##Node Block used to determine Target
    Node $ComputerName {
        
        ## Resource Block used to configure resources
        ##Windows Feature is a built-in Resource Block
        WindowsFeature FS{
            
            Name = 'FS-FileServer' ##Feature Name
            Ensure = 'Present'  ##Determines install status. To uninstall the role, set Ensure to "Absent"
        }
        ##Create c:\Scripts on remote servers
        file Scripts {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = 'c:\scripts\'
        }
        ##Copy ADScripts.zip to c:\Scripts
        file CopyScript {
            Ensure = 'Present'
            Type = "File"
            SourcePath = '\\servera\scripts\dsc\ADScripts.zip'
            DestinationPath = 'c:\scripts\adscripts.zip'
            DependsOn = '[file]Scripts'
        }
        ##Unzip ADSCripts to c:\scripts\ADScripts
        archive UnZip {
            Ensure = 'Present'
            Path = 'c:\scripts\adscripts.zip'
            Destination = 'c:\scripts\adscripts\'
            DependsOn = '[file]CopyScript'
        }

        #Create Share
        xsmbshare ScriptsShare {
            Name = 'Scripts'
            Ensure = 'Present'
            Path = 'c:\Scripts'
            Description = 'This is the Scripts share'
            DependsOn = '[file]Scripts'
        }

    }
}

#Install xSMBShare module from PowerShell Gallery
install-module -Name xSMBShare -Force
Invoke-Command -ComputerName $target -ScriptBlock { install-module -Name xSMBShare -Force }

##Executes WebServerConfig configuration to create the MOF file 
FileServerConfig -OutputPath c:\Scripts\DSC\Config\FS

##To run process for Configuration on DC01
Start-DscConfiguration -Path C:\scripts\dsc\config\FS -ComputerName $Target -Wait -Verbose -Force

start \\dsc1\Scripts ; start \\dsc2\Scripts