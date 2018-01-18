##SimpleConfigv2.ps1
##
##Based on DSC script from Jason Helmick
##
##This script will create a MOF file for installing the Web Server (IIS) role
##It will also test the running of the configuration on a remote system

#Configuration Block
configuration WebServerConfig {

    ##Node Block used to determine Target
    Node $ComputerName {

        ## Resource Block used to configure resources
        ##Windows Feature is a built-in Resource Block
        WindowsFeature IIS{
            
            Name = 'web-server' ##Feature Name
            Ensure = 'Present'  ##Determines install status. To uninstall the role, set Ensure to "Absent"
        }
    }
}
##Variable for Name of Computer that configuration will apply to
$computername = 'DC01'

##Executes WebServerConfig configuration to create the MOF file 
WebServerConfig -OutputPath c:\Scripts\DSC\Config

##To run process for Configuration on DC01
Start-DscConfiguration -Path C:\scripts\dsc\config -ComputerName DC01 -WhatIf -Wait