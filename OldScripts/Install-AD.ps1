##Windows PowerShell script for AD DS Deployment on RWDC01
##This script is used to build a custom domain called contosoxx.com where XX is your monitor number
##How to run: Open PowerShell console as Administrator on RWDC01 and type c:\software\Install-AD.ps1
##This running of this script assumes that it is located in the c:\software directory on RWDC01

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
