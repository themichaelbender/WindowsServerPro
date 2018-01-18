##Configure WDS##
Install-WindowsFeature WDS -IncludeAllSubFeature -IncludeManagementTools

get-command -Module WDS

#Initial Configuration
WDSUTIL /Initialize-Server /RemInst:"c:\RemoteInstall"

Get-Service *WDS*|restart-service

##Start Demo Here
New-WDSInstallImageGroup -Name "Custom Image Group"


Get-Command -Module WDS

Import-WdsBootImage -Path "d:\sources\boot.wim" `
-NewImageName "Windows Server 2012 R2 - Eval" `
-NewDescription "Choose this image to install Windows Server 2012 R2." `
-NewFileName "boot.wim" -SkipVerify

Get-WindowsImage -ImagePath C:\images\install.wim

Import-WdsInstallImage -Path c:\images\install.wim `
-ImageGroup "Custom Image Group" `
-ImageName 'Windows Server 2012 R2 SERVERSTANDARD' `
-NewImageName 'Custom Server 2012 R2 SERVERSTANDARD' `
-NewFileName 'CUSTOM.WIM' `
-SkipVerify

Get-WdsInstallImage | fl Name,Description,Version

Get-WdsInstallImageGroup | fl
