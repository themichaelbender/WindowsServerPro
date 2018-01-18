##Configure WDS##
Install-WindowsFeature WDS -IncludeAllSubFeature -IncludeManagementTools

get-command -Module WDS

#Initial Configuration
WDSUTIL /Initialize-Server /RemInst:"c:\RemoteInstall"

Get-Service *WDS*|restart-service


New-WDSInstallImageGroup -Name "Test Image Group"


Get-Command -Module WDS

Import-WdsBootImage -Path "d:\sources\boot.wim" `
-NewImageName "Windows Server 2012 R2 - Eval" `
-NewDescription "Choose this image to install Windows Server 2012 R2." `
-NewFileName "boot.wim" -SkipVerify

Get-WindowsImage -ImagePath D:\sources\install.wim

Import-WdsInstallImage -Path D:\sources\install.wim -ImageGroup "Test Image Group" -ImageName 'Windows Server 2012 R2 SERVERDATACENTER' -SkipVerify

Get-WdsInstallImage | fl Name,Description,Version

Get-WdsInstallImageGroup | fl

Approve-WdsClient
