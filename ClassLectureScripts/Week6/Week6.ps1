#Week 6
#DSC Resources
start iexplore.exe http://www.powershellgallery.com
#See Built in DSC ResourcesGet-DscResource
Get-DscResource

#View How to use FILE resourceGet-DSCResource File -Syntax
Get-DSCResource File -Syntax

 Get-DscResource -Syntax #View all resources syntax

#Find DNS resources available for PowerShell
Find-Module *DNS*

#Look at details for xDNSServer resourceFind-Module -Name xDNSServer -Repository PSGallery | FL
Find-Module -Name xDNSServer -Repository PSGallery | FL

#Find all DNS DSC resourcesFind-DscResource -moduleName *DNS* -Repository PSGallery
Find-DscResource -moduleName *DNS* -Repository PSGallery

#Install Module
Install-Module -Name xDNSServer

Get-DscResource -Module XDNSServer -Syntax

