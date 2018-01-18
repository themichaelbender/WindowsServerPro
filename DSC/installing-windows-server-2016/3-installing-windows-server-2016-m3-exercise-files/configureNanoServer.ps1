<# Notes:

Authors: Greg Shields

Goal - Configure a Nano Server.

Disclaimers

!!!!!!!!!!
This script is provided primarily as an example series of cmdlets and
is not directly intended to be run as-is.
!!!!!!!!!!

This example code is provided without copyright and AS IS.  It is free for you to use and modify.
Note: These demos should not be run as a script. These are the commands that I use in the 
demonstrations and would need to be modified for your environment.

#>

set-item wsman:\localhost\client\trustedhosts -value 192.168.3.112

$cred = get-credential 192.168.3.112\administrator
enter-pssession -computername 192.168.3.112 -credential $cred

get-dnsclientserveraddress
set-dnsclientserveraddress -interfacealias ethernet -serveraddress 192.168.3.10

### This first command is run on an existing domian machine to create the ODJ blob.
djoin /provision /domain company.pri /machine nanoserver1 /savefile c:/nanoserver/nanoserver1.txt

### Copy the results of the first command to the candidate machine and run this second
### command to complete the domain join.
djoin /requestodj /loadfile C:\nanoserver1.txt /windowspath C:\Windows /localos

### Configure package providers and install DNS and IIS roles.
install-packageprovider -name nuget -minimumversion 2.8.5.201 -force
save-module -path "$env:programfiles\windowspowershell\modules" -name nanoserverpackage
Install-packageprovider nanoserverpackage
Import-packageprovider nanoserverpackage
find-nanoserverpackage
install-nanoserverpackage -name microsoft-nanoserver-dns-package
enable-windowsoptionalfeature -online -featurename dns-server-full-role

install-nanoserverpackage -name microsoft-nanoserver-iis-package
import-module iis*
mkdir c:\site1
new-iissite -name site1 -bindinginformation "*:80:site1" -physicalpath c:\site1
get-iissite site1
start-service was,w3svc
start-iissite site1