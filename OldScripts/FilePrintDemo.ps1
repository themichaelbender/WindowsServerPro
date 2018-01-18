#File Services
Get-ChildItem -Path c:\ 

Get-ChildItem -Path c:\ -Recurse 

Get-ChildItem -Path c:\ -Recurse | gm

Get-ChildItem -Path c:\ -Recurse -Filter *events* | where PSIsContainer -NE $True

Get-ChildItem -Path c:\ -Recurse -Filter *events* | where PSIsContainer -NE $False

New-item -ItemType directory -Path c:\DemoShare

GCM *SMB*

New-SmbShare -Path C:\DemoShare -ChangeAccess 'bender\domain users' -FullAccess 'bender\Domain Admins' -Name DemoShare

Get-SmbShareAccess -Name DemoShare

get-smbshare

Get-SmbMapping

New-SmbMapping -LocalPath t: -RemotePath \\demo1\DemoShare

#Printers
Gcm *print*
Get-printer
Add-PrinterPort -name "ToDemo" -printerhostaddress '192.168.95.211'
Get-PrinterPort
Get-PrinterDriver

#First Install with pnputil for oemnn.inf file
pnputil -i -a 'C:\scripts\Dell_1130n_Laser_Printer_Driver\Printer\SPL_PCL\WINXP_VISTA_64\sdc1m.inf'

#add driver from oemnn.inf file
Add-PrinterDriver -Name "Dell 1130n Laser Printer" -InfPath 'C:\Windows\inf\oem11.inf'

Add-Printer -name "DemoPrinter1" `
-drivername "Dell 1130n Laser Printer" `
-PortName "ToDemo" `
-Shared `
-ShareName "DemoPrinter1"
Get-PrintConfiguration -PrinterName 'DemoPrinter1'|fl

ADD-Printer -ConnectionName \\Demo1-DC\Dell1130

##Get AD Domain Info
##Get Domain Controllers
##view information in AD