###Bulk Create AD Objects
##
##Created by Michael Bender
##Last Revision 11/12/2013
##
##Define ou.csv with headings Name,Path 
##
##Define groups.csv with headings SamAccountName,Name,GroupCategory,GroupScope,Path
##
##Define ou.csv with headings SamAccountName,Name,SurName,GivenName,Path,AccountPassword,Group
##
##Create OUs using CSV file
##

Import-csv C:\scripts\OU.csv|ForEach-Object {
    New-ADOrganizationalUnit -name $_.Name -path $_.Path -verbose
    $OU="OU="+$_.Name+","+$_.Path
    Set-ADObject -Identity $OU -ProtectedFromAccidentalDeletion $False -Verbose
    }

##Create Groups using CSV file
## 
Import-csv C:\scripts\Groups.csv|ForEach-Object {
    New-ADGroup -name $_.Name `
    -path $_.Path `
    -SamAccountName $_.SamAccountName `
    -GroupScope $_.GroupScope `
    -GroupCategory $_.GroupCategory `
    -verbose
   $CN="Cn="+$_.Name+","+$_.Path
   Set-ADObject -Identity $CN -ProtectedFromAccidentalDeletion $False -Verbose
       }

##Create Users using CSV file
##
Import-CSV C:\Scripts\Users.csv | ForEach-Object { 
    $setpass = ConvertTo-SecureString $_.AccountPassword -AsPlainText  -force
    New-ADUser -SamAccountName $_.SamAccountName `
    -Name $_.Name `
    -Surname $_.Surname `
    -GivenName $_.GivenName `
    -Path $_.Path `
    -AccountPassword $setpass `
    -ChangePasswordAtLogon $True `
    -Enabled $True -Verbose
    Add-ADGroupMember -Identity $_.Group -Members $_.SamAccountName 
     }
     
