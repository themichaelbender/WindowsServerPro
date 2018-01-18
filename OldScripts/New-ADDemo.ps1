##Demo 
get-command -Module 'ActiveDirectory' -CommandType Cmdlet,function | More

#Using Filter Left > Format Right
Get-adobject -Filter * | gm
Get-ADObject -Filter * -Properties * | gm
Get-ADObject -Filter 'ObjectClass -eq "group"'| ft Name,ObjectClass
(Get-ADObject -Filter 'ObjectClass -eq "group"'| ft Name,ObjectClass).count
(Get-ADObject -Filter *| ft Name,ObjectClass).count
Get-ADObject -Filter * | where ObjectClass -eq 'group' | ft Name,ObjectClass
Get-ADGroup -Filter *

Get-ADObject -Filter 'ObjectClass -eq "User"'
Get-ADObject -Filter 'ObjectClass -eq "OrganizationalUnit"'

##Get AD Domain Info
##Get Domain Controllers
Get-ADDomainController | ft -Wrap -Property Hostname


#Variables
$Server = "Demo1.bender.priv"
$setpass = read-host -Prompt 'Enter-password' -AsSecureString

#Create New OU called Demo2
New-ADOrganizationalUnit `
    -Server $Server `
    -Name Demo2 `
    -Path "dc=bender,dc=Priv" `
    -ProtectedFromAccidentalDeletion $false -Verbose

#Create a new Global Security Group called bender-Admins-GS
New-ADGroup `
    -Server $Server `
    -Name Bender-Admins-GS `
    -GroupCategory Security `
    -GroupScope Global `
    -Path "ou=Demo2,dc=bender,dc=priv" `
    -Verbose

    Get-ADGroup -Filter *|ft DistinguishedName,Name
#New User
    New-ADUser `
        -Server $Server `
        -SamAccountName EdwardN `
        -Name 'Edward Norton' `
        -Surname Norton `
        -GivenName Edward `
        -Path "ou=Demo2,dc=bender,dc=priv" `
        -AccountPassword $setpass `
        -ChangePasswordAtLogon $True `
        -Enabled $True -Verbose

Get-ADuser -Filter 'samaccountname -eq "edwardn"'|ft distinguishedName,identity

$DN=(Get-ADuser -Filter 'samaccountname -eq "edwardn"').distinguishedName

## Set-ADUser -Enabled $false -SamAccountName EdwardN -Identity $DN

$NewUser=(Get-ADuser -Filter 'samaccountname -eq "edwardn"').samaccountname

Get-ADObject -Filter * -SearchBase "OU=demo2,dc=bender,dc=priv"

#Add mbender99 to mbender99-Admins-GS group
Add-ADGroupMember `
    -Server $Server `
    -Identity bender-Admins-GS `
    -Members $NewUser `
    -Verbose

#add mbender99 to Domain Admins
Add-ADGroupMember `
    -Server $Server `
    -Identity "Domain Admins" `
    -Members $NewUser `
    -Verbose

#create New GPO 
New-GPO `
    -Server $Server `
    -name Set-IE-HomePage `
    -Verbose

#Link GPO to OU
New-gplink `
    -Server $Server `
    -name Set-IE-HomePage `
    -Target "OU=Domain Controllers,dc=bender,dc=priv" `
    -LinkEnabled Yes `
    -Verbose

#Set GPO Settings
Set-GPRegistryValue `
    -Server $Server `
    -Name Set-IE-HomePage `
     -key 'HKCU\Software\Microsoft\Windows\Microsoft\Internet Explorer\Main' `
     -ValueName 'Start Page' `
     -Type String `
     -value http://madisoncollege.edu `
     -Verbose

Set-GPRegistryValue `
    -Server $Server `
    -Name Set-IE-HomePage `
     -key 'HKCU\Software\Microsoft\Windows\Microsoft\Internet Explorer\Main' `
     -ValueName 'Default_Page_URL' `
     -Type String `
     -value http://madisoncollege.edu `
     -Verbose

     # HKCU\Software\Policies\Microsoft\Internet Explorer\Control Panel!HomePage; HKCU\Software\Policies\Microsoft\Internet Explorer\Main!Start Page 



