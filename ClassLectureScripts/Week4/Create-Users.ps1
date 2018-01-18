#Create-Users.ps1
#Script for creating AD users from a csv file formatted as follows:
#All Values Hard Coded

#UserSetup
    $SetPass = read-host -Prompt 'Enter Password' -assecurestring
    $Users =Import-CSV Y:\week3\DemoUsers.csv 
    $cred = Get-Credential

#ForEach loop creates users from CSV file
    ForEach ($user in $users){ 
    New-ADUser `
        -Credential $cred `
        -Path $user.DistinguishedName `
        -department $user.Department `
        -SamAccountName $user.SamAccountName `
        -Name $user.Name `
        -Surname $user.Surname `
        -GivenName $user.GivenName `
        -UserPrincipalName $user.UserPrincipalName `
        -City $user.city `
        -ChangePasswordAtLogon $False `
        -AccountPassword $SetPass `
        -Enabled $False -Verbose
    $CN="Cn="+$USER.Name+","+$user.DistinguishedName
    Set-ADObject -Identity $CN -ProtectedFromAccidentalDeletion $False -Verbose
    Add-ADGroupMember -Identity $User.Department -Members $user.SamAccountName
        }

