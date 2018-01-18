#Create-UsersFromCSVv1.ps1
#Parametized script for creating users with a specified CSV file

#Defined Parameters
    param (
    $File = 'y:\Week3\DemoUsers.csv'
)
#Prompted Variables
    $SetPass = (read-host -Prompt 'Enter Password' -assecurestring)
    $Cred = (Get-Credential)
    $Users = (Import-CSV $file)

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
    Add-ADGroupMember -Identity $user.Department -Members $user.SamAccountName -Verbose
        }
