#UserSetup
    $SetPass = read-host -Prompt 'Enter Password' -assecurestring
    $Users =Import-CSV C:\scripts\week3\DemoUsers.csv 
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
        }
#Set accounts as enabled
    set-aduser -Identity 'mbadmin' -enable $true

#Add mbadmin account to Admin Groups
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'mbadmin'
    Add-ADGroupMember -Identity 'Enterprise Admins' -Members 'mbadmin'
    Add-ADGroupMember -Identity 'Schema Admins' -Members 'mbadmin'

Get-ADUser -Filter * | FT