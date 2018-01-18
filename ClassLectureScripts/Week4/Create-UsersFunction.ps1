#Create-UsersFromCSVv2.ps1
#Advanced Function for creating users from CSV

<#
.Synopsis
   Create AD Users from a CSV file
.DESCRIPTION
   This function will create active directory users from a CSV file as well as other properly 
   formatted sources for Users. It includes the abilities to set the password for user securely, set the AD credential
   for creation of user objects, and set the file path location for the CSV file.

   Defaults for the parameter is as follows:
    $File = 'y:\Week3\DemoUsers.csv',
    
   Default Variables will be created based on the following: 
    $SetPass = (read-host -Prompt 'Enter Password' -assecurestring) ,
    $Cred = (Get-Credential) ,
    $Users = (Import-CSV $file)

.EXAMPLE
   PS>Create-CustomADUsers
   
   This will use the default options set for the function parameters

.EXAMPLE
   PS>Create-CustomADUsers -File Y:\Week04\Users.csv

   This will create users using the input of the CSV location
#>
function Create-ADUsers
{
    [CmdletBinding()]
    
    Param
    (
        # File Parameter to specificy location of CSV file
        [Parameter(Mandatory=$False,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('filepath','path')]
        [string]$File = 'y:\Week3\DemoUsers.csv'


    )

    Begin
    {
        $SetPass = (read-host -Prompt 'Enter Password' -assecurestring)
        $Cred = (Get-Credential)
        $Users = (Import-CSV $file)
    }
    Process
    {
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
    }
    End
    {
   
    }
}
