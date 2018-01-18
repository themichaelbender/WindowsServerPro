#region - IIS Demo
    Install-WindowsFeature Web-Server

    Expand-Archive -Path C:\scripts\Week10\website.zip -DestinationPath c:\inetpub\wwwroot -Force

    Restart-Service -Name W3SVC

    start iexplore.exe http://localhost
#endregion
#region -Creating a Profile Path

#IMPORTANT: Create File Share BEFORE logging on as user with Profile
$prof = "c:\shares\userdata"
$username = "tu1"

#create Share
    mkdir $prof

    New-SmbShare -Path $prof -Name Users -ChangeAccess "bender\Domain Users"

#Set Profile path
    Set-ADUser -ProfilePath \\ServerA\Users\$username\Profile\$Username -Identity $username -Verbose

#Bulk Set Profile Path
    $users = get-aduser -filter * -SearchBase "OU=Users,OU=Madison,OU=CompanyOU,dc=bender,dc=priv"
    
    foreach ($user in $Users) {
    
        $username = $user.SamAccountName
        $username
    
        Set-ADUser -ProfilePath \\ServerA\Users\$username\Profile\$Username -Identity $username -Verbose
    }
    get-aduser -properties * -filter * -SearchBase "OU=Users,OU=Madison,OU=CompanyOU,dc=bender,dc=priv"|
        FT SamAccountName,ProfilePath
#endregion
