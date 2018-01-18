#Demos - Administering Active Directory
#region - Create default environment
    #Create CimSession
    $cim = New-CimSession -ComputerName ServerA -Credential (get-credential)
    
    #Setup Files located at c:\shares\Demos\Setup & Create \\ServerA\demos share
        Invoke-Command -ComputerName ServerA {
            mkdir c:\shares\demos\setup; New-SmbShare -Path c:\shares\demos -Name Demos -FullAccess 'Bender\domain users'}

    #Add Printers
        Add-PrinterDriver -Name 'Dell 1130 Laser Printer' -ComputerName ServerA -Verbose

        Add-Printer `
            -Name 'WB-Demo-1' `
            -PortName 'file:' `
            -Comment 'This is a demo Printer' `
            -DriverName 'Dell 1130 Laser Printer' `
            -ComputerName ServerA `
            -Shared -ShareName 'WB-Demo-1'

        Add-Printer `
            -Name 'WB-Demo-2' `
            -PortName 'LPT2:' `
            -Comment 'This is a demo Printer' `
            -DriverName 'Dell 1130 Laser Printer' `
            -ComputerName ServerA `
            -Shared -ShareName 'WB-Demo-2'

    #Add AD Objects
        #Add OUs
        New-ADOrganizationalUnit `
            -Name CompanyOU `
            -path "DC=Bender,DC=priv"
        New-ADOrganizationalUnit `
            -Name Austin `
            -Path "OU=CompanyOU,DC=Bender,DC=priv"
        New-ADOrganizationalUnit `
            -Name Madison `
            -path "OU=CompanyOU,DC=Bender,DC=priv"
        New-ADOrganizationalUnit `
            -name Computers `
            -path "OU=Madison,OU=CompanyOU,DC=Bender,DC=priv"
        New-ADOrganizationalUnit `
            -Name Users `
            -Path "OU=Madison,OU=CompanyOU,DC=Bender,DC=priv"
        New-ADOrganizationalUnit `
            -Name Member-Servers `
            -path "Ou=Computers,OU=Madison,OU=CompanyOU,DC=Bender,DC=priv"

#endregion - Create Default Environment

#region Verify Environment
    cls

    Get-ADObject -SearchBase "OU=CompanyOU,DC=Bender,DC=priv" -Filter *|ft

    get-printer |ft

    get-smbshare -Name Demos -CimSession $cim

    Get-DhcpServerv4Scope -ComputerName ServerA | ft
#endregion

#File
#region - Shares
    #Folder Share Groups
    New-ADGroup -Name 'Folder-Share-Read' `
        -GroupScope DomainLocal `
        -GroupCategory Security
    
    New-ADGroup -name 'Folder-Share-Change' `
        -GroupScope DomainLocal `
        -GroupCategory Security
    
    #View Shares on Server
    $cimsession =New-CimSession -ComputerName ServerA
    
    get-smbshare -CimSession $cimsession

    get-smbshare -CimSession $cimsession -Name Demos | fl

    Get-SmbShareAccess -CimSession $cimsession -Name Demos | fl
    
    #New Share Creation
    new-item -ItemType Directory -Path \\ServerA\demos\Demo-FileServices

    New-SmbShare -Name SharedFolder `
        -CimSession $cimsession `
        -Path c:\shares\demos\Demo-FileServices `
        -Description 'This is a shared directory for users.' `
        -FullAccess 'builtin\administrators' `
        -ChangeAccess 'Bender\Folder-Share-Change' `
        -ReadAccess 'Bender\Folder-Share-Read' `
        -FolderEnumerationMode AccessBased

    get-smbshare -CimSession $cimsession -Name SharedFolder | Get-SmbShareAccess

    New-SmbMapping -LocalPath x: -RemotePath \\ServerA\SharedFolder

#endregion

#region - NTFS Permissions with icacls
    #working with Permissions using icacls
    
    icacls /?
    #a sequence of simple rights:
    #            N - no access
    #            F - full access
    #            M - modify access
    #            RX - read and execute access
    #            R - read-only access
    #            W - write-only access
    #            D - delete access
    
    Enter-PSSession -ComputerName ServerA

        icacls \\ServerA\demos\Demo-FileServices\
      
        icacls \\ServerA\demos\Demo-FileServices /grant mbtest:F
    
        icacls \\ServerA\demos\Demo-FileServices /grant Folder-Share-Change:M

        icacls \\ServerA\demos\Demo-FileServices /grant Folder-Share-Read:RX

        icacls \\ServerA\demos\Demo-FileServices
    
    #Copying File Permissions File Permissions
    get-acl \\ServerA\demos\Demo-FileServices | fl
    
    New-Item -ItemType directory -Name Demo-FileServices2 -Path \\ServerA\demos
    
    (get-acl -Path \\ServerA\demos\Demo-FileServices\).Access|
        ft AccessControlType,Identityreference

    (get-acl -Path \\ServerA\demos\Demo-FileServices2\).Access|
        ft AccessControlType,Identityreference
     
     $ACL = get-acl -Path \\ServerA\demos\Demo-FileServices\
     Set-Acl -Path \\ServerA\demos\Demo-FileServices2\ -AclObject $ACL
     
     
    (get-acl -Path \\ServerA\demos\Demo-FileServices\).Access|
        ft AccessControlType,Identityreference

    (get-acl -Path \\ServerA\demos\Demo-FileServices2\).Access|
        ft AccessControlType,Identityreference 
#endregion

#region - Working with Printers
    #View Printers
        Get-Printer -ComputerName ServerA

    #Adding a Printer to Server 
       #View drivers in Driver store
        Invoke-command -ComputerName ServerA {
         Get-windowsdriver -online -all |
             where {($_.classname -like “*print*”) -and ($_.ProviderName -like "*Lexmark*")}|
                fl Driver,Provider,OriginalFilename
        }

        notepad '\\ServerA\c$\windows\system32\driverstore\FileRepository\prnlxclv.inf_amd64_c29830f978cd4b85\prnlxclv.inf'
    
        #Add Driver
        Add-PrinterDriver -Name "Lexmark C734 Class Driver" -ComputerName ServerA
    
        get-printerdriver -ComputerName ServerA

        #Add Port
        add-printerport `
            -Name '192.168.95.201' `
            -PrinterHostAddress '192.168.95.201' `
            -ComputerName ServerA

        Get-PrinterPort -ComputerName ServerA

        #Add Printer
        Add-Printer `
            -ComputerName ServerA `
            -DriverName 'Lexmark C734 Class Driver' `
            -PortName '192.168.95.201' `
            -Comment 'Use this printer for default printer permissions' `
            -Shared -ShareName 'LexMarkC734-1' `
            -Name 'LexMarkC734-1' `
            -Published
        
        #Verify
        Get-Printer -ComputerName ServerA
        Get-Printer -ComputerName ServerA -Name 'LexMarkC734-1' | FL

        Get-Printer -ComputerName ServerA | ? Published

#endregion - Print 
   
#region Demo2 - Gathering information in Active Directory
    #View AD Hieararchy
    get-adobject -Filter * |ft name,objectclass
    
    Get-ADObject -Filter {ObjectClass -eq "OrganizationalUnit"}
    
    Get-ADObject -SearchBase 'OU=CompanyOU,DC=Bender,DC=Priv' `
        -Filter {ObjectClass -eq "OrganizationalUnit"}|
        FT Name,DistinguishedName -AutoSize
    
    #Find Objects
    get-adobject -Filter * | gm
    
    get-adobject -Filter * -Properties * | gm # -properties * brings extended Properties
    
    Get-ADObject -Filter {(name -like '*bender*') -and (ObjectClass -eq 'user')} -Properties *|
        ft Name,DistinguishedName
    
    #Finding specific user objects
    Get-ADObject `
        -Identity 'CN=Mike Bender-Admin,OU=Users,OU=Madison,OU=CompanyOU,DC=Bender,DC=priv' `
        -Properties * | FL

    get-adobject -Filter {SamAccountName -eq 'mbadmin'} -Properties * | FL

    #Add OU for Users and Computer under Austin
    New-ADOrganizationalUnit `
        -Name Users `
        -Path 'OU=Austin,OU=CompanyOU,DC=Bender,DC=Priv' `
        -Verbose
    
    New-ADOrganizationalUnit `
        -Name Computers `
        -Path 'OU=Austin,OU=CompanyOU,DC=Bender,DC=Priv' `
        -Verbose
    
    Get-ADObject -SearchBase 'OU=CompanyOU,DC=Bender,DC=Priv' `
        -Filter {ObjectClass -eq "OrganizationalUnit"}
#endregion Demo2

#region Demo3 - users

#Get User Information
get-aduser -Filter * -Properties *| gm

get-ADUser -Filter * -Properties *| fl Name,DistinguishedName,City

Get-ADUser -SearchBase 'OU=CompanyOU,DC=Bender,DC=Priv' -Filter *|
     ft Name,DistinguishedName -AutoSize

Get-ADUser -Filter {Name -like '*mb*'}  -Properties * |
 ft Name,DistinguishedName -AutoSize

Get-aduser -Identity 'mbadmin' -Properties *

#Find all users in Madison and in IT department; Export to CSV file 

get-aduser -Filter {(City -eq 'Madison') -and (department -eq 'IT')} -Properties *|
    select-object Name,City,Enabled|
    export-csv -Path C:\Scripts\Madusers.csv

notepad C:\Scripts\Madusers.csv

#Create a New user with PowerShell
    $SetPass = read-host -assecurestring
    New-ADUser `
        -Server ServerA `
        -Path 'OU=Users,OU=Madison,OU=CompanyOU,DC=Bender,DC=Priv' `
        -department IT `
        -SamAccountName TimJ `
        -Name Timj `
        -Surname Jones `
        -GivenName Tim `
        -UserPrincipalName Timj@Bender.priv `
        -City Madison `
        -AccountPassword $setpass `
        -ChangePasswordAtLogon $True `
        -Enabled $False -Verbose 
    
    Get-ADUser -Identity 'Timj'

#Modify single user object
Set-ADuser -Identity 'timJ' -Enabled $True -Description 'Tim is a demo User' -Title 'Demo User'
Get-ADUser -Identity 'Timj' -Properties *| FL Name,Description,Title,Enabled

#Find users in an OU and enable them
    get-aduser -Filter * `
        -SearchBase 'OU=Users,OU=Madison,OU=CompanyOU,DC=Bender,DC=Priv'|
        ft Name,SamAccountName,Enabled -AutoSize

#endregion Demo3

#region Demo4 - Computers

#Find all computers in domain
Get-ADComputer -Filter * -Properties * |ft Name,DNSHostName,OperatingSystem

Get-adcomputer -Filter {OperatingSystem -like "Windows 10*"} -Properties *|
    ft Name,DNSHostName,OperatingSystem

#View information for server1
Get-ADComputer -Identity 'Client1' -Properties *

#Modify Description on Computer 
Set-ADComputer -Identity 'Client1' -Description 'This is a Client Computer for Remote Admin' -PassThru|
    Get-ADComputer -Properties * | ft Name,DNSHostName,Description

#Move computer to OU
Get-ADComputer -Identity Server1 |
    Move-ADObject -TargetPath 'OU=Computers,OU=Austin,OU=CompanyOU,DC=Bender,DC=Priv'

Get-ADComputer -Identity Server1 -Properties * | FT Name,DistinguishedName
#endregion Demo4

#region Demo5 - Groups
#View all Groups
Get-ADGroup -Filter * -Properties *| FT Name,Description -AutoSize -Wrap

#View Specific Group
get-adgroup -Identity 'Domain Users' -Properties *

#create a new group for IT users
New-ADGroup `
    -Name 'IT Users' `
    -GroupCategory Security `
    -GroupScope Global

Set-ADGroup -Identity 'IT Users' -Description 'This is a group for IT Users'

get-adgroup -Identity 'IT Users' -Properties * | fl Name,Description

#View Group Membership of Group
Get-ADGroupMember -Identity 'Domain Users'|ft Name

#Add Users to Group for IT
Get-ADGroupMember -Identity 'IT Users'

Add-ADGroupMember `
    -Identity 'IT Users' `
    -Members (get-aduser -Filter {department -eq 'IT'})

Get-ADGroupMember -Identity 'IT Users'|ft Name

#Remove IT Users Group
Remove-ADGroup -Identity 'IT Users'

#endregion Demo5

#Bulk Creating Users w/ CSV file
C:\Scripts\Create-Users.ps1 