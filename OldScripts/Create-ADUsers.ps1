###########################################################
# AUTHOR  : Marius / Hican - http://www.hican.nl - @hicannl 
# DATE    : 26-04-2012 
# COMMENT : This script creates new Active Directory users
#           including different kind of properties based
#           on an input_create_ad_users.csv.
###########################################################
Import-Module ActiveDirectory
# Get current directory and set import file in variable
$path     = Split-Path -parent $MyInvocation.MyCommand.Definition
$newpath  = $path + "\import_create_ad_users.csv"
# Define variables
$log      = $path + "\create_ad_users.log"
$date     = Get-Date
$i        = 0
# Change this to the location you want the users to be created in your AD
$location = "OU=Test,OU=Users,DC=hican,DC=nl"
# FUNCTIONS
Function createUsers
{
  "Created following users (on " + $date + "): " | Out-File $log -append
  "--------------------------------------------" | Out-File $log -append
  Import-CSV $newpath | ForEach-Object { 
    # A check for the country, because those were full names and need 
    # to be landcodes in order for AD to accept them. I used Netherlands 
    # as example
    If($_.CO -eq "Netherlands")
    {
      $_.CO = "NL"
    }
    # Replace dots / points (.) in names, because AD will error when a 
    # name ends with a dot (and it looks cleaner as well)
    $replace = $_.CN.Replace(".","")
    If($replace.length -lt 4)
    {
      $lastname = $replace
    }
    Else
    {
      $lastname = $replace.substring(0,4)
    }
    # Create sAMAccountName according to this 'naming convention':
    # <FirstLetterInitials><FirstFourLettersLastName> for example
    # hhica
    $sam = $_.Initials.substring(0,1).ToLower() + $lastname.ToLower()
    Try   { $exists = Get-ADUser -LDAPFilter "(sAMAccountName=$sam)" }
    Catch { }
    If(!$exists)
    {
      $i++
      # Set all variables according to the table names in the Excel 
      # sheet / import CSV. The names can differ in every project, but 
      # if the names change, make sure to change it below as well.
      $setpass = ConvertTo-SecureString -AsPlainText $_.Password -force
      New-ADUser $sam -GivenName $_.GivenName -Initials $_.Initials `
      -Surname $_.SN -DisplayName $_.DisplayName -Office $_.OfficeName `
      -Description $_.Description -EmailAddress $_.Mail `
      -StreetAddress $_.StreetAddress -City $_.L `
      -PostalCode $_.PostalCode -Country $_.CO -UserPrincipalName $_.UPN `
      -Company $_.Company -Department $_.Department -EmployeeID $_.ID `
      -Title $_.Title -OfficePhone $_.Phone -AccountPassword $setpass
 
      # Set an ExtensionAttribute
      $dn  = (Get-ADUser $sam).DistinguishedName
      $ext = [ADSI]"LDAP://$dn"
      If ($_.ExtensionAttribute1 -ne "" -And $_.ExtensionAttribute1 -ne $Null)
      {
        $ext.Put("extensionAttribute1", $_.ExtensionAttribute1)
        $ext.SetInfo()
      }
 
      # Move the user to the OU you set above. If you don't want to
      # move the user(s) and just create them in the global Users
      # OU, comment the string below
      Move-ADObject -Identity $dn -TargetPath $location
 
      # Rename the object to a good looking name (otherwise you see
      # the 'ugly' shortened sAMAccountNames as a name in AD. This 
      # can't be set right away (as sAMAccountName) due to the 20
      # character restriction
      $newdn = (Get-ADUser $sam).DistinguishedName
      Rename-ADObject -Identity $newdn -NewName $_.CN
 
      $output  = $i.ToString() + ") Name: " + $_.CN + "  sAMAccountName: " 
      $output += $sam + "  Pass: " + $_.Password
      $output | Out-File $log -append
    }
    Else
    {
      "SKIPPED - ALREADY EXISTS OR ERROR: " + $_.CN | Out-File $log -append
    }
  }
  "----------------------------------------" + "`n" | Out-File $log -append
}
# RUN SCRIPT
createUsers
#Finished