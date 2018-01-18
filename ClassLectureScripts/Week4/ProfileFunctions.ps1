#ProfileFunctions

#Functions

Function sweep { Get-ADObject -Filter "ObjectClass -ne 'OrganizationalUnit'" -SearchBase "OU=Users,OU=Madison,OU=CompanyOU,DC=Bender,DC=Priv" | 
                    Remove-ADObject -Verbose
                }
Function NewGroups {
                    New-ADGroup -Name IT -GroupCategory Security -GroupScope Global -Path "OU=Users,OU=Madison,OU=CompanyOU,DC=Bender,DC=Priv" -verbose
                    New-ADGroup -Name Development -GroupCategory Security -GroupScope Global -Path "OU=Users,OU=Madison,OU=CompanyOU,DC=Bender,DC=Priv" -verbose
                    New-ADGroup -Name Operations -GroupCategory Security -GroupScope Global -Path "OU=Users,OU=Madison,OU=CompanyOU,DC=Bender,DC=Priv" -verbose
                    }

Function ADUsers { Get-ADUser -Filter * -SearchBase "OU=Users,OU=Madison,OU=CompanyOU,DC=Bender,DC=Priv" | FT}