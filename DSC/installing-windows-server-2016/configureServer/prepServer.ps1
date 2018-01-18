<# Notes:

Authors: Greg Shields

Goal - Prepare the local machine by installing needed PowerShell Gallery modules.
This script must be run before configureServer.

Disclaimer

This example code is provided without copyright and AS IS.  It is free for you to use and modify.
Note: These demos should not be run as a script. These are the commands that I use in the 
demonstrations and would need to be modified for your environment.

#>

Get-PackageSource -Name PSGallery | Set-PackageSource -Trusted -Force -ForceBootstrap

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

Install-Module xComputerManagement -Force
Install-Module xNetworking -Force

Write-Host "You may now execute '.\configureServer.ps1'"