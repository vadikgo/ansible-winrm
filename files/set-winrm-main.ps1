# join all scripts to one command

$groupName = "Remote Management Users"
$VerbosePreference = "Continue"


Push-Location(Split-Path($MyInvocation.MyCommand.Path))

.\ConfigureRemotingForAnsible.ps1

.\create-group.ps1 $groupName
echo "Local group $groupname added"

.\Add-PoShEndpointAccess.ps1 -SamAccountName $groupName -EndpointName Microsoft.PowerShell

$arc = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
if ( $arc -eq "64-bit") {
  .\Add-PoShEndpointAccess.ps1 -SamAccountName $groupName -EndpointName Microsoft.PowerShell32
}
.\Add-PoShEndpointAccess.ps1 -SamAccountName $groupName -EndpointName Microsoft.PowerShell.Workflow
Get-Service -Name WinRM | Restart-Service
.\grant-winrm-remote.ps1 $groupName

.\Set-WmiNamespaceSecurity.ps1 root/cimv2 add $groupName Enable,RemoteAccess

Pop-Location
