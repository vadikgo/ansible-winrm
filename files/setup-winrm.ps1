# Configure Windows for remote WinRM
# setup-winrm.ps {pcname1}
# pcname1 - remote windows hostname, empty for current host

Param (
    [string]$HostName = $env:COMPUTERNAME
)

$SB={

$groupName = "Remote Management Users"
#$VerbosePreference = "Continue"



Function ConfigureRemotingForAnsible {

# Configure a Windows host for remote management with Ansible
# -----------------------------------------------------------
#
# This script checks the current WinRM/PSRemoting configuration and makes the
# necessary changes to allow Ansible to connect, authenticate and execute
# PowerShell commands.
#
# Set $VerbosePreference = "Continue" before running the script in order to
# see the output messages.
# Set $SkipNetworkProfileCheck to skip the network profile check.  Without
# specifying this the script will only run if the device's interfaces are in
# DOMAIN or PRIVATE zones.  Provide this switch if you want to enable winrm on
# a device with an interface in PUBLIC zone.
#
# Written by Trond Hindenes <trond@hindenes.com>
# Updated by Chris Church <cchurch@ansible.com>
# Updated by Michael Crilly <mike@autologic.cm>
#
# Version 1.0 - July 6th, 2014
# Version 1.1 - November 11th, 2014
# Version 1.2 - May 15th, 2015

Param (
    [string]$SubjectName = $env:COMPUTERNAME,
    [int]$CertValidityDays = 365,
    [switch]$SkipNetworkProfileCheck,
    $CreateSelfSignedCert = $true
)

Function New-LegacySelfSignedCert
{
    Param (
        [string]$SubjectName,
        [int]$ValidDays = 365
    )

    $name = New-Object -COM "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$SubjectName", 0)

    $key = New-Object -COM "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 1024
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.Create()

    $serverauthoid = New-Object -COM "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = New-Object -COM "X509Enrollment.CObjectIds.1"
    $ekuoids.Add($serverauthoid)
    $ekuext = New-Object -COM "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = New-Object -COM "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = (Get-Date).AddDays(-1)
    $cert.NotAfter = $cert.NotBefore.AddDays($ValidDays)
    $cert.X509Extensions.Add($ekuext)
    $cert.Encode()

    $enrollment = New-Object -COM "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")

    # Return the thumbprint of the last installed certificate;
    # This is needed for the new HTTPS WinRM listerner we're
    # going to create further down.
    Get-ChildItem "Cert:\LocalMachine\my"| Sort-Object NotBefore -Descending | Select -First 1 | Select -Expand Thumbprint
}

# Setup error handling.
Trap
{
    $_
    Exit 1
}
$ErrorActionPreference = "Stop"

# Detect PowerShell version.
If ($PSVersionTable.PSVersion.Major -lt 3)
{
    Throw "PowerShell version 3 or higher is required."
}

# Find and start the WinRM service.
Write-Verbose "Verifying WinRM service."
If (!(Get-Service "WinRM"))
{
    Throw "Unable to find the WinRM service."
}
ElseIf ((Get-Service "WinRM").Status -ne "Running")
{
    Write-Verbose "Starting WinRM service."
    Start-Service -Name "WinRM" -ErrorAction Stop
}

# WinRM should be running; check that we have a PS session config.
If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener)))
{
  if ($SkipNetworkProfileCheck) {
    Write-Verbose "Enabling PS Remoting without checking Network profile."
    Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
  }
  else {
    Write-Verbose "Enabling PS Remoting"
    Enable-PSRemoting -Force -ErrorAction Stop
  }
}
Else
{
    Write-Verbose "PS Remoting is already enabled."
}

# Make sure there is a SSL listener.
$listeners = Get-ChildItem WSMan:\localhost\Listener
If (!($listeners | Where {$_.Keys -like "TRANSPORT=HTTPS"}))
{
    # HTTPS-based endpoint does not exist.
    If (Get-Command "New-SelfSignedCertificate" -ErrorAction SilentlyContinue)
    {
        $cert = New-SelfSignedCertificate -DnsName $SubjectName -CertStoreLocation "Cert:\LocalMachine\My"
        $thumbprint = $cert.Thumbprint
        Write-Host "Self-signed SSL certificate generated; thumbprint: $thumbprint"
    }
    Else
    {
        $thumbprint = New-LegacySelfSignedCert -SubjectName $SubjectName
        Write-Host "(Legacy) Self-signed SSL certificate generated; thumbprint: $thumbprint"
    }

    # Create the hashtables of settings to be used.
    $valueset = @{}
    $valueset.Add('Hostname', $SubjectName)
    $valueset.Add('CertificateThumbprint', $thumbprint)

    $selectorset = @{}
    $selectorset.Add('Transport', 'HTTPS')
    $selectorset.Add('Address', '*')

    Write-Verbose "Enabling SSL listener."
    New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
}
Else
{
    Write-Verbose "SSL listener is already active."
}

# Check for basic authentication.
$basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where {$_.Name -eq "Basic"}
If (($basicAuthSetting.Value) -eq $false)
{
    Write-Verbose "Enabling basic auth support."
    Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
}
Else
{
    Write-Verbose "Basic auth is already enabled."
}

# Configure firewall to allow WinRM HTTPS connections.
$fwtest1 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS"
$fwtest2 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS" profile=any
If ($fwtest1.count -lt 5)
{
    Write-Verbose "Adding firewall rule to allow WinRM HTTPS."
    netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow
}
ElseIf (($fwtest1.count -ge 5) -and ($fwtest2.count -lt 5))
{
    Write-Verbose "Updating firewall rule to allow WinRM HTTPS for any profile."
    netsh advfirewall firewall set rule name="Allow WinRM HTTPS" new profile=any
}
Else
{
    Write-Verbose "Firewall rule already exists to allow WinRM HTTPS."
}

# Test a remoting connection to localhost, which should work.
$httpResult = Invoke-Command -ComputerName "localhost" -ScriptBlock {$env:COMPUTERNAME} -ErrorVariable httpError -ErrorAction SilentlyContinue
$httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

$httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions -ErrorVariable httpsError -ErrorAction SilentlyContinue

If ($httpResult -and $httpsResult)
{
    Write-Verbose "HTTP: Enabled | HTTPS: Enabled"
}
ElseIf ($httpsResult -and !$httpResult)
{
    Write-Verbose "HTTP: Disabled | HTTPS: Enabled"
}
ElseIf ($httpResult -and !$httpsResult)
{
    Write-Verbose "HTTP: Enabled | HTTPS: Disabled"
}
Else
{
    Throw "Unable to establish an HTTP or HTTPS remoting session."
}
Write-Verbose "PS Remoting has been successfully configured for Ansible."
}

Function create-group{
  Param
  (
      [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
      $GroupName
  )
  $computer = $env:COMPUTERNAME
  $adsi = [ADSI]("WinNT://$computer")
  $group = $adsi.Create("Group", $GroupName)
  $group.SetInfo()
  $group.Description = "Remote WinRM Users"
  $group.SetInfo()
}

Function Add-PoShEndpointAccess{
#========================================================================
# Created By: Anders Wahlqvist
# Website: DollarUnderscore (http://dollarunderscore.azurewebsites.net)
#========================================================================
#Add-PoShEndpointAccess.ps1 -SamAccountName "contoso\PoShUsers" -ComputerName MyPoShEndpoint.contoso.com -EndpointName Microsoft.PowerShell32

Param
(
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true)]
    $SamAccountName,

    [Parameter(Mandatory=$false)]
    $ComputerName = '.',

    [Parameter(Mandatory=$false)]
    $EndpointName = 'Microsoft.PowerShell'
)

Process {
    if ($ComputerName -eq '.' -OR $ComputerName -eq "$($env:COMPUTERNAME)") {
            $IdentityObject = New-Object Security.Principal.NTAccount $SamAccountName
            try {
                $sid = $IdentityObject.Translate([Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                throw "Failed to translate $SamAccountName to a valid SID."
            }

            try {
                $PSSConfig = Get-PSSessionConfiguration -Name $EndpointName -ErrorAction Stop
            }
            catch {
                if ($_.Tostring() -like '*access is denied*') {
                    throw 'You need to have Admin-access to run this command!'
                }
            }

            $existingSDDL = $PSSConfig.SecurityDescriptorSDDL
            $isContainer = $false
            $isDS = $false

            $SecurityDescriptor = New-Object -TypeName Security.AccessControl.CommonSecurityDescriptor -ArgumentList $isContainer,$isDS, $existingSDDL
            $accessType = 'Allow'
            $accessMask = 268435456
            $inheritanceFlags = 'none'
            $propagationFlags = 'none'
            $SecurityDescriptor.DiscretionaryAcl.AddAccess($accessType,$sid,$accessMask,$inheritanceFlags,$propagationFlags)

            $null = Set-PSSessionConfiguration -Name $EndpointName -SecurityDescriptorSddl ($SecurityDescriptor.GetSddlForm('All')) -Confirm:$false -Force

    }
    else {
        Invoke-Command -ArgumentList $SamAccountName,$EndpointName -ScriptBlock {
            $IdentityObject = New-Object Security.Principal.NTAccount $args[0]
            $EndpointName = $args[1]

            try {
                $sid = $IdentityObject.Translate([Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                throw "Failed to translate $($args[0]) to a valid SID."
            }

            try {
                $PSSConfig = Get-PSSessionConfiguration -Name $EndpointName -ErrorAction Stop
            }
            catch {
                if ($_.Tostring() -like '*access is denied*') {
                    throw 'You need to have Admin-access and enable CredSSP to run this command remotely!'
                }
            }

            $existingSDDL = $PSSConfig.SecurityDescriptorSDDL
            $isContainer = $false
            $isDS = $false

            $SecurityDescriptor = New-Object -TypeName Security.AccessControl.CommonSecurityDescriptor -ArgumentList $isContainer,$isDS, $existingSDDL
            $accessType = 'Allow'
            $accessMask = 268435456
            $inheritanceFlags = 'none'
            $propagationFlags = 'none'
            $SecurityDescriptor.DiscretionaryAcl.AddAccess($accessType,$sid,$accessMask,$inheritanceFlags,$propagationFlags)

            $null = Set-PSSessionConfiguration -Name $EndpointName -SecurityDescriptorSddl ($SecurityDescriptor.GetSddlForm('All')) -Confirm:$false -Force -NoServiceRestart

        } -ComputerName $ComputerName
    }
}

End { }
}


Function grant-winrm-remote {
# grant-winrm-remote.ps1 group_name
  Param
  (
      [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
      $SamAccountName
  )
  $sid=(New-Object Security.Principal.NTAccount $SamAccountName).Translate([Security.Principal.SecurityIdentifier]).Value
  $args = @("set",
            "winrm/config/service",
            "@{RootSDDL=`"O:NSG:BAD:P(A;;GX;;;$sid)(A;;GA;;;BA)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD))`"}"
  )
  &"C:\Windows\System32\winrm.cmd" $args
}

Function Set-WmiNamespaceSecurity {
# Copyright (c) Microsoft Corporation.  All rights reserved.
# For personal use only.  Provided AS IS and WITH ALL FAULTS.

# Set-WmiNamespaceSecurity.ps1
# Example: Set-WmiNamespaceSecurity root/cimv2 add steve Enable,RemoteAccess

Param ( [parameter(Mandatory=$true,Position=0)][string] $namespace,
    [parameter(Mandatory=$true,Position=1)][string] $operation,
    [parameter(Mandatory=$true,Position=2)][string] $account,
    [parameter(Position=3)][string[]] $permissions = $null,
    [bool] $allowInherit = $true,
    [bool] $deny = $false,
    [string] $computerName = ".",
    [System.Management.Automation.PSCredential] $credential = $null)

Process {
    $ErrorActionPreference = "Stop"

    Function Get-AccessMaskFromPermission($permissions) {
        $WBEM_ENABLE            = 1
                $WBEM_METHOD_EXECUTE = 2
                $WBEM_FULL_WRITE_REP   = 4
                $WBEM_PARTIAL_WRITE_REP              = 8
                $WBEM_WRITE_PROVIDER   = 0x10
                $WBEM_REMOTE_ACCESS    = 0x20
                $WBEM_RIGHT_SUBSCRIBE = 0x40
                $WBEM_RIGHT_PUBLISH      = 0x80
        $READ_CONTROL = 0x20000
        $WRITE_DAC = 0x40000

        $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE,$WBEM_METHOD_EXECUTE,$WBEM_FULL_WRITE_REP,`
            $WBEM_PARTIAL_WRITE_REP,$WBEM_WRITE_PROVIDER,$WBEM_REMOTE_ACCESS,`
            $READ_CONTROL,$WRITE_DAC
        $WBEM_RIGHTS_STRINGS = "Enable","MethodExecute","FullWrite","PartialWrite",`
            "ProviderWrite","RemoteAccess","ReadSecurity","WriteSecurity"

        $permissionTable = @{}

        for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
            $permissionTable.Add($WBEM_RIGHTS_STRINGS[$i].ToLower(), $WBEM_RIGHTS_FLAGS[$i])
        }

        $accessMask = 0

        foreach ($permission in $permissions) {
            if (-not $permissionTable.ContainsKey($permission.ToLower())) {
                throw "Unknown permission: $permission`nValid permissions: $($permissionTable.Keys)"
            }
            $accessMask += $permissionTable[$permission.ToLower()]
        }

        $accessMask
    }

    if ($PSBoundParameters.ContainsKey("Credential")) {
        $remoteparams = @{ComputerName=$computer;Credential=$credential}
    } else {
        $remoteparams = @{ComputerName=$computerName}
    }

    $invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@"} + $remoteParams

    $output = Invoke-WmiMethod @invokeparams -Name GetSecurityDescriptor
    if ($output.ReturnValue -ne 0) {
        throw "GetSecurityDescriptor failed: $($output.ReturnValue)"
    }

    $acl = $output.Descriptor
    $OBJECT_INHERIT_ACE_FLAG = 0x1
    $CONTAINER_INHERIT_ACE_FLAG = 0x2

    $computerName = (Get-WmiObject @remoteparams Win32_ComputerSystem).Name

    if ($account.Contains('\')) {
        $domainaccount = $account.Split('\')
        $domain = $domainaccount[0]
        if (($domain -eq ".") -or ($domain -eq "BUILTIN")) {
            $domain = $computerName
        }
        $accountname = $domainaccount[1]
    } elseif ($account.Contains('@')) {
        $domainaccount = $account.Split('@')
        $domain = $domainaccount[1].Split('.')[0]
        $accountname = $domainaccount[0]
    } else {
        $domain = $computerName
        $accountname = $account
    }

    $getparams = @{Class="Win32_Account";Filter="Domain='$domain' and Name='$accountname'"}

    $win32account = Get-WmiObject @getparams

    if ($win32account -eq $null) {
        throw "Account was not found: $account"
    }

    switch ($operation) {
        "add" {
            if ($permissions -eq $null) {
                throw "-Permissions must be specified for an add operation"
            }
            $accessMask = Get-AccessMaskFromPermission($permissions)

            $ace = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
            $ace.AccessMask = $accessMask
            if ($allowInherit) {
                $ace.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
            } else {
                $ace.AceFlags = 0
            }

            $trustee = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
            $trustee.SidString = $win32account.Sid
            $ace.Trustee = $trustee

            $ACCESS_ALLOWED_ACE_TYPE = 0x0
            $ACCESS_DENIED_ACE_TYPE = 0x1

            if ($deny) {
                $ace.AceType = $ACCESS_DENIED_ACE_TYPE
            } else {
                $ace.AceType = $ACCESS_ALLOWED_ACE_TYPE
            }

            $acl.DACL += $ace.psobject.immediateBaseObject
        }

        "delete" {
            if ($permissions -ne $null) {
                throw "Permissions cannot be specified for a delete operation"
            }

            [System.Management.ManagementBaseObject[]]$newDACL = @()
            foreach ($ace in $acl.DACL) {
                if ($ace.Trustee.SidString -ne $win32account.Sid) {
                    $newDACL += $ace.psobject.immediateBaseObject
                }
            }

            $acl.DACL = $newDACL.psobject.immediateBaseObject
        }

        default {
            throw "Unknown operation: $operation`nAllowed operations: add delete"
        }
    }

    $setparams = @{Name="SetSecurityDescriptor";ArgumentList=$acl.psobject.immediateBaseObject} + $invokeParams

    $output = Invoke-WmiMethod @setparams
    if ($output.ReturnValue -ne 0) {
        throw "SetSecurityDescriptor failed: $($output.ReturnValue)"
    }
}}

echo "Enable WinRM on host"
ConfigureRemotingForAnsible

try {
  create-group $groupName
  echo "Local group $groupname added"
} catch {
  echo "group $groupname already exist"
}

echo "Grant access to Microsoft.PowerShell"
Add-PoShEndpointAccess -SamAccountName $groupName -EndpointName Microsoft.PowerShell

$arc = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
if ( $arc -eq "64-bit") {
  echo "Grant access to Microsoft.PowerShell32"
  Add-PoShEndpointAccess -SamAccountName $groupName -EndpointName Microsoft.PowerShell32
}

echo "Grant access to Microsoft.PowerShell.Workflow"
Add-PoShEndpointAccess -SamAccountName $groupName -EndpointName Microsoft.PowerShell.Workflow

echo "Grant access to configSDDL default"
grant-winrm-remote $groupName

echo "Grant access to WMI"
Set-WmiNamespaceSecurity root/cimv2 add $groupName Enable,RemoteAccess

Get-Service -Name WinRM | Restart-Service
}

if ($HostName -eq '.' -OR $HostName -eq "$($env:COMPUTERNAME)") {
  &$SB
} else {
  $job = Invoke-Command -ScriptBlock $SB -ComputerName $HostName -AsJob
  Get-Job | Wait-Job
  $out = Receive-Job -Job $job
  Get-Job | Remove-Job
}
