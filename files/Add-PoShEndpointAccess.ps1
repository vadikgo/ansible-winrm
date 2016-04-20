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
