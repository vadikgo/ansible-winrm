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
