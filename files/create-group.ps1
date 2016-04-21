# create-group.ps1 group_name

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
