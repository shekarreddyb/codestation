param(
    [Parameter(Mandatory = $true)]
    [string]$OU,  # Distinguished Name of the OU (e.g., "OU=Users,DC=domain,DC=com")

    [Parameter(Mandatory = $true)]
    [string]$GroupNamePrefix  # Prefix to match (e.g., "HR_")
)

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $groups = Get-ADGroup -Filter "Name -like '$GroupNamePrefix*'" -SearchBase $OU -SearchScope Subtree |
        Select-Object Name, SamAccountName, DistinguishedName

    if ($groups) {
        Write-Host "Groups in OU '$OU' starting with '$GroupNamePrefix':" -ForegroundColor Cyan
        $groups | Format-Table -AutoSize
    } else {
        Write-Host "No groups found in OU '$OU' starting with '$GroupNamePrefix'." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
}