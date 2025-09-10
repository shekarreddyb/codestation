# Prefix to search for
$prefix = "CA10"

# Distinguished Name of the CLD OU
$parentOU = "OU=CLD,DC=yourdomain,DC=com"

# Get immediate child OUs under CLD and filter by prefix
Get-ADOrganizationalUnit -SearchBase $parentOU -SearchScope OneLevel -Filter "Name -like '$prefix*'" |
    Select-Object Name, DistinguishedName