# Reusable helper
function New-NetworkPSDriveSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Server,     # e.g. "filesrv01"
        [Parameter(Mandatory)] [string] $Share,      # e.g. "prodshare"
        [Parameter(Mandatory)] [string] $Name,       # e.g. "P1", must be unique in the session
        [pscredential] $Credential = $null,
        [int] $TimeoutSec = 3,
        [switch] $Persist                           # use this if you want an actual mapped drive letter to persist
    )

    $unc = "\\$Server\$Share"

    # 1) Quick reachability checks (ping + SMB port)
    if (-not (Test-Connection -ComputerName $Server -Quiet -Count 1 -TimeoutSeconds $TimeoutSec)) {
        Write-Warning "Host '$Server' is not reachable (ICMP). Skipping $unc."
        return $false
    }
    # Test SMB (445) — faster fail than letting New-PSDrive hang
    $tnc = Test-NetConnection -ComputerName $Server -Port 445 -WarningAction SilentlyContinue
    if (-not $tnc.TcpTestSucceeded) {
        Write-Warning "SMB port 445 on '$Server' is closed/unreachable. Skipping $unc."
        return $false
    }

    # 2) Check the UNC exists
    if (-not (Test-Path -LiteralPath $unc)) {
        Write-Warning "UNC path '$unc' does not exist or is not accessible. Skipping."
        return $false
    }

    # 3) Remove any stale PSDrive with the same name
    $existing = Get-PSDrive -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-PSDrive -Name $Name -Force -ErrorAction SilentlyContinue
    }

    # 4) Attempt the mapping with robust error handling
    try {
        $args = @{
            Name       = $Name
            PSProvider = 'FileSystem'
            Root       = $unc
            ErrorAction= 'Stop'
        }
        if ($Credential) { $args.Credential = $Credential }
        if ($Persist)    { $args.Persist    = $true }   # requires drive-letter-esque name; PS will map it

        New-PSDrive @args | Out-Null
        Write-Host "Mapped $Name: -> $unc"
        return $true
    }
    catch {
        Write-Warning ("Failed to map {0}: -> {1}. Reason: {2}" -f $Name, $unc, $_.Exception.Message)
        return $false
    }
}

# ---------------------------
# Example: loop through servers and continue on failures
# ---------------------------

$servers = @(
    @{ Server = 'filesrv01'; Share = 'prodshare'  ; Name = 'P1' },
    @{ Server = 'filesrv02'; Share = 'engshare'   ; Name = 'E1' },
    @{ Server = 'filesrv03'; Share = 'backups'    ; Name = 'B1' }
)

# Optional: credential (if needed)
# $cred = Get-Credential

foreach ($s in $servers) {
    $ok = New-NetworkPSDriveSafe -Server $s.Server -Share $s.Share -Name $s.Name `
                                 # -Credential $cred `
                                 -TimeoutSec 3
    if (-not $ok) {
        # Log and continue to next
        Write-Host "Skipping work on \\$($s.Server)\$($s.Share) due to mapping failure."
        continue
    }

    try {
        # Do your work against the mapped drive:
        #   Example: Get-ChildItem "$($s.Name):\" -Force
        #   Example: Copy-Item ... -Destination "$($s.Name):\folder"
        Write-Host "Doing work on $($s.Name):\ ..."
    }
    catch {
        Write-Warning ("Work failed on drive {0}: {1}" -f $s.Name, $_.Exception.Message)
    }
    finally {
        # Always clean up the temporary PSDrive for transient use
        Remove-PSDrive -Name $s.Name -Force -ErrorAction SilentlyContinue
    }
}