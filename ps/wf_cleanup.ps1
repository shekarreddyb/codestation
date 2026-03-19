#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$GitHubToken,

    [Parameter(Mandatory = $true)]
    [string]$OrgName,

    [Parameter(Mandatory = $true)]
    [string]$RepoName,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$ThrottleLimit = 5,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$PerPage = 100,

    [Parameter(Mandatory = $false)]
    [ValidateSet("all", "queued", "in_progress", "completed", "success", "failure", "cancelled")]
    [string]$Status = "all",

    [Parameter(Mandatory = $false)]
    [string]$Branch,

    [Parameter(Mandatory = $false)]
    [int]$MaxRuns = 0,

    [Parameter(Mandatory = $false)]
    [switch]$ForceCancel
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-PlainTextFromSecureString {
    param(
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$SecureString
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-GitHubHeaders {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    return @{
        "Accept"               = "application/vnd.github+json"
        "Authorization"        = "Bearer $Token"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent"           = "PowerShell-GitHubWorkflowRunManager"
    }
}

function Get-ErrorDetails {
    param(
        [Parameter(Mandatory = $true)]
        $ErrorRecord
    )

    $statusCode = $null
    $responseBody = $null

    try {
        if ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.StatusCode) {
            $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
        }
    }
    catch {}

    try {
        if ($ErrorRecord.Exception.Response) {
            $stream = $ErrorRecord.Exception.Response.GetResponseStream()
            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                $responseBody = $reader.ReadToEnd()
                $reader.Dispose()
            }
        }
    }
    catch {}

    return [pscustomobject]@{
        StatusCode   = $statusCode
        ResponseBody = $responseBody
    }
}

function Invoke-GitHubApi {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET", "POST", "DELETE")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    try {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers
    }
    catch {
        $details = Get-ErrorDetails -ErrorRecord $_
        $message = "GitHub API call failed. Method=$Method Uri=$Uri"
        if ($details.StatusCode) {
            $message += " StatusCode=$($details.StatusCode)"
        }
        if ($details.ResponseBody) {
            $message += " Response=$($details.ResponseBody)"
        }

        throw $message
    }
}

function Get-WorkflowRuns {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OrgName,

        [Parameter(Mandatory = $true)]
        [string]$RepoName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [int]$PerPage,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [string]$Branch,

        [Parameter(Mandatory = $false)]
        [int]$MaxRuns
    )

    $page = 1
    $allRuns = New-Object System.Collections.Generic.List[object]

    do {
        $query = @(
            "per_page=$PerPage"
            "page=$page"
        )

        if ($Status -and $Status -ne "all") {
            $query += "status=$([uri]::EscapeDataString($Status))"
        }

        if ($Branch) {
            $query += "branch=$([uri]::EscapeDataString($Branch))"
        }

        $uri = "https://api.github.com/repos/$OrgName/$RepoName/actions/runs?" + ($query -join "&")
        $response = Invoke-GitHubApi -Method GET -Uri $uri -Headers $Headers

        $runs = @($response.workflow_runs)
        foreach ($run in $runs) {
            $allRuns.Add($run) | Out-Null

            if ($MaxRuns -gt 0 -and $allRuns.Count -ge $MaxRuns) {
                return $allRuns.ToArray()
            }
        }

        $page++
    }
    while ($runs.Count -eq $PerPage)

    return $allRuns.ToArray()
}

function Convert-RunToGridObject {
    param(
        [Parameter(Mandatory = $true)]
        $Run,

        [Parameter(Mandatory = $true)]
        [string]$OrgName,

        [Parameter(Mandatory = $true)]
        [string]$RepoName
    )

    [pscustomobject]@{
        Org          = $OrgName
        Repo         = $RepoName
        RunId        = [string]$Run.id
        RunNumber    = $Run.run_number
        WorkflowName = $Run.name
        Title        = $Run.display_title
        Event        = $Run.event
        Status       = $Run.status
        Conclusion   = $Run.conclusion
        Branch       = $Run.head_branch
        Commit       = if ($Run.head_sha) { $Run.head_sha.Substring(0, [Math]::Min(8, $Run.head_sha.Length)) } else { $null }
        Actor        = if ($Run.actor) { $Run.actor.login } else { $null }
        CreatedAt    = [datetime]$Run.created_at
        UpdatedAt    = [datetime]$Run.updated_at
        Url          = $Run.html_url
    }
}

function Show-TextProgressBar {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Completed,

        [Parameter(Mandatory = $true)]
        [int]$Total,

        [Parameter(Mandatory = $true)]
        [int]$Succeeded,

        [Parameter(Mandatory = $true)]
        [int]$Failed,

        [Parameter(Mandatory = $false)]
        [int]$Width = 30
    )

    if ($Total -le 0) {
        return
    }

    $ratio = if ($Completed -gt 0) { $Completed / $Total } else { 0 }
    $filled = [math]::Floor($ratio * $Width)
    if ($filled -gt $Width) { $filled = $Width }

    $empty = $Width - $filled
    $percent = [math]::Floor($ratio * 100)
    if ($percent -gt 100) { $percent = 100 }

    $bar = ("=" * $filled) + ("." * $empty)
    $text = "[{0}] {1,3}%  {2}/{3}  Success: {4}  Failed: {5}" -f $bar, $percent, $Completed, $Total, $Succeeded, $Failed
    Write-Host "`r$text" -NoNewline
}

function Invoke-RunActionWithProgress {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject[]]$SelectedRuns,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [ValidateSet("cancel", "delete")]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 100)]
        [int]$ThrottleLimit,

        [Parameter(Mandatory = $false)]
        [switch]$ForceCancel
    )

    $total = $SelectedRuns.Count
    $completed = 0
    $succeeded = 0
    $failed = 0

    $results = New-Object System.Collections.Generic.List[object]
    $jobs = New-Object System.Collections.ArrayList
    $headersJson = $Headers | ConvertTo-Json -Compress

    foreach ($run in $SelectedRuns) {
        while (($jobs | Where-Object { $_.State -eq "Running" }).Count -ge $ThrottleLimit) {
            $finishedJobs = @($jobs | Where-Object { $_.State -in @("Completed", "Failed", "Stopped") })

            foreach ($job in $finishedJobs) {
                $jobOutput = @(Receive-Job -Job $job -ErrorAction SilentlyContinue)

                foreach ($item in $jobOutput) {
                    $results.Add($item) | Out-Null
                    $completed++

                    if ($item.Result -eq "Success") {
                        $succeeded++
                    }
                    else {
                        $failed++
                    }
                }

                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                [void]$jobs.Remove($job)
            }

            Show-TextProgressBar -Completed $completed -Total $total -Succeeded $succeeded -Failed $failed
            Start-Sleep -Milliseconds 200
        }

        $job = Start-ThreadJob -ArgumentList $run, $headersJson, $Action, [bool]$ForceCancel -ScriptBlock {
            param($run, $headersJson, $action, $forceCancel)

            $headers = $headersJson | ConvertFrom-Json -AsHashtable
            $baseUri = "https://api.github.com/repos/$($run.Org)/$($run.Repo)/actions/runs/$($run.RunId)"

            if ($action -eq "cancel") {
                $uri = if ($forceCancel) { "$baseUri/force-cancel" } else { "$baseUri/cancel" }
                $method = "POST"
            }
            else {
                $uri = $baseUri
                $method = "DELETE"
            }

            try {
                Invoke-RestMethod -Method $method -Uri $uri -Headers $headers | Out-Null

                [pscustomobject]@{
                    Org          = $run.Org
                    Repo         = $run.Repo
                    RunId        = $run.RunId
                    WorkflowName = $run.WorkflowName
                    Action       = $action
                    Result       = "Success"
                    Message      = ""
                }
            }
            catch {
                $statusCode = $null
                $responseBody = $null

                try {
                    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                    }
                }
                catch {}

                try {
                    if ($_.Exception.Response) {
                        $stream = $_.Exception.Response.GetResponseStream()
                        if ($stream) {
                            $reader = New-Object System.IO.StreamReader($stream)
                            $responseBody = $reader.ReadToEnd()
                            $reader.Dispose()
                        }
                    }
                }
                catch {}

                [pscustomobject]@{
                    Org          = $run.Org
                    Repo         = $run.Repo
                    RunId        = $run.RunId
                    WorkflowName = $run.WorkflowName
                    Action       = $action
                    Result       = "Failed"
                    Message      = "StatusCode=$statusCode Response=$responseBody"
                }
            }
        }

        [void]$jobs.Add($job)
        Show-TextProgressBar -Completed $completed -Total $total -Succeeded $succeeded -Failed $failed
    }

    while ($jobs.Count -gt 0) {
        $finishedJobs = @($jobs | Where-Object { $_.State -in @("Completed", "Failed", "Stopped") })

        foreach ($job in $finishedJobs) {
            $jobOutput = @(Receive-Job -Job $job -ErrorAction SilentlyContinue)

            foreach ($item in $jobOutput) {
                $results.Add($item) | Out-Null
                $completed++

                if ($item.Result -eq "Success") {
                    $succeeded++
                }
                else {
                    $failed++
                }
            }

            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            [void]$jobs.Remove($job)
        }

        Show-TextProgressBar -Completed $completed -Total $total -Succeeded $succeeded -Failed $failed

        if ($jobs.Count -gt 0) {
            Start-Sleep -Milliseconds 200
        }
    }

    Show-TextProgressBar -Completed $completed -Total $total -Succeeded $succeeded -Failed $failed
    Write-Host ""

    return $results.ToArray()
}

function Ensure-CommandAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName,

        [Parameter(Mandatory = $true)]
        [string]$HelpMessage
    )

    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw $HelpMessage
    }
}

if (-not $GitHubToken) {
    $secureToken = Read-Host "Enter GitHub PAT" -AsSecureString
    $GitHubToken = Get-PlainTextFromSecureString -SecureString $secureToken
}

Ensure-CommandAvailable -CommandName "Out-GridView" -HelpMessage "Out-GridView is not available. This script requires Windows PowerShell UI support."
Ensure-CommandAvailable -CommandName "Start-ThreadJob" -HelpMessage "Start-ThreadJob is not available. Install/import the ThreadJob module or use PowerShell 7."

$headers = Get-GitHubHeaders -Token $GitHubToken

Write-Host "Fetching workflow runs for $OrgName/$RepoName ..." -ForegroundColor Cyan

$runs = Get-WorkflowRuns `
    -OrgName $OrgName `
    -RepoName $RepoName `
    -Headers $headers `
    -PerPage $PerPage `
    -Status $Status `
    -Branch $Branch `
    -MaxRuns $MaxRuns

if (-not $runs -or $runs.Count -eq 0) {
    Write-Warning "No workflow runs found."
    return
}

$gridData = $runs |
    ForEach-Object { Convert-RunToGridObject -Run $_ -OrgName $OrgName -RepoName $RepoName } |
    Sort-Object CreatedAt -Descending

$selectedRuns = $gridData | Out-GridView -Title "Select workflow runs from $OrgName/$RepoName" -PassThru

if (-not $selectedRuns -or $selectedRuns.Count -eq 0) {
    Write-Host "No runs selected. Exiting." -ForegroundColor Yellow
    return
}

Write-Host ""
Write-Host "Selected $($selectedRuns.Count) run(s)." -ForegroundColor Green
$action = Read-Host "Enter action: cancel / delete / quit"

switch ($action.ToLowerInvariant()) {
    "cancel" {
        $confirm = Read-Host "Cancel selected run(s)? (y/n)"
        if ($confirm -ne "y") {
            Write-Host "Cancelled by user." -ForegroundColor Yellow
            return
        }

        $results = Invoke-RunActionWithProgress `
            -SelectedRuns $selectedRuns `
            -Headers $headers `
            -Action "cancel" `
            -ThrottleLimit $ThrottleLimit `
            -ForceCancel:$ForceCancel
    }

    "delete" {
        $confirm = Read-Host "Delete selected run(s)? (y/n)"
        if ($confirm -ne "y") {
            Write-Host "Cancelled by user." -ForegroundColor Yellow
            return
        }

        $results = Invoke-RunActionWithProgress `
            -SelectedRuns $selectedRuns `
            -Headers $headers `
            -Action "delete" `
            -ThrottleLimit $ThrottleLimit
    }

    default {
        Write-Host "No action performed." -ForegroundColor Yellow
        return
    }
}

Write-Host ""
$results |
    Sort-Object Result, RunId |
    Format-Table -AutoSize

$results | Out-GridView -Title "Operation Results"