

# Network Health Console - local backend (PowerShell 5.1, nothing to install)
# Run:  powershell -ExecutionPolicy Bypass -File .\Start-NetworkHealth.ps1
# Then use the page that opens at http://localhost:8080/  (Ctrl+C here to stop)
param([int]$Port = 8080)

$ErrorActionPreference = "Continue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = (Get-Location).Path }
$indexFile = Join-Path $scriptDir "index.html"

$ssh = Get-Command ssh -ErrorAction SilentlyContinue
if (-not $ssh)                              { Write-Host "ERROR: SSH client not found." -ForegroundColor Red; exit 1 }
if (-not (Test-Path -LiteralPath $indexFile)) { Write-Host "ERROR: index.html must sit next to this script." -ForegroundColor Red; exit 1 }

# ---------------- Reports folder ----------------
$reportDir = Join-Path $scriptDir "reports"
try { New-Item -ItemType Directory -Path $reportDir -Force -ErrorAction Stop | Out-Null }
catch { $reportDir = $env:TEMP }

# ---------------- Credentials (Desktop\preetham\idpass.*) ----------------
$credDirs = @(
    "\\Global.tesco.org\dfsroot\uk\HeadOffice\Profile\VMHZRedirected\INE12493141\Desktop\preetham",
    (Join-Path ([Environment]::GetFolderPath("Desktop")) "preetham")
)
$credFile = $null
foreach ($d in $credDirs) {
    if (Test-Path -LiteralPath $d -PathType Container) {
        $f = Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "idpass*" } | Select-Object -First 1
        if ($f) { $credFile = $f.FullName; break }
    }
}
if (-not $credFile) { Write-Host "ERROR: credential file (idpass*) not found." -ForegroundColor Red; exit 1 }
$credLines = @(Get-Content -LiteralPath $credFile | Where-Object { $_.Trim() -ne "" })
if ($credLines.Count -lt 2) { Write-Host "ERROR: credential file needs username (line 1) and password (line 2)." -ForegroundColor Red; exit 1 }
$username = $credLines[0].Trim()
$password = $credLines[1].Trim()

$askpass = Join-Path $env:TEMP "ssh_askpass.cmd"
Set-Content -LiteralPath $askpass -Encoding ASCII -Value @('@echo off', 'powershell -NoProfile -NonInteractive -Command "Write-Output $env:SSH_PW"')
$env:SSH_PW = $password; $env:SSH_ASKPASS = $askpass; $env:SSH_ASKPASS_REQUIRE = "force"; $env:DISPLAY = "localhost:0"
$password = $null

# ---------------- Approved read-only commands (the page sends IDs only) ----------------
$catalog = [ordered]@{
    router = @(
        @{ id = "route0";   label = "Default route";      cmd = "show route 0"; parse = "route" }
        @{ id = "routesum"; label = "Route summary";      cmd = "show route summary" }
        @{ id = "bgp";      label = "BGP summary";        cmd = "show bgp summary" }
        @{ id = "ospf";     label = "OSPF neighbors";     cmd = "show ospf neighbor" }
        @{ id = "ifterse";  label = "Interfaces (terse)"; cmd = "show interfaces terse" }
        @{ id = "alarms";   label = "Chassis alarms";     cmd = "show chassis alarms"; check = "alarms" }
        @{ id = "uptime";   label = "System uptime";      cmd = "show system uptime" }
    )
    switch = @(
        @{ id = "ifterse";  label = "Interfaces (terse)"; cmd = "show interfaces terse" }
        @{ id = "vlans";    label = "VLANs";              cmd = "show vlans" }
        @{ id = "lldp";     label = "LLDP neighbors";     cmd = "show lldp neighbors" }
        @{ id = "stp";      label = "Spanning tree";      cmd = "show spanning-tree bridge" }
        @{ id = "vc";       label = "Virtual chassis";    cmd = "show virtual-chassis" }
        @{ id = "alarms";   label = "Chassis alarms";     cmd = "show chassis alarms"; check = "alarms" }
        @{ id = "uptime";   label = "System uptime";      cmd = "show system uptime" }
    )
}

# ---------------- Helpers ----------------
function Invoke-Ssh([string]$dev, [string]$cmd) {
    $raw = & $ssh.Source -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR `
        -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password,keyboard-interactive `
        "$username@$dev" $cmd 2>&1 | ForEach-Object { "$_" }
    $code  = $LASTEXITCODE
    $lines = @($raw -split "`r?`n")
    $b = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'law enforcement officials') { $b = $i } }
    if ($b -ge 0) {
        if ($b + 1 -le $lines.Count - 1) { $lines = @($lines[($b + 1)..($lines.Count - 1)]) } else { $lines = @() }
    }
    return @{ code = $code; text = (($lines -join "`n").Trim()) }
}

function Parse-JunosRoute([string[]]$Lines) {
    $tables = New-Object System.Collections.ArrayList
    $tbl = $null; $row = $null; $prefix = ""
    foreach ($l in $Lines) {
        if ($l -match '^(\S+): (\d+) destinations, (\d+) routes \((\d+) active, (\d+) holddown, (\d+) hidden\)') {
            $tbl = [pscustomobject]@{ name = $matches[1]; dest = [int]$matches[2]; routes = [int]$matches[3]; active = [int]$matches[4]
                                      hold = [int]$matches[5]; hidden = [int]$matches[6]; rows = (New-Object System.Collections.ArrayList) }
            [void]$tables.Add($tbl); $row = $null; continue
        }
        if ($null -eq $tbl) { continue }
        if ($l -match '^\s*([0-9a-fA-F:.]+/\d+)?\s*([*+\-]*)\[([\w\-]+)/(\d+)\]\s+([^,]+?)\s*(?:,\s*(.*))?$') {
            $p = $matches[1]; $mark = $matches[2]; $proto = $matches[3]; $pref = $matches[4]; $age = $matches[5]; $extra = $matches[6]
            if ($p) { $prefix = $p }
            $row = [pscustomobject]@{ prefix = $prefix; active = [bool]($mark -match '[*+]'); proto = $proto; pref = $pref; age = $age
                                      extra = $extra; asPath = ""; nextHop = ""; via = "" }
            [void]$tbl.rows.Add($row); continue
        }
        if ($null -eq $row) { continue }
        if ($l -match '^\s*AS path:\s*([^,]*)') { $row.asPath = $matches[1].Trim(); continue }
        if ($l -match '^\s*>?\s*(?:to (\S+)\s+)?via (\S+)') {
            $nh = $matches[1]; $via = $matches[2]
            if ($row.via -eq "") { $row.nextHop = $nh; $row.via = $via }
            else { $row.nextHop = "$($row.nextHop), $nh"; $row.via = "$($row.via), $via" }
        }
    }
    return ,$tables
}

function Invoke-Device($dev, $type, $ids, $runId) {
    $t0 = Get-Date
    $status = "ok"
    $results = New-Object System.Collections.ArrayList
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(("=" * 60)); [void]$sb.AppendLine("DEVICE: $dev ($type)")
    [void]$sb.AppendLine("TIME: $(Get-Date)");  [void]$sb.AppendLine(("=" * 60))

    foreach ($id in $ids) {
        $entry = $catalog[$type] | Where-Object { $_.id -eq $id } | Select-Object -First 1
        if (-not $entry) { continue }
        Write-Host "  [$dev] $($entry.cmd)" -ForegroundColor Gray
        $s = Get-Date
        $r = Invoke-Ssh $dev $entry.cmd
        $tables = @()
        if ($entry.parse -eq "route") { $tables = Parse-JunosRoute ($r.text -split "`n") }
        $bad = ($r.code -ne 0) -or [string]::IsNullOrWhiteSpace($r.text) -or ($r.text -match 'syntax error|unknown command')
        $att = ($entry.check -eq "alarms") -and ($r.text -notmatch 'No alarms currently active')
        if ($bad) { $status = "failed" } elseif ($att -and $status -ne "failed") { $status = "attention" }

        [void]$results.Add(@{ id = $id; label = $entry.label; cmd = $entry.cmd; exit = $r.code
                              seconds = [math]::Round(((Get-Date) - $s).TotalSeconds, 1)
                              output = $r.text; tables = $tables; attention = ($att -and -not $bad) })
        [void]$sb.AppendLine(""); [void]$sb.AppendLine(">>> $($entry.cmd)"); [void]$sb.AppendLine($r.text)
        if ($r.code -ne 0) { [void]$sb.AppendLine("SSH exit code: $($r.code)") }
    }
    [void]$sb.AppendLine(""); [void]$sb.AppendLine("Finished: $(Get-Date)")

    if ($runId -notmatch '^\d{8,14}$') { $runId = Get-Date -Format "yyyyMMddHHmmss" }
    $file = Join-Path $reportDir "health_report_$runId.txt"
    try { Add-Content -LiteralPath $file -Value $sb.ToString() -Encoding UTF8 -ErrorAction Stop } catch { $file = "(could not save: $($_.Exception.Message))" }

    return @{ device = $dev; status = $status; seconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
             commands = @($results); text = $sb.ToString(); file = $file }
}

function Send($ctx, [int]$code, [string]$type, [string]$body) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $ctx.Response.StatusCode = $code; $ctx.Response.ContentType = $type
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.Close()
}

# ---------------- Server ----------------
$token    = [guid]::NewGuid().ToString("N")   # blocks other web pages from calling this local API
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Prefixes.Add("http://127.0.0.1:$Port/")

try {
    $listener.Start()
    Write-Host ""
    Write-Host "Network Health Console running at http://localhost:$Port/  (user: $username)" -ForegroundColor Cyan
    Write-Host "Reports are saved in: $reportDir" -ForegroundColor Gray
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Gray
    Start-Process "http://localhost:$Port/"

    while ($listener.IsListening) {
        $task = $listener.GetContextAsync()
        while (-not $task.AsyncWaitHandle.WaitOne(300)) { }
        $ctx = $task.GetAwaiter().GetResult()
        try {
            $path = $ctx.Request.Url.AbsolutePath
            if ($path -eq "/") {
                $html = (Get-Content -LiteralPath $indexFile -Raw -Encoding UTF8).Replace("__TOKEN__", $token)
                Send $ctx 200 "text/html; charset=utf-8" $html
            }
            elseif ($ctx.Request.Headers["X-Token"] -ne $token) { Send $ctx 403 "application/json" '{"error":"forbidden"}' }
            elseif ($path -eq "/api/commands") {
                $out = @{}
                foreach ($k in $catalog.Keys) { $out[$k] = @($catalog[$k] | ForEach-Object { @{ id = $_.id; label = $_.label; cmd = $_.cmd } }) }
                Send $ctx 200 "application/json" (ConvertTo-Json -InputObject $out -Depth 5)
            }
            elseif ($path -eq "/api/run" -and $ctx.Request.HttpMethod -eq "POST") {
                $reader = New-Object IO.StreamReader($ctx.Request.InputStream, [Text.Encoding]::UTF8)
                $body = $reader.ReadToEnd() | ConvertFrom-Json
                $dev  = [string]$body.device
                $type = [string]$body.type
                if ($dev -notmatch '^[A-Za-z0-9][A-Za-z0-9._:\-]*$') { Send $ctx 400 "application/json" '{"error":"invalid device address"}' }
                elseif (-not $catalog.Contains($type))                { Send $ctx 400 "application/json" '{"error":"invalid device type"}' }
                else {
                    Write-Host "Checking $dev ..." -ForegroundColor Cyan
                    $res = Invoke-Device $dev $type @($body.commands) ([string]$body.runId)
                    Send $ctx 200 "application/json" (ConvertTo-Json -InputObject $res -Depth 8)
                }
            }
            else { Send $ctx 404 "application/json" '{"error":"not found"}' }
        }
        catch {
            try { Send $ctx 500 "application/json" (ConvertTo-Json -InputObject @{ error = $_.Exception.Message }) } catch { }
        }
    }
}
finally {
    if ($listener.IsListening) { $listener.Stop() }
    Remove-Item -LiteralPath $askpass -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\SSH_PW, Env:\SSH_ASKPASS, Env:\SSH_ASKPASS_REQUIRE, Env:\DISPLAY -ErrorAction SilentlyContinue
    Write-Host "Stopped." -ForegroundColor Yellow
}


