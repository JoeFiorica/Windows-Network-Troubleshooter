[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [string]$Target,
    [string]$Share,
    [string]$TargetIP,
    [string]$Drive,
    [object]$IntervalSeconds = 5,
    [object]$DurationSeconds = 600,
    [object]$ProbeTimeoutMs = 4000,
    [switch]$InspectSession,
    [string[]]$SessionPath = @(),
    [string]$InputPath,
    [string]$OutputDirectory,
    [switch]$Redact,
    [switch]$Library,
    [string]$WorkerPayload
)
$ErrorActionPreference = 'Stop'


# NetworkTroubleshooter.psm1
Set-StrictMode -Version 2.0
$script:ModuleDirectory = $PSScriptRoot

function Get-NtUtc { [DateTime]::UtcNow.ToString('o') }

function ConvertFrom-NtJson {
    param([Parameter(Mandatory = $true)][string]$Json)
    # PS 7.5+ otherwise converts ISO strings into DateTime values. Keep the v1
    # schema identical to Windows PowerShell 5.1, including timestamp strings.
    if ($PSVersionTable.PSVersion -ge [version]'7.5') { ConvertFrom-Json -InputObject $Json -DateKind String }
    else { ConvertFrom-Json -InputObject $Json }
}

function Get-NtProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function Assert-NtLocalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    # Reject UNC, device paths, relative paths and network-mapped drives before any I/O.
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[*?]') {
        throw 'Use an absolute local disk path.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ((New-Object IO.DriveInfo $root).DriveType -eq [IO.DriveType]::Network) {
        throw 'Network paths are not allowed for session metadata, input or output.'
    }
    $drive = Get-PSDrive -Name $root.Substring(0, 1) -ErrorAction SilentlyContinue
    if ($drive -and (Get-NtProperty $drive 'DisplayRoot' '') -like '\\*') { throw 'Mapped network paths are not allowed.' }
    # Walk from the root so a junction cannot redirect a later component to a share.
    $componentPath = $root
    foreach ($component in $full.Substring($root.Length).Split([char[]]'\/')) {
        if (-not $component) { continue }
        $componentPath = [IO.Path]::Combine($componentPath, $component)
        try { $attributes = [IO.File]::GetAttributes($componentPath) }
        catch [IO.FileNotFoundException] { break }
        catch [IO.DirectoryNotFoundException] { break }
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Choose a local folder reached without symbolic links or folder junctions.' }
    }
    return $full
}

function Get-NtContext {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    [pscustomobject]@{
        user = $identity.Name
        sid = $identity.User.Value
        isSystem = ($identity.User.Value -eq 'S-1-5-18')
        elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        computer = $env:COMPUTERNAME
        powershell = $PSVersionTable.PSVersion.ToString()
        osVersion = [Environment]::OSVersion.Version.ToString()
    }
}

function Invoke-NtBoundedProbes {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Requests,
          [ValidateRange(100, 30000)][int]$TimeoutMs = 2000)
    $exe = Join-Path $PSHOME 'powershell.exe'
    if (-not [IO.File]::Exists($exe)) { $exe = Join-Path $PSHOME 'pwsh.exe' }
    $running = New-Object Collections.Generic.List[object]
    $results = [ordered]@{}
    try {
        foreach ($request in $Requests) {
            $started = Get-NtUtc
            $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $request -Depth 12 -Compress)))
            $info = New-Object Diagnostics.ProcessStartInfo
            $info.FileName = $exe
            $worker = Join-Path $script:ModuleDirectory 'network-troubleshooter.ps1'
            $info.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $worker + '" -WorkerPayload ' + $payload
            $info.UseShellExecute = $false
            $info.CreateNoWindow = $true
            $info.RedirectStandardOutput = $true
            $info.RedirectStandardError = $true
            $process = New-Object Diagnostics.Process
            $process.StartInfo = $info
            try {
                [void]$process.Start()
                $running.Add([pscustomobject]@{
                    name = $request.kind; process = $process; startedUtc = $started
                    clock = [Diagnostics.Stopwatch]::StartNew()
                    stdout = $process.StandardOutput.ReadToEndAsync()
                    stderr = $process.StandardError.ReadToEndAsync()
                })
            } catch {
                $process.Dispose()
                $results[$request.kind] = [pscustomobject]@{
                    status = 'error'; startedUtc = $started; finishedUtc = Get-NtUtc
                    data = @{ errorType = 'WorkerStartFailed' }
                }
            }
        }
        while ($running.Count -gt 0) {
            foreach ($item in @($running.ToArray())) {
                $done = $item.process.HasExited
                $expired = $item.clock.ElapsedMilliseconds -ge $TimeoutMs
                if (-not $done -and -not $expired) { continue }
                $result = $null
                if (-not $done) {
                    $item.process.Kill()
                    [void]$item.process.WaitForExit(500)
                    $result = [pscustomobject]@{ status = 'timeout'; data = @{ limitMs = $TimeoutMs } }
                } else {
                    try {
                        if (-not $item.stdout.IsCompleted) { [void]$item.stdout.Wait(500) }
                        if (-not $item.stdout.IsCompleted) { throw 'Incomplete worker output' }
                        $result = ConvertFrom-NtJson $item.stdout.Result
                        if (-not (Get-NtProperty $result 'status')) { throw 'Missing worker status' }
                    } catch {
                        $result = [pscustomobject]@{ status = 'error'; data = @{ errorType = 'InvalidWorkerOutput' } }
                    }
                }
                $result | Add-Member -NotePropertyName startedUtc -NotePropertyValue $item.startedUtc -Force
                $result | Add-Member -NotePropertyName finishedUtc -NotePropertyValue (Get-NtUtc) -Force
                $results[$item.name] = $result
                $item.process.Dispose()
                [void]$running.Remove($item)
            }
            if ($running.Count -gt 0) { Start-Sleep -Milliseconds 25 }
        }
    } finally {
        foreach ($item in $running) {
            try { if (-not $item.process.HasExited) { $item.process.Kill(); [void]$item.process.WaitForExit(500) } } catch { }
            $item.process.Dispose()
        }
    }
    [pscustomobject]$results
}

function Read-NtSession {
    param([string]$Path)
    $full = Assert-NtLocalPath $Path
    if (-not [IO.File]::Exists($full)) { return [pscustomobject]@{ path = $full; status = 'missing' } }
    $before = Get-Item -LiteralPath $full -Force
    if ($before.Length -gt 4MB) { return [pscustomobject]@{ path = $full; status = 'too-large' } }
    $bytes = $null
    $hashes = @()
    for ($read = 0; $read -lt 2; $read++) {
        $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            $memory = New-Object IO.MemoryStream
            try {
                $buffer = New-Object byte[] 8192
                while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($memory.Length + $count -gt 4MB) { throw 'Session exceeded limit during read' }
                    $memory.Write($buffer, 0, $count)
                }
                $bytes = $memory.ToArray()
            } finally { $memory.Dispose() }
        } finally { $stream.Dispose() }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hashes += [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '') } finally { $sha.Dispose() }
    }
    $after = Get-Item -LiteralPath $full -Force
    $stable = $hashes[0] -eq $hashes[1] -and $before.Length -eq $after.Length -and $before.LastWriteTimeUtc -eq $after.LastWriteTimeUtc
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 4MB
    $memory = New-Object IO.MemoryStream (,$bytes)
    $reader = [Xml.XmlReader]::Create($memory, $settings)
    try {
        $xml = New-Object Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.Load($reader)
        if (-not $xml.SelectSingleNode('/NotepadPlus/Session')) { throw 'Not a recognized session document' }
        $references = @()
        foreach ($node in $xml.SelectNodes('/NotepadPlus/Session//File[@filename]')) {
            $name = $node.GetAttribute('filename')
            if ($name -match '^\\\\') {
                $references += [pscustomobject]@{ kind = 'unc'; path = $name }
            } elseif ($name -match '^[A-Za-z]:[\\/]') {
                # Do not resolve file paths or open referenced documents, including drive roots.
                $references += [pscustomobject]@{ kind = 'drive-qualified-unresolved'; path = $name }
            }
        }
        [pscustomobject]@{
            path = $full; status = $(if ($stable) { 'observed-stable' } else { 'concurrent-change' })
            sha256 = $hashes[1]; length = $after.Length; lastWriteUtc = $after.LastWriteTimeUtc.ToString('o')
            observedUtc = Get-NtUtc
            fileEntryCount = $xml.SelectNodes('/NotepadPlus/Session//File').Count
            references = $references
        }
    } finally { $reader.Dispose(); $memory.Dispose() }
}

function Invoke-NtProbe {
    param([string]$Kind, $Options)
    switch ($Kind) {
        'resolve' {
            try {
                $addresses = @([Net.Dns]::GetHostAddresses($Options.target) | ForEach-Object { $_.ToString() })
                return @{ status = 'ok'; data = @{ addresses = $addresses; method = 'Windows resolver (cache/hosts/DNS and system policy)' } }
            } catch { return @{ status = 'failed'; data = @{ errorType = $_.Exception.GetType().FullName } } }
        }
        'transport' {
            $addresses = @($Options.addresses | Select-Object -Unique | Select-Object -First 4)
            $attempts = @()
            foreach ($address in $addresses) {
                $pingStatus = 'unknown'
                $ping = New-Object Net.NetworkInformation.Ping
                try { $pingStatus = $ping.Send([Net.IPAddress]::Parse($address), 200).Status.ToString() } catch { $pingStatus = 'error' } finally { $ping.Dispose() }
                $ports = @()
                foreach ($port in @(445, 3389)) {
                    $client = New-Object Net.Sockets.TcpClient ([Net.IPAddress]::Parse($address).AddressFamily)
                    try {
                        $pending = $client.BeginConnect([Net.IPAddress]::Parse($address), $port, $null, $null)
                        try {
                            if ($pending.AsyncWaitHandle.WaitOne(200)) {
                                try { $client.EndConnect($pending); $state = 'reachable' } catch { $state = 'unreachable' }
                            } else { $state = 'timeout' }
                        } finally { $pending.AsyncWaitHandle.Close() }
                    } catch { $state = 'error' } finally { $client.Close() }
                    $ports += @{ port = $port; status = $state; observedUtc = Get-NtUtc }
                }
                $attempts += @{ address = $address; icmp = $pingStatus; ports = $ports }
            }
            return @{ status = $(if ($addresses.Count) { 'ok' } else { 'unavailable' }); data = @{ attempts = $attempts; addressLimit = 4 } }
        }
        'share' {
            $started = Get-NtUtc
            try {
                # Listing permission is tested without opening a document or returning entry names.
                $enumerator = [IO.Directory]::EnumerateFileSystemEntries($Options.share).GetEnumerator()
                try { [void]$enumerator.MoveNext() } finally { if ($enumerator -is [IDisposable]) { $enumerator.Dispose() } }
                return @{ status = 'accessible'; data = @{ observedUtc = Get-NtUtc; attemptStartedUtc = $started; operation = 'directory-enumeration'; credentialContext = 'current token and existing Windows SMB sessions' } }
            } catch {
                $exception = $_.Exception
                while ($exception.InnerException) { $exception = $exception.InnerException }
                $code = $exception.HResult -band 0xffff
                $category = 'unknown'
                if ($code -in @(5, 65)) { $category = 'authorization-or-policy' }
                elseif ($code -in @(86, 1326, 1909, 1330, 1331, 1219)) { $category = 'authentication-or-session-conflict' }
                elseif ($code -in @(53, 67, 64, 121, 1231, 1232)) { $category = 'network-or-share-path' }
                return @{ status = 'inaccessible'; data = @{ observedUtc = Get-NtUtc; attemptStartedUtc = $started; win32Code = $code; category = $category; errorType = $exception.GetType().FullName } }
            }
        }
        'processes' {
            $instances = @()
            foreach ($p in @(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue)) {
                $start = $null; $path = $null; $session = $null
                try { $start = $p.StartTime.ToUniversalTime().ToString('o') } catch { }
                try { $path = $p.Path } catch { }
                try { $session = $p.SessionId } catch { }
                $instances += @{ pid = $p.Id; startUtc = $start; executable = $path; sessionId = $session }
            }
            return @{ status = 'ok'; data = @{ instances = $instances; observedUtc = Get-NtUtc; source = 'process snapshot; short-lived instances between polls may be missed' } }
        }
        'local' {
            $errors = @()
            $adapters = @(); $ips = @(); $profiles = @(); $services = @()
            try {
                $adapters = @(Get-NetAdapter -ErrorAction Stop | ForEach-Object { @{ Name = $_.Name; interfaceIndex = $_.InterfaceIndex; status = $_.Status.ToString(); linkSpeed = $_.LinkSpeed } })
            } catch { $errors += @{ check = 'adapters'; status = 'unavailable'; elevatedMayHelp = $true; errorType = $_.Exception.GetType().FullName } }
            try {
                $ips = @(Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
                    @{ interfaceIndex = $_.InterfaceIndex; ipv4 = @($_.IPv4Address | ForEach-Object { $_.IPAddress }); ipv6 = @($_.IPv6Address | ForEach-Object { $_.IPAddress }); gateways = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }); ipv6Gateways = @($_.IPv6DefaultGateway | ForEach-Object { $_.NextHop }); dnsServers = @($_.DNSServer | ForEach-Object { $_.ServerAddresses }) }
                })
            } catch { $errors += @{ check = 'ip'; status = 'unavailable'; elevatedMayHelp = $true; errorType = $_.Exception.GetType().FullName } }
            try { $profiles = @(Get-NetConnectionProfile -ErrorAction Stop | Select-Object Name, InterfaceIndex, NetworkCategory, IPv4Connectivity, IPv6Connectivity) }
            catch { $errors += @{ check = 'profile'; status = 'unavailable'; elevatedMayHelp = $true; errorType = $_.Exception.GetType().FullName } }
            foreach ($name in @('FDResPub', 'fdPHost', 'Dnscache', 'LanmanWorkstation')) {
                try { $s = Get-Service -Name $name -ErrorAction Stop; $services += @{ name = $name; status = $s.Status.ToString() } }
                catch { $services += @{ name = $name; status = 'unavailable' } }
            }
            return @{ status = $(if ($errors.Count) { 'partial' } else { 'ok' }); data = @{ adapters = $adapters; ip = $ips; profiles = $profiles; services = $services; errors = $errors; explorerNetworkVisibility = 'not-observed' } }
        }
        'mapped' {
            if (-not $Options.drive) { return @{ status = 'not-requested'; data = @{} } }
            $name = $Options.drive.TrimEnd(':')
            $drive = Get-PSDrive -Name $name -PSProvider FileSystem -ErrorAction SilentlyContinue
            $mappings = @(); $mappingCheck = 'ok'
            try { $mappings = @(Get-SmbMapping -ErrorAction Stop | Where-Object { $_.LocalPath -eq ($name + ':') } | Select-Object LocalPath, RemotePath, Status) }
            catch { $mappingCheck = 'unavailable' }
            return @{ status = $(if ($drive -or $mappings.Count) { 'present' } elseif ($mappingCheck -eq 'unavailable') { 'unavailable' } else { 'missing' }); data = @{ drive = $name + ':'; displayRoot = $(if ($drive) { $drive.DisplayRoot } else { $null }); mappings = $mappings; smbMappingCheck = $mappingCheck; scope = 'current logon token only; presence does not prove access' } }
        }
        'sessions' {
            $candidates = @($Options.sessionPaths)
            if ($Options.autoDiscover) {
                if ($env:APPDATA) { $candidates += Join-Path $env:APPDATA 'Notepad++\session.xml' }
                foreach ($p in @(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue)) {
                    try {
                        $directory = [IO.Path]::GetDirectoryName($p.Path)
                        [void](Assert-NtLocalPath ($directory + '\session.xml'))
                        if ([IO.File]::Exists((Join-Path $directory 'doLocalConf.xml'))) { $candidates += Join-Path $directory 'session.xml' }
                    } catch { }
                }
            }
            $sessions = @()
            foreach ($path in @($candidates | Where-Object { $_ } | Select-Object -Unique)) {
                try { $sessions += Read-NtSession $path }
                catch { $sessions += @{ path = $path; status = 'unreadable-or-invalid'; errorType = $_.Exception.GetType().FullName } }
            }
            return @{ status = 'ok'; data = @{ sessions = $sessions; discovery = 'candidate locations only; custom session/configuration paths require explicit SessionPath' } }
        }
        'test-delay' {
            # Internal offline regression hook; never dispatched by the public CLI.
            Start-Sleep -Milliseconds ([int]$Options.delayMs)
            return @{ status = 'ok'; data = @{} }
        }
        default { throw 'Unknown probe kind' }
    }
}

function Get-NtSample {
    param($Options, [int]$TimeoutMs, [int]$Sequence, [double]$ScheduledOffsetSeconds,
          [int]$BudgetMs = 60000)
    $started = Get-NtUtc
    $clock = [Diagnostics.Stopwatch]::StartNew()
    # Reserve half of the remaining wall-clock budget for each phase.
    $phaseTimeout = [Math]::Max(100, [Math]::Min($TimeoutMs, [int]($BudgetMs / 2)))
    $resolved = Invoke-NtBoundedProbes -Requests @(@{ kind = 'resolve'; options = @{ target = $Options.target } }) -TimeoutMs $phaseTimeout
    $addresses = @()
    if ($Options.directIP) { $addresses += $Options.directIP }
    if ($resolved.resolve.status -eq 'ok') { $addresses += @($resolved.resolve.data.addresses) }
    $requests = @(
        @{ kind = 'transport'; options = @{ addresses = $addresses } },
        @{ kind = 'share'; options = @{ share = $Options.share } },
        @{ kind = 'processes'; options = @{} },
        @{ kind = 'local'; options = @{} },
        @{ kind = 'mapped'; options = @{ drive = $Options.drive } }
    )
    if ($Options.inspectSession) { $requests += @{ kind = 'sessions'; options = @{ sessionPaths = $Options.sessionPaths; autoDiscover = $true } } }
    $remaining = [Math]::Max(100, [Math]::Min($TimeoutMs, $BudgetMs - [int]$clock.ElapsedMilliseconds))
    $probes = Invoke-NtBoundedProbes -Requests $requests -TimeoutMs $remaining
    $probes | Add-Member -NotePropertyName resolve -NotePropertyValue $resolved.resolve
    [pscustomobject]@{
        kind = 'sample'; sequence = $Sequence; scheduledOffsetSeconds = $ScheduledOffsetSeconds
        pollStartedUtc = $started; pollFinishedUtc = Get-NtUtc; elapsedMs = $clock.ElapsedMilliseconds
        probes = $probes
    }
}



# Reports.psm1
Set-StrictMode -Version 2.0

function New-NtFinding {
    param([string]$Id, [string]$Hypothesis, [object[]]$Observations,
          [object[]]$Counterevidence, [string]$Uncertainty, [string]$NextTest)
    if (-not $Counterevidence.Count) { $Counterevidence = @('No direct counterevidence was captured; incomplete observations cannot confirm this hypothesis.') }
    [pscustomobject]@{
        id = $Id; hypothesis = $Hypothesis; observations = @($Observations)
        counterevidence = @($Counterevidence); uncertainty = $Uncertainty; nextTest = $NextTest
    }
}

function Get-NtPortStates {
    param($Sample, [int]$Port)
    $transport = Get-NtProperty $Sample.probes 'transport'
    if ($transport -and $transport.status -eq 'ok') {
        foreach ($attempt in @($transport.data.attempts)) {
            foreach ($p in @($attempt.ports)) {
                if ($p.port -eq $Port) { [pscustomobject]@{ address = $attempt.address; status = $p.status } }
            }
        }
    }
}

function New-NtReport {
    param([Parameter(Mandatory = $true)][object[]]$Records)
    $headers = @($Records | Where-Object { $_.kind -eq 'header' })
    if ($headers.Count -ne 1) { throw 'The timeline must contain one file header. Use a complete timeline.jsonl saved by this tool.' }
    $header = $headers[0]
    if ($header.schemaVersion -ne 1) { throw 'This timeline format is unsupported. Use timeline.jsonl saved by this tool.' }
    $samples = @($Records | Where-Object { $_.kind -eq 'sample' } | Sort-Object { [DateTimeOffset]$_.pollStartedUtc })
    $findings = @()
    $timeouts = @(); $dnsFailures = @(); $dnsSuccess = @(); $shareFailures = @(); $shareSuccess = @()
    $splitPorts = @(); $transportOnly = @(); $missingDrives = @(); $processes = @{}; $sessionHistory = @{}
    $auth = @(); $gaps = @()
    foreach ($s in $samples) {
        foreach ($probe in $s.probes.PSObject.Properties) {
            if ($probe.Value.status -in @('timeout', 'error', 'partial', 'unavailable')) {
                $timeouts += "Poll $($s.sequence): $($probe.Name)=$($probe.Value.status)"
            }
        }
        $resolve = Get-NtProperty $s.probes 'resolve'
        if ($resolve) {
            if ($resolve.status -eq 'ok') { $dnsSuccess += $s } else { $dnsFailures += $s }
        }
        $share = Get-NtProperty $s.probes 'share'
        if ($share) {
            if ($share.status -eq 'accessible') { $shareSuccess += $s }
            elseif ($share.status -eq 'inaccessible') {
                $shareFailures += $s
                if ((Get-NtProperty $share.data 'category') -in @('authorization-or-policy', 'authentication-or-session-conflict')) {
                    $auth += "Poll $($s.sequence): $($share.data.category), Win32 $($share.data.win32Code)"
                }
            }
        }
        $p445 = @(Get-NtPortStates $s 445)
        $p3389 = @(Get-NtPortStates $s 3389)
        foreach ($rdp in @($p3389 | Where-Object { $_.status -eq 'reachable' })) {
            if (@($p445 | Where-Object { $_.address -eq $rdp.address -and $_.status -in @('unreachable', 'timeout') }).Count) {
                $splitPorts += "Poll $($s.sequence): $($rdp.address) accepts TCP 3389 while TCP 445 fails or times out."
            }
        }
        if ($share -and $share.status -eq 'inaccessible' -and @($p445 | Where-Object { $_.status -eq 'reachable' }).Count) {
            $transportOnly += "Poll $($s.sequence): TCP 445 reachable on a tested address; configured UNC enumeration failed."
        }
        $mapped = Get-NtProperty $s.probes 'mapped'
        if ($mapped -and $mapped.status -eq 'missing') { $missingDrives += "Poll $($s.sequence): requested drive absent from this token's view; mapping query=$($mapped.data.smbMappingCheck)." }
        $proc = Get-NtProperty $s.probes 'processes'
        if ($proc -and $proc.status -eq 'ok') {
            foreach ($p in @($proc.data.instances)) {
                $key = "$($p.pid)|$($p.startUtc)"
                if (-not $processes.ContainsKey($key)) {
                    $processes[$key] = [pscustomobject]@{ pid = $p.pid; startUtc = $p.startUtc; firstObservedUtc = (Get-NtProperty $proc.data 'observedUtc' $s.pollFinishedUtc); sessionId = $p.sessionId }
                }
            }
        }
        $sessions = Get-NtProperty $s.probes 'sessions'
        if ($sessions -and $sessions.status -eq 'ok') {
            foreach ($item in @($sessions.data.sessions)) {
                if (-not $sessionHistory.ContainsKey($item.path)) { $sessionHistory[$item.path] = @() }
                $sessionHistory[$item.path] += [pscustomobject]@{ observedUtc = (Get-NtProperty $item 'observedUtc' $s.pollFinishedUtc); metadata = $item }
            }
        }
        if ($s.elapsedMs -gt ($header.intervalSeconds * 1000) -and $header.command -eq 'monitor') {
            $gaps += "Poll $($s.sequence) took $($s.elapsedMs) ms, longer than the requested interval."
        }
    }
    $firstSuccess = $null
    if ($shareSuccess.Count) { $firstSuccess = $shareSuccess[0] }
    if ($dnsFailures.Count) {
        $findings += New-NtFinding 'resolution' 'Windows hostname resolution was unavailable during some polls.' @($dnsFailures | ForEach-Object { "Poll $($_.sequence): resolver=$($_.probes.resolve.status)" }) @($dnsSuccess | ForEach-Object { "Poll $($_.sequence): resolver succeeded." }) 'Timeouts include worker startup overhead. The resolver uses Windows policy; this does not isolate DNS, hosts, cache, LLMNR or NetBIOS.' 'Compare the resolver timeline to a separately supplied, verified target IP; inspect DNS configuration before proposing changes.'
    }
    if ($splitPorts.Count) {
        $findings += New-NtFinding 'rdp-without-smb' 'SMB transport may be unavailable while the RDP TCP endpoint is reachable.' $splitPorts @('A TCP connection does not prove RDP login or SMB authentication succeeds.') 'Firewall, host boot order, endpoint policy, routing and listener state remain possible. These probes do not establish which one applies.' 'Capture another affected boot and compare the same address and ports; review host-side listener/firewall evidence with approval.'
    }
    if ($transportOnly.Count) {
        $findings += New-NtFinding 'share-despite-445' 'An accepting SMB TCP endpoint is insufficient for usable share access.' $transportOnly $auth 'The UNC can resolve to a different address or DFS target. Enumeration failure can involve path, authentication, authorization, policy or transient server state.' 'Verify the configured UNC, address correspondence and returned Win32 category using the same user token. Do not change credentials automatically.'
    }
    if ($auth.Count) {
        $findings += New-NtFinding 'access-category' 'Returned share errors suggest authentication/session or authorization/policy investigation.' $auth @('A coarse Win32 category does not identify an exact cause or justify a credential change.') 'Existing SMB sessions and Windows policy affect results; no credentials were requested or logged.' 'Review server-side SMB/security events for the exact UTC window with the share owner; compare the interactive user context.'
    }
    if ($missingDrives.Count) {
        $findings += New-NtFinding 'mapped-drive' 'The requested mapped drive is absent or unobservable in this logon context.' $missingDrives @('Direct UNC access and a mapped drive have separate availability and token scopes.') 'SYSTEM, elevated and interactive tokens can see different mappings. A failed mapping query weakens the absence evidence.' 'Compare an unelevated run in the affected user session to direct UNC results; do not remap automatically.'
    }
    if ($shareFailures.Count -and $shareSuccess.Count) {
        $recoveries = @()
        foreach ($ok in $shareSuccess) {
            $prior = @($shareFailures | Where-Object { [DateTimeOffset]$_.pollFinishedUtc -lt [DateTimeOffset]$ok.pollStartedUtc })
            if ($prior.Count) {
                $lastFailure = $prior[-1]
                $recoveries += "Failed poll $($lastFailure.sequence) finished $($lastFailure.pollFinishedUtc); successful poll $($ok.sequence) checked $($ok.probes.share.data.observedUtc). Recovery occurred between observations, or fluctuated."
                break
            }
        }
        if ($recoveries.Count) {
            $findings += New-NtFinding 'transient-recovery' 'Share enumeration recovered after observed failure.' $recoveries @('Later failures remain possible; one success does not establish permanent readiness.') 'Polling brackets observations. It does not reveal the exact transition time or responsible subsystem.' 'Repeat at least two ordinary boot cycles and compare link, resolver, transport and share observations.'
        }
    }
    if ($shareFailures.Count -and -not $shareSuccess.Count) {
        $findings += New-NtFinding 'no-share-success' 'The configured share was never observed accessible in this capture.' @($shareFailures | ForEach-Object { "Poll $($_.sequence): enumeration failed." }) @('An inaccessible target can also be offline or have an incorrect configured share path.') 'The capture cannot distinguish permanent failure from recovery outside the recording window.' 'Verify the target and UNC with its owner, then capture a longer ordinary boot window without disrupting the share.'
    }
    $launches = @()
    foreach ($p in @($processes.Values | Sort-Object startUtc)) {
        $relation = 'no-observed-share-success'
        $failedAfterLaunch = @()
        if ($p.startUtc) {
            $failedAfterLaunch = @($shareFailures | Where-Object { [DateTimeOffset]$_.pollStartedUtc -ge [DateTimeOffset]$p.startUtc })
            if ($firstSuccess) {
                if ([DateTimeOffset]$p.startUtc -lt [DateTimeOffset]$firstSuccess.probes.share.data.observedUtc) { $relation = 'before-first-observed-success' }
                else { $relation = 'at-or-after-first-observed-success' }
            }
        } else { $relation = 'start-time-unavailable' }
        $launches += [pscustomobject]@{
            pid = $p.pid; startUtc = $p.startUtc; firstObservedUtc = $p.firstObservedUtc; sessionId = $p.sessionId
            relation = $relation; failedPollsAtOrAfterLaunch = @($failedAfterLaunch | ForEach-Object { $_.sequence })
        }
    }
    if ($launches.Count) {
        $findings += New-NtFinding 'notepad-timing' 'Notepad++ process timing can be compared with observed share checks.' @($launches | ForEach-Object { "PID $($_.pid): actual start=$($_.startUtc); first polled=$($_.firstObservedUtc); $($_.relation)." }) @('No observation here proves that a session was loaded, tabs disappeared, or unavailable files caused tab loss.') 'The share can change between polls. Processes started before capture, other user sessions, multiple instances and short-lived processes limit interpretation.' 'Compare stable session metadata snapshots and manually record visible tabs before and after two normal boots; record the active Notepad++ instance and configuration.'
    } else {
        $findings += New-NtFinding 'notepad-coverage' 'No Notepad++ process instance was retained in this capture.' @('No launch ordering can be assessed from the available process snapshots.') @('Short-lived instances between polls, unavailable process probes and pre-capture events can be missed.') 'This is not evidence that Notepad++ never ran or that its tabs survived.' 'Start a bounded capture before the ordinary application launch when feasible and record visible tabs and the active instance manually.'
    }
    $sessionComparisons = @()
    foreach ($path in @($sessionHistory.Keys | Sort-Object)) {
        $history = @($sessionHistory[$path])
        $stable = @($history | Where-Object { $_.metadata.status -eq 'observed-stable' })
        $state = 'insufficient-stable-snapshots'; $removed = @()
        if ($stable.Count -ge 2) {
            $first = $stable[0].metadata; $last = $stable[-1].metadata
            $fingerprints = @($stable | ForEach-Object { $_.metadata.sha256 } | Select-Object -Unique)
            $state = $(if ($fingerprints.Count -eq 1) { 'unchanged' } else { 'changed' })
            $lastPaths = @($last.references | ForEach-Object { $_.path })
            $removed = @($first.references | Where-Object { $_.kind -eq 'unc' -and $_.path -notin $lastPaths } | ForEach-Object { $_.path })
        }
        $sessionComparisons += [pscustomobject]@{
            path = $path; state = $state; stableSnapshots = $stable.Count
            unstableOrUnavailableSnapshots = $history.Count - $stable.Count; removedUncReferences = $removed
        }
    }
    if ($sessionComparisons.Count) {
        $findings += New-NtFinding 'session-metadata' 'Optional session metadata snapshots show disk metadata state, with concurrent writes excluded from comparisons.' @($sessionComparisons | ForEach-Object { "$($_.path): $($_.state); removed UNC references=$($_.removedUncReferences.Count); unstable/unavailable=$($_.unstableOrUnavailableSnapshots)." }) @('A hash change can reflect cursor or layout state. A removed reference can reflect an intentional close, another instance or configuration. Unchanged disk metadata does not prove in-memory tabs survived.') 'Two stable reads reduce concurrent-write ambiguity but cannot eliminate all races. The selected file may not belong to the active instance or custom configuration.' 'Correlate the exact active session file, manual tab observations and process instance. Never replace or restore session files during diagnosis.'
    }
    if ($timeouts.Count -or $gaps.Count -or $samples.Count -eq 0) {
        $findings += New-NtFinding 'coverage' 'Capture coverage limits the available conclusions.' @($timeouts + $gaps) @('Unavailable, timed-out and partial checks are not proof of network failure.') 'Worker startup counts toward each timeout. No sample can observe changes between polls; the monitor can stop or be canceled before completion.' 'Increase the probe timeout on a slow machine and compare requested versus actual poll times; retain a bounded duration.'
    }
    $findings += New-NtFinding 'discovery' 'Explorer Network visibility was not measured by this utility.' @('Discovery-service states are captured where available; no reliable built-in Explorer visibility indicator is claimed.') @('A host can be absent from Explorer Network while its UNC share works. Service states alone do not establish discoverability.') 'Discovery, resolution, SMB transport, authentication, share enumeration and Notepad++ restoration are separate observations.' 'During the same UTC window, manually record Explorer Network visibility and compare an explicit UNC access under the same user token.'
    $end = @($Records | Where-Object { $_.kind -eq 'end' })
    [pscustomobject]@{
        schemaVersion = 1; generatedUtc = Get-NtUtc; header = $header
        summary = @{ sampleCount = $samples.Count; shareSuccessCount = $shareSuccess.Count; shareFailureCount = $shareFailures.Count; completion = $(if ($end.Count) { $end[-1].reason } else { 'incomplete-or-interrupted' }) }
        findings = $findings; notepadLaunches = $launches; sessionComparisons = $sessionComparisons
        limitations = @('Read-only means no configuration writes or document writes; network checks still create ordinary network traffic and may use Windows integrated authentication.', 'Directory enumeration proves listing at one moment, not permission to open every document.', 'No root cause or Notepad++ tab-loss causality is established automatically.', 'Current user/token observations cannot be transferred to SYSTEM or another user.', 'Local output can contain private metadata unless redaction is enabled.')
        records = $Records
    }
}

function ConvertTo-NtRedacted {
    param([Parameter(Mandatory = $true)]$Value)
    $copy = ConvertFrom-NtJson (ConvertTo-Json -InputObject $Value -Depth 60)
    $map = @{}; $counts = @{}
    $sensitive = @('target', 'directIP', 'share', 'user', 'sid', 'computer', 'path', 'executable', 'displayRoot', 'RemotePath', 'LocalPath', 'addresses', 'address', 'ipv4', 'ipv6', 'gateways', 'ipv6Gateways', 'dnsServers', 'sessionPaths', 'removedUncReferences', 'Name')
    function Add-PrivateValue($node, [string]$key) {
        if ($null -eq $node) { return }
        if ($node -is [ValueType]) { return }
        if ($node -is [string]) {
            if ($key -in $sensitive -and $node.Length -gt 0 -and -not $map.ContainsKey($node) -and
                -not ($key -eq 'Name' -and $node -in @('FDResPub', 'fdPHost', 'Dnscache', 'LanmanWorkstation'))) {
                $category = 'VALUE'
                if ($key -in @('target', 'computer')) { $category = 'HOST' }
                elseif ($key -in @('user', 'sid')) { $category = 'IDENTITY' }
                elseif ($key -in @('addresses', 'address', 'ipv4', 'ipv6', 'gateways', 'ipv6Gateways', 'dnsServers', 'directIP')) { $category = 'IP' }
                elseif ($key -in @('path', 'share', 'executable', 'displayRoot', 'RemotePath', 'sessionPaths', 'removedUncReferences', 'LocalPath')) { $category = 'PATH' }
                if (-not $counts.ContainsKey($category)) { $counts[$category] = 0 }
                $counts[$category]++
                $map[$node] = '<' + $category + '_' + $counts[$category] + '>'
                if ($node -match '^\\\\([^\\]+)\\') {
                    $hostPart = $Matches[1]
                    if (-not $map.ContainsKey($hostPart)) { $counts['HOST'] = 1 + [int]$counts['HOST']; $map[$hostPart] = '<HOST_' + $counts['HOST'] + '>' }
                }
            }
        } elseif ($node -is [Collections.IEnumerable] -and $node -isnot [pscustomobject] -and $node -isnot [Collections.IDictionary]) {
            foreach ($item in $node) { Add-PrivateValue $item $key }
        } else {
            foreach ($property in $node.PSObject.Properties) { Add-PrivateValue $property.Value $property.Name }
        }
    }
    Add-PrivateValue $copy ''
    $ordered = @($map.Keys | Sort-Object Length -Descending)
    # One regex pass prevents replacement placeholders being re-redacted by short host names.
    $patterns = @($ordered | ForEach-Object { '(?<![A-Za-z0-9_])' + [regex]::Escape($_) + '(?![A-Za-z0-9_])' })
    $pattern = $patterns -join '|'
    function Rewrite-PrivateValue($node) {
        if ($null -eq $node) { return $null }
        if ($node -is [ValueType]) { return $node }
        if ($node -is [string]) {
            if ($map.ContainsKey($node)) { return $map[$node] }
            if ($pattern) { return [regex]::Replace($node, $pattern, [Text.RegularExpressions.MatchEvaluator]{ param($m) $map[$m.Value] }, [Text.RegularExpressions.RegexOptions]::IgnoreCase) }
            return $node
        }
        if ($node -is [Collections.IEnumerable] -and $node -isnot [pscustomobject] -and $node -isnot [Collections.IDictionary]) {
            $items = @(); foreach ($item in $node) { $items += ,(Rewrite-PrivateValue $item) }; return ,$items
        }
        foreach ($property in @($node.PSObject.Properties)) { $node.$($property.Name) = Rewrite-PrivateValue $property.Value }
        if ($node.PSObject.Properties['kind'] -and $node.kind -eq 'header') { $node.redacted = $true }
        return $node
    }
    $copy = Rewrite-PrivateValue $copy
    if ($copy.PSObject.Properties['header']) { $copy.header.redacted = $true }
    elseif ($copy.PSObject.Properties['kind'] -and $copy.kind -eq 'header') { $copy.redacted = $true }
    $copy
}

function ConvertTo-NtTextReport {
    param($Report)
    $lines = @('Windows Network Troubleshooter report', "Generated UTC: $($Report.generatedUtc)", "Capture start UTC: $($Report.header.startedUtc)", "Target: $($Report.header.target) | Share: $($Report.header.share)", "Context: $($Report.header.context.user) | SYSTEM: $($Report.header.context.isSystem) | Elevated: $($Report.header.context.elevated)", "Polls: $($Report.summary.sampleCount) | share successes: $($Report.summary.shareSuccessCount) | share failures: $($Report.summary.shareFailureCount) | completion: $($Report.summary.completion)", "Redacted: $($Report.header.redacted)", '')
    foreach ($finding in $Report.findings) {
        $lines += "[$($finding.id)] $($finding.hypothesis)"
        foreach ($observation in $finding.observations) { $lines += "  Observation: $observation" }
        foreach ($counter in $finding.counterevidence) { $lines += "  Counterevidence / alternative: $counter" }
        $lines += "  Uncertainty: $($finding.uncertainty)"
        $lines += "  Recommended next test: $($finding.nextTest)"
        $lines += ''
    }
    $lines += 'Timeline (UTC; poll timestamps are not inferred event times):'
    foreach ($sample in @($Report.records | Where-Object { $_.kind -eq 'sample' })) {
        $lines += "  Poll $($sample.sequence): $($sample.pollStartedUtc) -> $($sample.pollFinishedUtc), $($sample.elapsedMs) ms"
        foreach ($property in $sample.probes.PSObject.Properties) {
            $lines += "    $($property.Name): $($property.Value.status)"
        }
        $transport = Get-NtProperty $sample.probes 'transport'
        if ($transport -and $transport.status -eq 'ok') {
            foreach ($attempt in @($transport.data.attempts)) {
                $ports = @($attempt.ports | ForEach-Object { "$($_.port)=$($_.status)" }) -join ', '
                $lines += "    Address $($attempt.address): ICMP=$(Get-NtProperty $attempt 'icmp' 'not-recorded'); TCP $ports"
            }
        }
        $share = Get-NtProperty $sample.probes 'share'
        if ($share) { $lines += "    Share check result time: $(Get-NtProperty $share.data 'observedUtc' 'unknown')" }
        $local = Get-NtProperty $sample.probes 'local'
        if ($local -and $local.status -in @('ok', 'partial')) {
            foreach ($name in @('adapters', 'ip', 'profiles', 'services', 'errors')) {
                $details = Get-NtProperty $local.data $name @()
                if (@($details).Count) { $lines += "    ${name}: $(ConvertTo-Json -InputObject $details -Depth 8 -Compress)" }
            }
        }
    }
    $lines += ''
    $lines += 'Limits and privacy:'
    $lines += @($Report.limitations | ForEach-Object { '  ' + $_ })
    $lines -join [Environment]::NewLine
}

function Write-NtReports {
    param([object[]]$Records, [string]$OutputDirectory, [switch]$Redact)
    $report = New-NtReport -Records $Records
    if ($Redact) { $report = ConvertTo-NtRedacted $report }
    $utf8 = New-Object Text.UTF8Encoding $false
    # CreateNew prevents accidental overwrite of existing outputs or user files.
    foreach ($item in @(@{ name = 'report.json'; text = (ConvertTo-Json -InputObject $report -Depth 60) }, @{ name = 'report.txt'; text = (ConvertTo-NtTextReport $report) })) {
        $path = Join-Path $OutputDirectory $item.name
        $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $writer = New-Object IO.StreamWriter $stream, $utf8
        try { $writer.Write($item.text) } finally { $writer.Dispose() }
    }
    $report
}



# Internal read-only function loading for worker/tests.
try {
    if ($Command -notin @('diagnose','monitor','report','help')) { throw 'Choose diagnose, monitor, report or help as the command.' }
    try { [int]$IntervalSeconds = $IntervalSeconds; [int]$DurationSeconds = $DurationSeconds; [int]$ProbeTimeoutMs = $ProbeTimeoutMs }
    catch { throw 'Use whole numbers for -IntervalSeconds, -DurationSeconds and -ProbeTimeoutMs.' }
    if ($IntervalSeconds -lt 1 -or $IntervalSeconds -gt 3600) { throw '-IntervalSeconds must be from 1 to 3600.' }
    if ($DurationSeconds -lt 1 -or $DurationSeconds -gt 3600) { throw '-DurationSeconds must be from 1 to 3600.' }
    if ($ProbeTimeoutMs -lt 100 -or $ProbeTimeoutMs -gt 30000) { throw '-ProbeTimeoutMs must be from 100 to 30000.' }
} catch {
    [Console]::Error.WriteLine('ERROR: ' + $_.Exception.Message + ' Run network-troubleshooter.bat help for usage.')
    exit 1
}

if ($WorkerPayload) {
    $Payload=$WorkerPayload
try {
    $request = ConvertFrom-NtJson ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload)))
    $result = Invoke-NtProbe -Kind $request.kind -Options $request.options
    [Console]::Out.Write((ConvertTo-Json -InputObject $result -Depth 30 -Compress))
} catch {
    # Exception messages may contain paths or other private data; retain only a type.
    [Console]::Out.Write((ConvertTo-Json -Compress -InputObject @{
        status = 'error'; data = @{ errorType = $_.Exception.GetType().FullName }
    }))
    exit 1
}

    exit 0
}

if ($Library) { return }


if ($Command -eq 'help') {
    @'
Windows Network Troubleshooter - read-only Windows network checks

Usage:
  network-troubleshooter.bat help
  network-troubleshooter.bat diagnose -Target files.example.test -Share "\\files.example.test\team" -Redact
  network-troubleshooter.bat monitor -Target files.example.test -Share "\\files.example.test\team" -Redact
  network-troubleshooter.bat report -InputPath "C:\Captures\run\timeline.jsonl" -Redact

Commands:
  diagnose  Check once and save a report.
  monitor   Repeat checks for a limited time; Ctrl+C stops capture.
  report    Rebuild reports from a saved timeline without network checks.

Options:
  -Target            Hostname or IP you are authorized to check.
  -Share             Full share-folder path to check using your Windows account.
  -TargetIP          Optional verified IP for separate connection checks.
  -Drive             Optional mapped-drive letter, such as Z:.
  -IntervalSeconds   Seconds between monitor checks (default 5; range 1-3600).
  -DurationSeconds   Monitor duration in seconds (default 600; range 1-3600).
  -ProbeTimeoutMs    Time allowed per check, including startup (default 4000 ms;
                     range 100-30000).
  -InspectSession    Also inspect Notepad++ session metadata; documents stay closed.
  -SessionPath       Local session.xml path(s); also enables session inspection.
  -OutputDirectory   New absolute local output folder; must not already exist.
  -InputPath         Saved local timeline.jsonl for the report command.
  -Redact            Hide captured names and paths; still review files before sharing.

Replace the example target with your own. Quote paths containing spaces.
In PowerShell, prefix BAT commands with .\.
Output: timeline.jsonl, report.txt and report.json in a new local runs/ subfolder.
Each run prints its location. report -Redact also writes a sanitized timeline.
No repairs, settings changes, administrator prompt, telemetry or uploads.
Share checks send normal network and Windows authentication traffic.
Timeouts and failed checks do not establish a root cause or explain lost editor tabs.
Exit codes: 0 completed (check failures may appear in reports); 1 invalid input/failure.
'@ | Write-Output
    exit 0
}

$writer = $null
try {
    if ($Command -ne 'report') {
        if ([string]::IsNullOrWhiteSpace($Target) -or [string]::IsNullOrWhiteSpace($Share)) { throw 'diagnose/monitor require explicit -Target and -Share.' }
        if ($Target -match '[\s\\/"\x00-\x1f]' -or $Target.Length -gt 253) { throw 'Use a hostname or IP address for -Target, without spaces or a folder path.' }
        if ($Share -notmatch '^\\\\[^\\/\s]+\\[^\\/]+(?:\\[^/]+)?$' -or $Share -match '["\x00-\x1f*?]' -or $Share -match '^\\\\[?.]\\') { throw 'Use a full share-folder path for -Share, such as \\host\share.' }
        if ($Drive -and $Drive -notmatch '^[A-Za-z]:?$') { throw 'Drive must be one drive letter with an optional colon.' }
        if ($TargetIP) { $parsedIP = $null; if (-not [Net.IPAddress]::TryParse($TargetIP, [ref]$parsedIP)) { throw 'Use an IP address for -TargetIP, not a hostname.' } }
        foreach ($path in $SessionPath) { [void](Assert-NtLocalPath $path) }
        if ($SessionPath.Count) { $InspectSession = $true }
    } else {
        if (-not $InputPath) { throw 'report requires -InputPath.' }
        $InputPath = Assert-NtLocalPath $InputPath
    }
    if (-not $OutputDirectory) {
        $OutputDirectory = Join-Path (Join-Path (Get-Location).Path 'runs') (([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')) + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    $OutputDirectory = Assert-NtLocalPath $OutputDirectory
    if (Test-Path -LiteralPath $OutputDirectory) { throw 'OutputDirectory must be a new folder; existing paths are never overwritten.' }
    # Parent must be local as well. Refuse reparse points to avoid output redirection.
    $ancestor = [IO.Path]::GetDirectoryName($OutputDirectory)
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor) {
            if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Choose an output folder reached without symbolic links or folder junctions.' }
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
    $records = New-Object Collections.Generic.List[object]
    if ($Command -eq 'report') {
        $lineNumber = 0
        foreach ($line in [IO.File]::ReadLines($InputPath)) {
            $lineNumber++
            if (-not $line.Trim()) { continue }
            try { $record = ConvertFrom-NtJson $line }
            catch { throw "Invalid JSON at line $lineNumber; preserve the source and remove only a confirmed truncated final line in a separate copy." }
            $records.Add($record)
        }
        # Validate before creating any output.
        [void](New-NtReport -Records $records.ToArray())
        [void][IO.Directory]::CreateDirectory($OutputDirectory)
        $report = Write-NtReports -Records $records.ToArray() -OutputDirectory $OutputDirectory -Redact:$Redact
        if ($Redact) {
            $export = @($report.records | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 40 -Compress })
            $stream = [IO.File]::Open((Join-Path $OutputDirectory 'timeline.jsonl'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            $writer = New-Object IO.StreamWriter $stream, (New-Object Text.UTF8Encoding $false)
            foreach ($line in $export) { $writer.WriteLine($line) }
            $writer.Dispose(); $writer = $null
        }
    } else {
        [void][IO.Directory]::CreateDirectory($OutputDirectory)
        $stream = [IO.File]::Open((Join-Path $OutputDirectory 'timeline.jsonl'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $writer = New-Object IO.StreamWriter $stream, (New-Object Text.UTF8Encoding $false)
        $writer.AutoFlush = $true
        $options = @{ target = $Target; share = $Share; directIP = $TargetIP; drive = $Drive; inspectSession = [bool]$InspectSession; sessionPaths = $SessionPath }
        $header = [pscustomobject]@{
            kind = 'header'; schemaVersion = 1; command = $Command; startedUtc = Get-NtUtc
            target = $Target; share = $Share; directIP = $TargetIP; drive = $Drive
            inspectSession = [bool]$InspectSession; sessionPaths = $SessionPath
            intervalSeconds = $IntervalSeconds; durationSeconds = $(if ($Command -eq 'monitor') { $DurationSeconds } else { 0 })
            probeTimeoutMs = $ProbeTimeoutMs; context = Get-NtContext; redacted = [bool]$Redact
        }
        $records.Add($header)
        # A single redaction map is built over accumulated metadata for each write.
        # Nothing unredacted is written to disk in Redact mode.
        if ($Redact) { $safeHeader = ConvertTo-NtRedacted $header } else { $safeHeader = $header }
        $writer.WriteLine((ConvertTo-Json -InputObject $safeHeader -Depth 40 -Compress))
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $sequence = 0; $nextOffset = 0.0
        do {
            if ($Command -eq 'monitor' -and $timer.Elapsed.TotalSeconds -ge $DurationSeconds) { break }
            $budget = $(if ($Command -eq 'monitor') { [Math]::Max(100, [int](($DurationSeconds - $timer.Elapsed.TotalSeconds) * 1000)) } else { 60000 })
            $sample = Get-NtSample -Options $options -TimeoutMs $ProbeTimeoutMs -Sequence $sequence -ScheduledOffsetSeconds $nextOffset -BudgetMs $budget
            $records.Add($sample)
            if ($Redact) {
                $safe = ConvertTo-NtRedacted ([pscustomobject]@{ header = $header; records = $records.ToArray() })
                $toWrite = $safe.records[-1]
            } else { $toWrite = $sample }
            $writer.WriteLine((ConvertTo-Json -InputObject $toWrite -Depth 40 -Compress))
            Write-Output ("Check {0}: share={1}; name lookup={2}; time={3} ms" -f $sequence, $sample.probes.share.status, $sample.probes.resolve.status, $sample.elapsedMs)
            $sequence++
            if ($Command -eq 'diagnose') { break }
            # Skip missed deadlines instead of burst polling or drifting the schedule.
            $nextOffset = ([Math]::Floor($timer.Elapsed.TotalSeconds / $IntervalSeconds) + 1) * $IntervalSeconds
            $waitUntil = [Math]::Min($nextOffset, $DurationSeconds)
            while ($timer.Elapsed.TotalSeconds -lt $waitUntil) { Start-Sleep -Milliseconds 100 }
        } while ($true)
        $end = [pscustomobject]@{ kind = 'end'; finishedUtc = Get-NtUtc; reason = 'completed'; actualDurationSeconds = $timer.Elapsed.TotalSeconds }
        $records.Add($end)
        $writer.WriteLine((ConvertTo-Json -InputObject $end -Compress))
        $writer.Dispose(); $writer = $null
        $report = Write-NtReports -Records $records.ToArray() -OutputDirectory $OutputDirectory -Redact:$Redact
    }
    Write-Output ("Reports saved in: {0}" -f $OutputDirectory)
    exit 0
} catch {
    # Avoid echoing raw exception messages, which can contain private paths.
    # Only exact, fixed validation messages may be shown. Never echo imported data.
    $publicMessages = @(
        'diagnose/monitor require explicit -Target and -Share.',
        'Use a hostname or IP address for -Target, without spaces or a folder path.',
        'Use a full share-folder path for -Share, such as \\host\share.',
        'Drive must be one drive letter with an optional colon.',
        'Use an IP address for -TargetIP, not a hostname.',
        'report requires -InputPath.',
        'Use an absolute local disk path.',
        'Network paths are not allowed for session metadata, input or output.',
        'Mapped network paths are not allowed.',
        'Choose a local folder reached without symbolic links or folder junctions.',
        'OutputDirectory must be a new folder; existing paths are never overwritten.',
        'Choose an output folder reached without symbolic links or folder junctions.',
        'The timeline must contain one file header. Use a complete timeline.jsonl saved by this tool.',
        'This timeline format is unsupported. Use timeline.jsonl saved by this tool.'
    )
    $hint = 'Check the command options, saved timeline file and permission to write to the output folder.'
    if ($_.Exception.Message -cin $publicMessages) { $hint = $_.Exception.Message }
    [Console]::Error.WriteLine('Troubleshooter failed: ' + $hint + ' Run network-troubleshooter.bat help for usage. No repairs were made.')
    exit 1
} finally {
    if ($writer) { $writer.Dispose() }
}
