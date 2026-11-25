# Windows PowerShell 5.1. No Python, no installation, no administrator required.
# Only discovers and reads FC04. Does not alter PC or board network settings.
param([string]$InterfaceIP = '', [switch]$NoModbus)
$ErrorActionPreference = 'Stop'
function Get-AddressBytes([byte[]]$Packet, [int]$Offset) {
    return [System.Net.IPAddress]::new([byte[]]$Packet[$Offset..($Offset+3)]).ToString()
}
function Read-Exact($Stream, [int]$Count) {
    [byte[]]$bytes = New-Object byte[] $Count
    $used = 0
    while ($used -lt $Count) {
        $n = $Stream.Read($bytes, $used, $Count-$used)
        if ($n -le 0) { throw 'Board closed the Modbus connection' }
        $used += $n
    }
    return ,$bytes
}
function Read-NetworkRegisters([string]$BoardIP, [string]$LocalIP) {
    $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($LocalIP),0)
    $tcp = [System.Net.Sockets.TcpClient]::new($endpoint)
    try {
        $pending = $tcp.BeginConnect($BoardIP, 502, $null, $null)
        try {
            if (-not $pending.AsyncWaitHandle.WaitOne(3000)) { throw 'TCP connect timeout' }
            $tcp.EndConnect($pending)
        } finally { $pending.AsyncWaitHandle.Close() }
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 5000; $stream.WriteTimeout = 5000
        [byte[]]$request = 0,1,0,0,0,6,1,4,0,0,0,64
        $stream.Write($request,0,$request.Length)
        [byte[]]$header = Read-Exact $stream 7
        $length = [int]$header[4]*256 + $header[5]
        if ($header[0] -ne 0 -or $header[1] -ne 1 -or $header[2] -ne 0 -or
            $header[3] -ne 0 -or $header[6] -ne 1 -or $length -ne 131) {
            throw 'Unexpected MBAP. Check that the new firmware is running.'
        }
        [byte[]]$pdu = Read-Exact $stream ($length-1)
        if ($pdu[0] -ne 4 -or $pdu[1] -ne 128 -or $pdu[2] -ne 0x4e -or $pdu[3] -ne 0x49) {
            throw 'Invalid FC04 network identity response'
        }
        # PDU begins with Function and ByteCount, followed by big-endian words.
        [int[]]$r = New-Object int[] 64
        for ($i=0; $i -lt 64; $i++) { $r[$i] = [int]$pdu[2+2*$i]*256 + $pdu[3+2*$i] }
        $clientIP = Get-AddressBytes $pdu (2+16*2)
        $clientMask = 'unknown (not reported)'
        if ($r[24] -eq 1) { $clientMask = Get-AddressBytes $pdu (2+18*2) }
        $clientMAC = 'unknown (off-link or not in ARP cache)'
        if ($r[23] -eq 1) {
            $clientMAC = (($pdu[(2+20*2)..(2+23*2-1)] | ForEach-Object { $_.ToString('X2') }) -join ':')
        }
        $mode = switch ($r[2]) { 1 {'DHCP'} 2 {'AutoIP'} default {'pending'} }
        Write-Host "  Modbus FC04 OK; board mode=$mode; link=$($r[3])"
        Write-Host "  Client seen by board: IP=$clientIP  MAC=$clientMAC  Mask=$clientMask"
        Write-Host "  Client mask is a host report, not authenticated detection."
    } finally { $tcp.Close() }
}
$rows = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.AddressState -eq 'Preferred' -and $_.IPAddress -ne '127.0.0.1' -and $_.PrefixLength -gt 0 -and $_.PrefixLength -lt 31
})
if ($InterfaceIP) { $rows = @($rows | Where-Object { $_.IPAddress -eq $InterfaceIP }) }
if ($rows.Count -eq 0) { throw 'No matching PC interface. Check ipconfig; InterfaceIP does not assign an address.' }
$devices = @{}
foreach ($row in $rows) {
    $udp = $null
    try {
        [byte[]]$ip = [System.Net.IPAddress]::Parse($row.IPAddress).GetAddressBytes()
        [byte[]]$mask = New-Object byte[] 4
        [byte[]]$broadcast = New-Object byte[] 4
        for ($i=0; $i -lt 4; $i++) {
            $bits = [Math]::Min(8,[Math]::Max(0,[int]$row.PrefixLength-8*$i))
            $mask[$i] = if ($bits -eq 0) {0} else {256-[int][Math]::Pow(2,8-$bits)}
            $broadcast[$i] = $ip[$i] -bor (255-$mask[$i])
        }
        $destination = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::new($broadcast),30303)
        $local = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($row.IPAddress),0)
        $udp = [System.Net.Sockets.UdpClient]::new($local)
        $udp.EnableBroadcast = $true; $udp.Client.ReceiveTimeout = 300
        [byte[]]$nonce = New-Object byte[] 8
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($nonce) } finally { $rng.Dispose() }
        [byte[]]$request = [System.Text.Encoding]::ASCII.GetBytes('F107FIND') + $nonce + $mask
        Write-Host "Scanning PC interface: $($row.IPAddress)/$($row.PrefixLength)"
        $watch = [System.Diagnostics.Stopwatch]::StartNew(); $nextSend = 0; $sends = 0
        while ($watch.ElapsedMilliseconds -lt 3000) {
            if ($sends -lt 3 -and $watch.ElapsedMilliseconds -ge $nextSend) {
                [void]$udp.Send($request,$request.Length,$destination); $sends++; $nextSend += 600
            }
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0)
            try { [byte[]]$reply = $udp.Receive([ref]$remote) }
            catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) { continue }
                throw
            }
            if ($reply.Length -ne 60 -or $remote.Port -ne 30303 -or
                [System.Text.Encoding]::ASCII.GetString($reply,0,8) -ne 'F107HERE') { continue }
            $match = $true
            for ($i=0; $i -lt 8; $i++) { if ($reply[8+$i] -ne $nonce[$i]) { $match=$false } }
            if (-not $match) { continue }
            $address = Get-AddressBytes $reply 16
            if ($address -ne $remote.Address.ToString()) { continue }
            # Accept only replies on the selected adapter subnet.
            $onSubnet = $true
            for ($i=0; $i -lt 4; $i++) {
                if (($reply[16+$i] -band $mask[$i]) -ne ($ip[$i] -band $mask[$i])) { $onSubnet=$false }
            }
            if (-not $onSubnet) { continue }
            $port = [int]$reply[30]*256 + $reply[31]
            if ($port -ne 502) { continue }
            $uid = (($reply[32..43] | ForEach-Object { $_.ToString('X2') }) -join '')
            $isNew = -not $devices.ContainsKey($uid)
            $devices[$uid] = @{IP=$address; LocalIP=$row.IPAddress}
            $mac = (($reply[24..29] | ForEach-Object { $_.ToString('X2') }) -join ':')
            $boardMask = Get-AddressBytes $reply 20
            if ($isNew) {
                Write-Host "FOUND IP=$address  Mask=$boardMask  MAC=$mac  UID=$uid"
            }
        }
    } catch { Write-Warning "Interface $($row.IPAddress): $($_.Exception.Message)" }
    finally { if ($null -ne $udp) { $udp.Close() } }
}
if ($devices.Count -eq 0) {
    Write-Host 'No board found. Wait for DHCP/AutoIP, then retry. Check link, subnet and UDP firewall.'
    exit 1
}
if (-not $NoModbus) {
    $failed = $false
    foreach ($device in $devices.Values) {
        $address = $device.IP
        try { Read-NetworkRegisters $address $device.LocalIP }
        catch { Write-Warning "Modbus $address : $($_.Exception.Message)"; $failed=$true }
    }
    if ($failed) { exit 1 }
}
exit 0
