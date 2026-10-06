#requires -Version 5.1
<#
.SYNOPSIS
Upload a file using acknowledged, resumable Base64URL GET requests.
.EXAMPLE
.\Upload-File.ps1 -ServerUrl https://upload.example.com -Path .\report.zip -OpenResult
.EXAMPLE
.\Upload-File.ps1 -ServerUrl https://upload.example.com -Path .\report.zip -TransferId 0123456789abcdef0123456789abcdef
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [Parameter(Mandatory = $true)][string]$Path,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$TransferId = [Guid]::NewGuid().ToString('N'),
    [ValidateRange(1, 10)][int]$MaxAttempts = 5,
    [switch]$OpenResult
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
# Windows PowerShell uses the machine's TLS settings, with TLS 1.2 also enabled.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$baseUri = [Uri]$ServerUrl
if (-not $baseUri.IsAbsoluteUri -or $baseUri.Scheme -notin @('http', 'https') -or
    $baseUri.Query -or $baseUri.Fragment -or $baseUri.UserInfo) {
    throw 'ServerUrl must be an absolute HTTP(S) URL without credentials, query, or fragment.'
}
if ($baseUri.Scheme -eq 'http' -and -not $baseUri.IsLoopback) {
    throw 'Use HTTPS for remote uploads; HTTP is supported only on loopback for development.'
}
$baseUrl = $baseUri.AbsoluteUri.TrimEnd('/')
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(60)
$client.DefaultRequestHeaders.TryAddWithoutValidation('Cache-Control', 'no-store, no-cache') | Out-Null
$client.DefaultRequestHeaders.TryAddWithoutValidation('Pragma', 'no-cache') | Out-Null
$stream = $null
$hasher = $null

function Invoke-UploadGet {
    param([string]$Endpoint, [hashtable]$Parameters)
    $pairs = foreach ($key in ($Parameters.Keys | Sort-Object)) {
        [Uri]::EscapeDataString([string]$key) + '=' + [Uri]::EscapeDataString([string]$Parameters[$key])
    }
    $uri = $baseUrl + $Endpoint + '?' + ($pairs -join '&')
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $response = $null
        $retry = $true
        $failure = 'No acknowledgment from the server.'
        try {
            $response = $client.GetAsync($uri).GetAwaiter().GetResult()
            $statusCode = [int]$response.StatusCode
            if ($response.IsSuccessStatusCode) {
                return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
            }
            # Never print a request URL, payload, or a transport exception containing one.
            $failure = "Upload request rejected (HTTP $statusCode)."
            $retry = ($statusCode -eq 408 -or $statusCode -eq 429 -or $statusCode -ge 500)
        }
        catch {
            $failure = 'Network request failed or acknowledgment was unreadable.'
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
        }
        if (-not $retry -or $attempt -eq $MaxAttempts) { throw $failure }
        Start-Sleep -Milliseconds ([int]([Math]::Min(8000, 500 * [Math]::Pow(2, $attempt - 1)) + (Get-Random -Minimum 0 -Maximum 250)))
    }
}

try {
    $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
    # Keep the same file handle for hashing and sending, and deny concurrent writes.
    $stream = [IO.File]::Open($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $hasher = [Security.Cryptography.SHA256]::Create()
    $digest = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    $stream.Position = 0
    $size = $stream.Length
    Write-Host "Transfer ID: $TransferId"
    Write-Host 'Keep this ID to resume an interrupted upload of the same file.'
    $transfer = Invoke-UploadGet '/start' @{
        id = $TransferId; name = [IO.Path]::GetFileName($resolved); size = $size; sha256 = $digest
    }
    $chunkSize = [int]$transfer.chunk_size
    if ($chunkSize -lt 64 -or $chunkSize -gt 1024 -or $transfer.id -ne $TransferId) {
        throw 'Server returned invalid transfer metadata.'
    }
    $total = [int]$transfer.total
    if ($total -ne [Math]::Max(1, [Math]::Ceiling($size / $chunkSize))) {
        throw 'Server returned an invalid chunk count.'
    }
    $buffer = [byte[]]::new($chunkSize)
    while ($transfer.state -eq 'uploading') {
        $transfer = Invoke-UploadGet '/status' @{ id = $TransferId }
        if ($transfer.state -ne 'uploading') { break }
        if (@($transfer.missing).Count -eq 0) { throw 'Server returned no missing chunks for an incomplete transfer.' }
        foreach ($sequence in $transfer.missing) {
            $seq = [int]$sequence
            if ($seq -lt 0 -or $seq -ge $total) { throw 'Server returned an invalid missing sequence.' }
            $offset = [long]$seq * $chunkSize
            $length = [int][Math]::Min($chunkSize, $size - $offset)
            $stream.Position = $offset
            $read = 0
            while ($read -lt $length) {
                $count = $stream.Read($buffer, $read, $length - $read)
                if ($count -eq 0) { throw 'Unexpected end of local file.' }
                $read += $count
            }
            $encoded = [Convert]::ToBase64String($buffer, 0, $length).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $ack = Invoke-UploadGet '/receive' @{ id = $TransferId; seq = $seq; total = $total; data = $encoded }
            if ($ack.ack -ne $seq -or $ack.id -ne $TransferId) { throw 'Invalid chunk acknowledgment.' }
            Write-Progress -Activity 'Uploading via GET' -Status "$($ack.received) / $total chunks acknowledged" -PercentComplete ([int](100 * $ack.received / $total))
        }
    }
    $transfer = Invoke-UploadGet '/status' @{ id = $TransferId }
    if ($transfer.state -ne 'complete' -or $transfer.sha256 -ne $digest -or $transfer.size -ne $size) {
        throw 'File was not successfully verified by the server. Start a new transfer if verification failed.'
    }
    $resultUrl = $baseUrl + '/#id=' + $TransferId
    $downloadUrl = $baseUrl + $transfer.download_url
    Write-Progress -Activity 'Uploading via GET' -Completed
    if ($OpenResult) { Start-Process $resultUrl }
    [pscustomobject]@{
        TransferId = $TransferId
        DownloadUrl = $downloadUrl
        ResultPage = $resultUrl
        ExpiresUtc = [DateTimeOffset]::FromUnixTimeSeconds([long][Math]::Floor($transfer.expires)).UtcDateTime
        SHA256 = $digest
    }
}
finally {
    if ($null -ne $stream) { $stream.Dispose() }
    if ($null -ne $hasher) { $hasher.Dispose() }
    $client.Dispose()
    $handler.Dispose()
}
