# Let's Escape

A file upload service that carries **1 KiB raw chunks in HTTP GET query parameters**. It includes a PowerShell client and an upload page that shows progress and a shareable download link. The server verifies the whole-file SHA-256 before making a download available, and the link expires **24 hours after verification**.

## Run locally

Requires Linux and Python 3.12 or newer. No Python packages are needed.

```sh
python3 server.py
```

Open `http://localhost:8080`, download `Upload-File.ps1`, enter a local file path, and copy the generated command. The page tracks that transfer while PowerShell sends the chunks. The script can also run directly in Windows PowerShell 5.1 or PowerShell 7:

```powershell
Unblock-File .\Upload-File.ps1
.\Upload-File.ps1 -ServerUrl http://localhost:8080 -Path 'C:\files\report.zip' -OpenResult
```

Your execution policy must allow scripts. The client requires HTTPS for remote servers; HTTP is allowed only for loopback development. It hashes and streams the file from a single read handle, rather than loading the entire file into memory.

If interrupted, rerun with the same file and transfer ID printed by the client:

```powershell
.\Upload-File.ps1 -ServerUrl https://upload.example.com -Path 'C:\files\report.zip' -TransferId '0123456789abcdef0123456789abcdef' -OpenResult
```

The client requests missing sequences, retries network failures and HTTP 408/429/5xx responses with exponential backoff and jitter, and checks every acknowledgment. `-MaxAttempts` defaults to 5 per request. Successful output includes `DownloadUrl`, `ResultPage`, `ExpiresUtc`, and `SHA256`. The result page uses a URL fragment for the transfer ID, keeping that ID out of the page's initial request.

## Protocol

All fields are URL encoded. Transfer IDs are random 128-bit values written as 32 lowercase hexadecimal characters. Treat them as bearer capabilities: anyone holding one can query transfer progress and obtain the eventual download URL.

1. Register file metadata (idempotent for the same ID and metadata):

   ```text
   GET /start?id=<id>&name=report.zip&size=43000&sha256=<64-lowercase-hex>
   ```

   The JSON response declares `chunk_size`, `total`, `received`, `state`, and `expires`. The total is calculated by the server. Empty files use one empty chunk.

2. Send each chunk using unpadded Base64URL:

   ```text
   GET /receive?id=<id>&seq=0&total=42&data=<base64url-chunk>
   GET /receive?id=<id>&seq=1&total=42&data=<base64url-chunk>
   ```

   A success response acknowledges `ack` (the sequence) and `received` (unique chunk count). Chunks can arrive out of order. Identical duplicates are harmless; conflicting duplicates return HTTP 409. An acknowledgment is sent only after SQLite commits the chunk. A lost final acknowledgment can safely be retried without extending the download expiry.

3. Resume or poll:

   ```text
   GET /status?id=<id>
   ```

   Uploading responses include up to 1,024 `missing` sequences. Fill those, then requery for the next batch. Once all chunks arrive, the server streams them in sequence into a file, checks its length and SHA-256, syncs it to disk, and atomically publishes it. Only `state: complete` includes `download_url`. A checksum mismatch persists `state: failed`, deletes the invalid chunks, and returns HTTP 422; use a new ID to retry the file.

4. Download:

   ```text
   GET /download/<random-256-bit-token>
   ```

   Downloads use `application/octet-stream`, attachment disposition, the original filename, and an `X-File-SHA256` response header. A download may begin only before expiry; an already running response can finish. Range requests are not supported.

An incomplete upload expires 24 hours after creation. Verified files expire 24 hours after completion; neither status reads nor downloads extend this deadline. Expired access returns HTTP 410 until cleanup removes the record, then HTTP 404. A cleanup worker deletes expired files and records every minute and at startup. SQLite reuses freed pages, so its allocated file size need not shrink immediately. Chunks, metadata, and completed files survive process restarts. Run one service process per data directory on local storage; use the proxy in front for public access.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `8080` | Listen port |
| `DATA_DIR` | `data` | Private SQLite and file storage directory |
| `CHUNK_SIZE` | `1024` | Raw bytes per chunk, from 64 to 1024 |
| `MAX_FILE_BYTES` | `26214400` | Maximum file size, 25 MiB |
| `MAX_STORAGE_BYTES` | `1073741824` | Sum of reserved file sizes, 1 GiB |
| `MAX_TRANSFERS` | `100` | Maximum retained transfers, including incomplete/failed ones |

The storage budget reserves the declared file size when a transfer starts. Leave additional disk capacity for SQLite overhead, WAL, and the temporary assembled file: this is a logical file budget, not a hard disk quota. Capacity exhaustion returns HTTP 503. The service limits itself to 32 request threads and sets connection timeouts. `/health` is a liveness check; `/config` exposes the chunk and file-size limits.

## Deploy

```sh
docker compose up --build -d
```

The container runs as an unprivileged user with a read-only root filesystem and a persistent named volume. The published port listens on loopback. Put a TLS reverse proxy in front. `deploy/nginx.conf` includes an example with URL buffers, per-IP request/connection limits, no proxy caching or automatic retries, and access logs that omit the entire request URL and Referer. Replace its hostname/certificate paths, install your certificate, and validate with `nginx -t` before reloading.

One 1,024-byte chunk becomes 1,366 Base64URL characters (roughly 33% overhead). Normal `/receive` URLs are under 1.5 KiB; the app rejects URLs over 2,048 bytes. Check **every** proxy, WAF, CDN, and server in your deployment with a full-size chunk. Reduce `CHUNK_SIZE` if an intermediary has a smaller limit; existing transfers keep their original chunk size.

All app responses carry `Cache-Control: no-store`, `Pragma: no-cache`, and `Referrer-Policy: no-referrer`. Configure any CDN to bypass caching for this service, and disable request/query capture in upstream access logs, tracing, and analytics. The Python handler does not log request URLs. The Nginx example suppresses error logging because those messages can include the original URL; use app diagnostics when investigating failures.

This is an anonymous upload service: possession of the generated links grants access, and there are no accounts or encryption at rest. GET-based persistence conflicts with GET's intended read-only semantics, and URLs can appear in intermediary logs even over HTTPS. Use HTTPS and trusted intermediaries. For a private deployment, add authentication at the reverse proxy; public deployments should also apply infrastructure quotas. The included client never redirects payload-bearing requests and never prints payload URLs in transport errors.

## Test

```sh
python3 -m unittest discover -s tests -v
node --check web/app.js
```

The tests use a live HTTP server and cover out-of-order chunks, duplicate/conflicting retries, concurrent requests, resume after restart, zero-byte files, SHA-256 failure, URL/input limits, HEAD behavior, expiry and cleanup, capacity limits, and response headers. With `pwsh` installed, they also run the actual PowerShell uploader against the server, resume a partially uploaded binary file, rerun a completed upload, and compare downloaded bytes. CI requires PowerShell and builds the container too.
