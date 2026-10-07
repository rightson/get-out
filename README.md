# Let's Escape

A file upload service that carries **1 KiB raw chunks in HTTP GET query parameters**. The upload page sends files straight from the browser, shows progress, and gives a shareable download link; PowerShell and POSIX shell clients are the fallback when a browser can't upload. The server verifies the whole-file SHA-256 before making a download available. The uploader chooses when the link disappears (**0.1 to 24 hours after verification**) and can require a **download password**. At expiry the link stops working and the file is deleted. The server keeps an audit log of uploads and download-link visits (see [Audit log](#audit-log)).

## Run locally

Requires Linux and Python 3.12 or newer. No Python packages are needed.

```sh
python3 server.py
python3 server.py --port 9000 --max-file-mb 50
python3 server.py --watch      # development: restart when server.py changes
python3 server.py audit        # print upload and download history
```

`--port`, `--max-file-mb` (default 10 MiB), and `--trust-proxy` override the `PORT`, `MAX_FILE_MB`, and `TRUST_PROXY` environment variables. `--watch` runs the server in a child process and restarts it within about a second of a change to `server.py`; the web page and client scripts are read on each request, so they never need a restart.

Open `http://localhost:8080`, choose a file, set when the link disappears and an optional download password, and select **Upload**. The browser reads the file with the File API, computes its SHA-256 with Web Crypto, and sends chunks with the same GET protocol as the scripts (four requests in flight, with the scripts' retry policy). No local path is needed: browsers never reveal one. Web Crypto requires HTTPS (or `localhost`), and the whole file is read into memory, which is fine within the file-size limit.

If the browser can't upload (the network blocks it, retries run out, or the page isn't served over HTTPS), the page opens **Browser can't upload? Use a script instead** and explains why. The generated commands use the same transfer ID, expiry, and password setting, so a script resumes whatever the browser already sent. Rejections a script can't fix, such as an oversized file, don't open it.

## PowerShell client

Download `Upload-File.ps1` from the page, enter the file's local path, and copy the generated command. The page tracks that transfer while PowerShell sends the chunks. The script can also run directly in Windows PowerShell 5.1 or PowerShell 7:

```powershell
Unblock-File .\Upload-File.ps1
.\Upload-File.ps1 -ServerUrl http://localhost:8080 -Path 'C:\files\report.zip' -ExpiresHours 1 -OpenResult
```

`-ExpiresHours` is required: the download link disappears that long after the upload is verified (0.1 to 24, up to two decimals). To require a download password, add `-DownloadPassword (Read-Host 'Download password' -AsSecureString)`.

Your execution policy must allow scripts. The client requires HTTPS for remote servers; HTTP is allowed only for loopback development. It hashes and streams the file from a single read handle, rather than loading the entire file into memory.

If interrupted, rerun with the same file and transfer ID printed by the client:

```powershell
.\Upload-File.ps1 -ServerUrl https://upload.example.com -Path 'C:\files\report.zip' -ExpiresHours 1 -TransferId '0123456789abcdef0123456789abcdef' -OpenResult
```

Both clients request missing sequences, retry network failures and HTTP 408/429/5xx responses with exponential backoff and jitter, and check every acknowledgment. The default is 5 attempts per request. A resume must repeat the same expiry and password. Successful output includes `DownloadUrl`, `ResultPage`, `ExpiresUtc`, `PasswordProtected`, and `SHA256`. The result page uses a URL fragment for the transfer ID, keeping that ID out of the page's initial request.

## Bash / POSIX shell client

The upload page's script section provides `Upload-File.sh` beside the PowerShell download, with a generated command for each. The shell script uses POSIX `sh` syntax and runs under `sh`, `dash`, or Bash on Linux and macOS; Bash-specific features are not required. Dependencies: `curl`, `jq`, `base64`, standard shell utilities, and one of `sha256sum`, `shasum`, or `openssl`. It uses `/dev/urandom` to generate transfer IDs. Install `jq` if needed (for example, `sudo apt install jq` or `brew install jq`).

```sh
sh ./Upload-File.sh --server-url http://localhost:8080 --path './report.zip' --expires-hours 1 --open-result
```

Add `--ask-password` to require a download password. The script prompts twice on a terminal without echoing; otherwise it reads the first line of stdin (`printf '%s\n' "$pw" | sh ./Upload-File.sh ... --ask-password`). The password is passed to curl through a private header file, never on the command line.

Resume an interrupted upload with its transfer ID:

```sh
sh ./Upload-File.sh --server-url https://upload.example.com --path './report.zip' \
  --expires-hours 1 --transfer-id '0123456789abcdef0123456789abcdef' --open-result
```

| PowerShell | POSIX shell |
| --- | --- |
| `-ServerUrl` | `--server-url` |
| `-Path` | `--path` |
| `-ExpiresHours` | `--expires-hours` |
| `-DownloadPassword` | `--ask-password` |
| `-TransferId` | `--transfer-id` |
| `-MaxAttempts` | `--max-attempts` |
| `-OpenResult` | `--open-result` |

The shell client prints progress to stderr and the result object as JSON to stdout, so you can save it with `> result.json`. `--open-result` uses `xdg-open` on Linux or `open` on macOS; without a browser opener it prints the result page URL for manual use. It accepts HTTPS for remote servers and HTTP only for loopback, does not follow redirects, ignores `.curlrc`, and removes its private temporary files on exit. It streams one chunk at a time; keep the source file unchanged during upload. Use `--help` for all options.

## Protocol

All fields are URL encoded. Transfer IDs are random 128-bit values written as 32 lowercase hexadecimal characters. Treat them as bearer capabilities: anyone holding one can query transfer progress and obtain the eventual download URL.

1. Register file metadata (idempotent for the same ID and metadata):

   ```text
   GET /start?id=<id>&name=report.zip&size=43000&sha256=<64-lowercase-hex>&ttl_hours=1
   Authorization: Basic <base64(":" + download password)>     (optional)
   ```

   `ttl_hours` (0.1 to 24, up to two decimals) sets how long the download link lives after verification. The optional password travels in a Basic `Authorization` header, never the URL, and is stored only as a salted scrypt hash. Repeating `/start` for the same ID must send the same metadata, `ttl_hours`, and password, or it returns HTTP 409. The JSON response declares `chunk_size`, `total`, `received`, `state`, `expires`, `ttl_hours`, and `password_protected`. The total is calculated by the server. Empty files use one empty chunk.

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

   Downloads use `application/octet-stream`, attachment disposition, the original filename, and an `X-File-SHA256` response header. A password-protected download returns HTTP 401 with `WWW-Authenticate: Basic` until the request carries the password: browsers show their sign-in prompt (any username), and curl uses `curl -u ':password'`. A download may begin only before expiry; an already running response can finish. Range requests are not supported.

An incomplete upload expires 24 hours after creation, regardless of the chosen link lifetime, so a short lifetime cannot expire a slow upload. Verified files expire `ttl_hours` after completion; neither status reads nor downloads extend this deadline. At expiry the link returns HTTP 410 immediately, and a cleanup worker (every minute and at startup) deletes the file, its chunks, and the transfer record; the link then returns HTTP 404. SQLite runs with `secure_delete`, so deleted rows are overwritten. Overwriting a file before unlinking it gives no guarantee on SSDs or copy-on-write filesystems, so the service does not attempt it; use encrypted storage if you need that guarantee. SQLite reuses freed pages, so its allocated file size need not shrink immediately. Chunks, metadata, and completed files survive process restarts. Run one service process per data directory on local storage; use the proxy in front for public access.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `8080` | Listen port |
| `DATA_DIR` | `data` | Private SQLite and file storage directory |
| `CHUNK_SIZE` | `1024` | Raw bytes per chunk, from 64 to 1024 |
| `MAX_FILE_MB` | `10` | Maximum file size in MiB (`--max-file-mb`) |
| `MAX_STORAGE_BYTES` | `1073741824` | Sum of reserved file sizes, 1 GiB |
| `MAX_TRANSFERS` | `100` | Maximum retained transfers, including incomplete/failed ones |
| `TRUST_PROXY` | unset | `1` logs the client IP from the proxy's `X-Real-IP` header (`--trust-proxy`) |

The storage budget reserves the declared file size when a transfer starts. Leave additional disk capacity for SQLite overhead, WAL, and the temporary assembled file: this is a logical file budget, not a hard disk quota. Capacity exhaustion returns HTTP 503. The service limits itself to 32 request threads and sets connection timeouts. `/health` is a liveness check; `/config` exposes the chunk size, file-size limit, and allowed link lifetime (`min_ttl_hours`, `max_ttl_hours`).

## Audit log

The database keeps two tables that cleanup never deletes, so the history remains after the file is gone:

- `upload_log`: uploader IP, start/completion/expiry/deletion times, filename, size, SHA-256, chosen lifetime, whether a password was set, and final state (`complete`, `failed`, or `abandoned`).
- `access_log`: every request to an issued download link, with IP, time, User-Agent, and result: `downloaded`, `interrupted`, `password_required`, `wrong_password`, `expired`, or `not_found` (after deletion). Requests for tokens the service never issued are not recorded.

`python3 server.py audit` (or `docker compose exec upload python server.py audit`) opens the database read-only and prints tab-separated uploads with click and completed-download counts, followed by every access. Records are kept indefinitely; IP addresses can be personal data, so set a retention policy that fits your jurisdiction. Behind a reverse proxy, every request comes from the proxy's address: set `--trust-proxy` (`TRUST_PROXY=1`) and have the proxy set `X-Real-IP`, as `deploy/nginx.conf` does. Never enable it when clients can reach the service directly, because they could forge the header.

## Deploy

```sh
docker compose up --build -d
```

The container runs as an unprivileged user with a read-only root filesystem and a persistent named volume. The published port listens on loopback. Put a TLS reverse proxy in front. `deploy/nginx.conf` includes an example with URL buffers, per-IP request/connection limits, no proxy caching or automatic retries, and access logs that omit the entire request URL and Referer. Replace its hostname/certificate paths, install your certificate, and validate with `nginx -t` before reloading.

One 1,024-byte chunk becomes 1,366 Base64URL characters (roughly 33% overhead). Normal `/receive` URLs are under 1.5 KiB; the app rejects URLs over 2,048 bytes. Check **every** proxy, WAF, CDN, and server in your deployment with a full-size chunk. Reduce `CHUNK_SIZE` if an intermediary has a smaller limit; existing transfers keep their original chunk size.

All app responses carry `Cache-Control: no-store`, `Pragma: no-cache`, and `Referrer-Policy: no-referrer`. Configure any CDN to bypass caching for this service, and disable request/query capture in upstream access logs, tracing, and analytics. The Python handler does not log request URLs. The Nginx example suppresses error logging because those messages can include the original URL; use app diagnostics when investigating failures.

This is an anonymous upload service: possession of the generated links (plus the download password, if one is set) grants access, and there are no accounts or encryption at rest. The upload page tells users that IP addresses and visits are logged. GET-based persistence conflicts with GET's intended read-only semantics, and URLs can appear in intermediary logs even over HTTPS. Use HTTPS and trusted intermediaries. For a private deployment, add authentication at the reverse proxy; public deployments should also apply infrastructure quotas. The included client never redirects payload-bearing requests and never prints payload URLs in transport errors.

## Test

```sh
python3 -m unittest discover -s tests -v
node --check web/app.js
```

The tests use a live HTTP server and cover out-of-order chunks, duplicate/conflicting retries, concurrent requests, resume after restart, zero-byte files, SHA-256 failure, URL/input limits, HEAD behavior, uploader-chosen expiry and cleanup, download passwords, the audit log and proxy IP handling, `--watch` restarts, capacity limits, and response headers. With Node.js installed, they load `web/app.js` against a minimal DOM stub (`tests/browser_upload.mjs`) and run real browser uploads with and without a password, plus the oversized-file and unreachable-server fallbacks. With `sh`, `curl`, and `jq` installed, they also exercise the actual shell client, including binary/empty files, partial resume, completed retries, lost acknowledgments, and a password read from stdin. With `pwsh` installed, they run the PowerShell uploader with a download password, resume a partially uploaded binary file, rerun a completed upload, and compare downloaded bytes. CI requires the client dependencies and builds the container too.
