#!/bin/sh
# POSIX shell uploader for Linux/macOS. Requires curl, jq, base64, and a SHA-256 tool.
set -eu
LC_ALL=C
export LC_ALL

usage() {
    cat <<'EOF'
Usage: sh Upload-File.sh --server-url URL --path FILE --expires-hours H [options]
  --server-url URL   HTTPS service URL (HTTP allowed only on loopback)
  --path FILE        File to upload
  --expires-hours H  Download link lifetime after upload, 0.1 to 24 hours
  --ask-password     Require a download password (read from the terminal, or the first line of stdin)
  --transfer-id ID   32 lowercase hex characters; reuse to resume the same file
  --max-attempts N   Attempts per request, from 1 to 10 (default: 5)
  --open-result     Open the result page using xdg-open or macOS open
  --help            Show this help

Example:
  sh Upload-File.sh --server-url https://upload.example.com --path './report.zip' --expires-hours 1 --open-result
EOF
}

die() { printf '%s\n' "$*" >&2; exit 1; }
server_url=
file_path=
transfer_id=
max_attempts=5
expires_hours=
ask_password=0
open_result=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --server-url|--path|--transfer-id|--max-attempts|--expires-hours)
            [ "$#" -ge 2 ] || die "Missing value for $1"
            case "$1" in
                --server-url) server_url=$2 ;;
                --path) file_path=$2 ;;
                --transfer-id) transfer_id=$2 ;;
                --max-attempts) max_attempts=$2 ;;
                --expires-hours) expires_hours=$2 ;;
            esac
            shift 2 ;;
        --open-result) open_result=1; shift ;;
        --ask-password) ask_password=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done
[ -n "$server_url" ] && [ -n "$file_path" ] && [ -n "$expires_hours" ] || { usage >&2; exit 1; }
# Same format and range as the server: up to two decimals, 0.1 to 24.
printf '%s\n' "$expires_hours" | awk '/^(0|[1-9][0-9]?)(\.[0-9][0-9]?)?$/ && $1 >= 0.1 && $1 <= 24 { ok = 1 } END { exit !ok }' ||
    die '--expires-hours must be from 0.1 to 24.'
case "$max_attempts" in 1|2|3|4|5|6|7|8|9|10) ;; *) die '--max-attempts must be from 1 to 10.' ;; esac
for tool in curl jq base64 dd od tr awk wc mkdir rm; do
    command -v "$tool" >/dev/null 2>&1 || die "Required command is missing: $tool"
done
case "$server_url" in
    *'?'*|*'#'*|*'@'*|*' '*|*'\'*) die 'Server URL must not contain credentials, query, fragment, or whitespace.' ;;
esac
case "$server_url" in
    https://*) ;;
    http://*)
        authority=${server_url#http://}
        authority=${authority%%/*}
        case "$authority" in
            localhost|127.0.0.1|'[::1]') ;;
            localhost:*|127.0.0.1:*|'[::1]':*)
                port=${authority##*:}
                case "$port" in ''|*[!0-9]*) die 'Invalid loopback port.' ;; esac ;;
            *) die 'Use HTTPS for remote uploads; HTTP is supported only on loopback.' ;;
        esac ;;
    *) die 'Server URL must be an absolute HTTP(S) URL.' ;;
esac
while [ "${server_url%/}" != "$server_url" ]; do server_url=${server_url%/}; done
case "$file_path" in /*) ;; *) file_path=$PWD/$file_path ;; esac
[ -f "$file_path" ] && [ -r "$file_path" ] || die 'File must be a readable regular file.'
if [ -z "$transfer_id" ]; then
    transfer_id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
fi
case "$transfer_id" in ''|*[!a-f0-9]*) die 'Transfer ID must be 32 lowercase hexadecimal characters.' ;; esac
[ "${#transfer_id}" -eq 32 ] || die 'Transfer ID must be 32 lowercase hexadecimal characters.'

# Exclusive mkdir and restrictive permissions avoid relying on a non-POSIX mktemp.
umask 077
work_dir=${TMPDIR:-/tmp}/lets-escape-$transfer_id-$$
mkdir "$work_dir" || die 'Could not create a private temporary directory.'
# Restore terminal echo if interrupted at the password prompt.
trap 'rm -rf "$work_dir"; if [ "$ask_password" -eq 1 ] && [ -t 0 ]; then stty echo; fi' 0
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum < "$file_path" > "$work_dir/hash"
    digest=$(awk '{print $1}' "$work_dir/hash")
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 < "$file_path" > "$work_dir/hash"
    digest=$(awk '{print $1}' "$work_dir/hash")
elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 < "$file_path" > "$work_dir/hash"
    digest=$(awk '{print $NF}' "$work_dir/hash")
else
    die 'Install sha256sum, shasum, or openssl to calculate SHA-256.'
fi
case "$digest" in ''|*[!a-f0-9]*) die 'Could not calculate SHA-256.' ;; esac
[ "${#digest}" -eq 64 ] || die 'Could not calculate SHA-256.'
size=$(wc -c < "$file_path" | tr -d ' ')
start_auth=
if [ "$ask_password" -eq 1 ]; then
    if [ -t 0 ]; then
        printf 'Download password: ' >&2
        stty -echo
        IFS= read -r password || password=
        stty echo
        printf '\nConfirm password: ' >&2
        stty -echo
        IFS= read -r confirm || confirm=
        stty echo
        printf '\n' >&2
        [ "$password" = "$confirm" ] || die 'Passwords do not match.'
    else
        IFS= read -r password || [ -n "$password" ] || die 'No password on stdin.'
    fi
    [ -n "$password" ] || die 'Download password must not be empty.'
    # Keep the password out of argv: curl reads the header from a private file.
    printf 'Authorization: Basic %s\n' "$(printf ':%s' "$password" | base64 | tr -d '\n')" > "$work_dir/auth"
    start_auth="@$work_dir/auth"
    unset password confirm
fi
name=${file_path##*/}
printf 'Transfer ID: %s\nKeep this ID to resume an interrupted upload of the same file.\n' "$transfer_id" >&2

# Subshell keeps retry variables out of the caller. Never log payload URLs or curl errors.
# --disable must be first: ignore curlrc settings such as redirects, verbose traces, or caching.
get() (
    endpoint=$1
    shift
    attempt=1
    delay=1
    while :; do
        if code=$(curl --disable --silent --get --globoff --proto '=http,https' \
            --connect-timeout 10 --max-time 60 \
            --header 'Cache-Control: no-store, no-cache' --header 'Pragma: no-cache' \
            --output "$work_dir/response.json" --write-out '%{http_code}' \
            "$server_url$endpoint" "$@" 2>/dev/null); then
            case "$code" in
                200)
                    if jq -e 'type == "object"' "$work_dir/response.json" >/dev/null 2>&1; then
                        exit 0
                    fi ;;
                408|429|5??) ;;
                *) die "Upload request rejected (HTTP $code)." ;;
            esac
        fi
        [ "$attempt" -lt "$max_attempts" ] || die 'Network request failed or acknowledgment was unreadable; retry limit reached.'
        # Integer exponential delay plus jitter works with POSIX sleep on Linux and macOS.
        jitter=$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')
        sleep "$((delay + jitter % 2))"
        attempt=$((attempt + 1))
        if [ "$delay" -lt 8 ]; then delay=$((delay * 2)); fi
    done
)

if [ -n "$start_auth" ]; then
    get /start --header "$start_auth" --data-urlencode "id=$transfer_id" --data-urlencode "name=$name" \
        --data-urlencode "size=$size" --data-urlencode "sha256=$digest" --data-urlencode "ttl_hours=$expires_hours"
else
    get /start --data-urlencode "id=$transfer_id" --data-urlencode "name=$name" \
        --data-urlencode "size=$size" --data-urlencode "sha256=$digest" --data-urlencode "ttl_hours=$expires_hours"
fi
chunk_size=$(jq -er '.chunk_size | select(type == "number" and . >= 64 and . <= 1024 and floor == .)' "$work_dir/response.json")
total=$(((size + chunk_size - 1) / chunk_size))
if [ "$total" -eq 0 ]; then total=1; fi
jq -e --arg id "$transfer_id" --argjson total "$total" '.id == $id and .total == $total' \
    "$work_dir/response.json" >/dev/null || die 'Server returned invalid transfer metadata.'
while :; do
    get /status --data-urlencode "id=$transfer_id"
    state=$(jq -er '.state' "$work_dir/response.json")
    case "$state" in
        complete) break ;;
        failed) die 'SHA-256 verification failed; start a new transfer.' ;;
        uploading) ;;
        *) die 'Server returned an invalid transfer state.' ;;
    esac
    jq -e --arg id "$transfer_id" --argjson total "$total" \
        '.id == $id and (.missing | type == "array" and length > 0 and all(.[]; type == "number" and floor == . and . >= 0 and . < $total))' \
        "$work_dir/response.json" >/dev/null || die 'Server returned invalid missing sequences.'
    # Save the missing batch separately; each acknowledgment overwrites response.json.
    jq -r '.missing[]' "$work_dir/response.json" > "$work_dir/missing"
    while IFS= read -r seq; do
        dd if="$file_path" of="$work_dir/chunk" bs="$chunk_size" skip="$seq" count=1 2>/dev/null
        expected=$((size - seq * chunk_size))
        if [ "$expected" -gt "$chunk_size" ]; then expected=$chunk_size; fi
        actual=$(wc -c < "$work_dir/chunk" | tr -d ' ')
        [ "$actual" -eq "$expected" ] || die 'Local file size changed during upload.'
        base64 < "$work_dir/chunk" > "$work_dir/base64"
        tr '+/' '-_' < "$work_dir/base64" | tr -d '=\015\012' > "$work_dir/encoded"
        if [ "$expected" -eq 0 ]; then
            # curl omits an empty name@file field; keep the required data= parameter.
            get /receive --data-urlencode "id=$transfer_id" --data-urlencode "seq=$seq" \
                --data-urlencode "total=$total" --data-urlencode 'data='
        else
            get /receive --data-urlencode "id=$transfer_id" --data-urlencode "seq=$seq" \
                --data-urlencode "total=$total" --data-urlencode "data@$work_dir/encoded"
        fi
        jq -e --arg id "$transfer_id" --argjson seq "$seq" '.id == $id and .ack == $seq' \
            "$work_dir/response.json" >/dev/null || die 'Invalid chunk acknowledgment.'
        received=$(jq -er '.received' "$work_dir/response.json")
        printf '\rUploading: %s / %s chunks acknowledged' "$received" "$total" >&2
    done < "$work_dir/missing"
done
jq -e --arg id "$transfer_id" --arg hash "$digest" --argjson size "$size" \
    '.id == $id and .state == "complete" and .sha256 == $hash and .size == $size and (.download_url | test("^/download/[a-f0-9]{64}$"))' \
    "$work_dir/response.json" >/dev/null || die 'File was not successfully verified by the server.'
printf '\nUploaded and verified.\n' >&2
result_url=$server_url/#id=$transfer_id
# Print machine-readable output equivalent to the PowerShell result object.
jq --arg base "$server_url" --arg page "$result_url" \
    '{TransferId: .id, DownloadUrl: ($base + .download_url), ResultPage: $page, ExpiresUtc: (.expires | floor | todateiso8601), PasswordProtected: .password_protected, SHA256: .sha256}' \
    "$work_dir/response.json"
if [ "$open_result" -eq 1 ]; then
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$result_url" >/dev/null 2>&1 || printf 'Could not open browser; use ResultPage above.\n' >&2
    elif command -v open >/dev/null 2>&1; then
        open "$result_url" >/dev/null 2>&1 || printf 'Could not open browser; use ResultPage above.\n' >&2
    else
        printf 'No browser opener found; use ResultPage above.\n' >&2
    fi
fi
