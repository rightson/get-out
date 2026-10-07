#!/usr/bin/env python3
"""Durable GET-only chunk uploads. Python 3.12+, no third-party dependencies."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlsplit

ROOT = Path(__file__).resolve().parent
# Uploaders choose the download lifetime; unfinished uploads get a fixed window.
MIN_TTL, MAX_TTL = 6 * 60, 24 * 60 * 60
UPLOAD_WINDOW = 24 * 60 * 60
TTL_RE = re.compile(r"(?:0|[1-9][0-9]?)(?:\.[0-9]{1,2})?\Z")
ID_RE = re.compile(r"[a-f0-9]{32}\Z")
HASH_RE = re.compile(r"[a-f0-9]{64}\Z")


class APIError(Exception):
    def __init__(self, status, message, headers=None):
        self.status, self.message, self.headers = status, message, headers


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + key.hex()


def password_matches(stored, password):
    if stored is None or password is None:
        return stored is None and password is None
    return hmac.compare_digest(hash_password(password, bytes.fromhex(stored.split("$")[0])), stored)


class Store:
    def __init__(self, directory, *, chunk_size=1024, max_file=10 * 1024**2,
                 max_storage=1024**3, max_transfers=100, clock=time.time):
        if not 64 <= chunk_size <= 1024 or min(max_file, max_storage, max_transfers) <= 0:
            raise ValueError("Invalid storage limits or chunk size")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.files = self.directory / "files"
        self.files.mkdir(exist_ok=True, mode=0o700)
        self.db = self.directory / "uploads.sqlite3"
        self.chunk_size, self.max_file = chunk_size, max_file
        self.max_storage, self.max_transfers, self.clock = max_storage, max_transfers, clock
        with self.connect() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS transfers (
                  id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL,
                  sha256 TEXT NOT NULL, total INTEGER NOT NULL, chunk_size INTEGER NOT NULL,
                  state TEXT NOT NULL, received INTEGER NOT NULL DEFAULT 0,
                  created REAL NOT NULL, expires REAL NOT NULL, token TEXT UNIQUE NOT NULL,
                  ttl REAL NOT NULL DEFAULT 3600, password TEXT
                );
                CREATE TABLE IF NOT EXISTS chunks (
                  id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
                  seq INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(id, seq)
                );
                -- Audit records outlive transfers: cleanup never deletes them.
                CREATE TABLE IF NOT EXISTS upload_log (
                  token TEXT PRIMARY KEY, transfer_id TEXT NOT NULL, ip TEXT NOT NULL,
                  name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
                  ttl REAL NOT NULL, password INTEGER NOT NULL, started REAL NOT NULL,
                  state TEXT NOT NULL, completed REAL, expires REAL, deleted REAL
                );
                CREATE TABLE IF NOT EXISTS access_log (
                  token TEXT NOT NULL REFERENCES upload_log(token), at REAL NOT NULL,
                  ip TEXT NOT NULL, result TEXT NOT NULL, user_agent TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS access_log_token ON access_log(token);
            """)
            # Databases created before per-transfer expiry and passwords.
            columns = {r[1] for r in conn.execute("PRAGMA table_info(transfers)")}
            if "ttl" not in columns:
                conn.execute("ALTER TABLE transfers ADD COLUMN ttl REAL NOT NULL DEFAULT 3600")
            if "password" not in columns:
                conn.execute("ALTER TABLE transfers ADD COLUMN password TEXT")
        self.cleanup()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA secure_delete=ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def transfer_id(value):
        if not ID_RE.fullmatch(value):
            raise APIError(400, "id must be 32 lowercase hexadecimal characters")
        return value

    @staticmethod
    def integer(value):
        if not re.fullmatch(r"0|[1-9][0-9]{0,9}", value):
            raise APIError(400, "Invalid integer parameter")
        return int(value)

    def get(self, conn, transfer_id):
        row = conn.execute("SELECT * FROM transfers WHERE id=?", (transfer_id,)).fetchone()
        if row is None:
            raise APIError(404, "Transfer not found")
        if row["expires"] <= self.clock():
            raise APIError(410, "Transfer expired")
        return row

    def result(self, row):
        result = {key: row[key] for key in
                  ("id", "name", "size", "sha256", "total", "chunk_size", "state", "received", "expires")}
        result["ttl_hours"] = row["ttl"] / 3600
        result["password_protected"] = row["password"] is not None
        if row["state"] == "complete":
            result["download_url"] = "/download/" + row["token"]
        return result

    def start(self, params, ip, password=None):
        transfer_id = self.transfer_id(params["id"])
        name, digest = params["name"], params["sha256"]
        size = self.integer(params["size"])
        if not TTL_RE.fullmatch(params["ttl_hours"]) or not MIN_TTL <= float(params["ttl_hours"]) * 3600 <= MAX_TTL:
            raise APIError(400, "ttl_hours must be from 0.1 to 24")
        ttl = round(float(params["ttl_hours"]) * 3600)
        if password is not None and not 1 <= len(password) <= 128:
            raise APIError(400, "Download password must be 1 to 128 characters")
        if not name or len(name.encode("utf-8")) > 180 or any(
                ord(c) < 32 or ord(c) == 127 or c in '/\\' for c in name):
            raise APIError(400, "Use a filename without paths or control characters (maximum 180 UTF-8 bytes)")
        if not HASH_RE.fullmatch(digest):
            raise APIError(400, "sha256 must be 64 lowercase hexadecimal characters")
        if size > self.max_file:
            raise APIError(413, "File exceeds the configured size limit")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM transfers WHERE id=?", (transfer_id,)).fetchone()
            if existing:
                existing = self.get(conn, transfer_id)
                if ((existing["name"], existing["size"], existing["sha256"], existing["ttl"]) != (name, size, digest, ttl)
                        or not password_matches(existing["password"], password)):
                    raise APIError(409, "Transfer id already belongs to different file metadata, expiry, or password")
                return self.result(existing)
            usage = conn.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM transfers").fetchone()
            if usage[0] >= self.max_transfers or usage[1] + size > self.max_storage:
                raise APIError(503, "Upload capacity reached; retry later")
            now, token = self.clock(), secrets.token_hex(32)
            conn.execute("INSERT INTO transfers(id,name,size,sha256,total,chunk_size,state,created,expires,token,ttl,password) "
                         "VALUES(?,?,?,?,?,?,'uploading',?,?,?,?,?)",
                         (transfer_id, name, size, digest, max(1, math.ceil(size / self.chunk_size)),
                          self.chunk_size, now, now + UPLOAD_WINDOW, token, ttl,
                          None if password is None else hash_password(password)))
            conn.execute("INSERT INTO upload_log(token,transfer_id,ip,name,size,sha256,ttl,password,started,state) "
                         "VALUES(?,?,?,?,?,?,?,?,?,'uploading')",
                         (token, transfer_id, ip, name, size, digest, ttl, password is not None, now))
            return self.result(self.get(conn, transfer_id))

    def receive(self, params):
        transfer_id = self.transfer_id(params["id"])
        seq, total = self.integer(params["seq"]), self.integer(params["total"])
        encoded = params["data"]
        if len(encoded) > 1366 or not re.fullmatch(r"[A-Za-z0-9_-]*", encoded):
            raise APIError(400, "Invalid unpadded Base64URL chunk")
        try:
            chunk = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        except ValueError:
            raise APIError(400, "Invalid Base64URL chunk") from None
        if base64.urlsafe_b64encode(chunk).decode().rstrip("=") != encoded:
            raise APIError(400, "Noncanonical Base64URL chunk")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self.get(conn, transfer_id)
            if total != row["total"] or seq >= total:
                raise APIError(400, "Invalid sequence or total count")
            expected = min(row["chunk_size"], row["size"] - seq * row["chunk_size"])
            if len(chunk) != expected:
                raise APIError(400, "Chunk size does not match the declared file size")
            if row["state"] == "failed":
                raise APIError(422, "SHA-256 verification failed; start a new transfer")
            if row["state"] == "complete":
                # A final acknowledgment can be lost. Check duplicate bytes against the saved file.
                with (self.files / transfer_id).open("rb") as file:
                    file.seek(seq * row["chunk_size"])
                    if file.read(expected) != chunk:
                        raise APIError(409, "Duplicate sequence contains different bytes")
                return {**self.result(row), "ack": seq, "duplicate": True}
            existing = conn.execute("SELECT data FROM chunks WHERE id=? AND seq=?", (transfer_id, seq)).fetchone()
            if existing and existing[0] != chunk:
                raise APIError(409, "Duplicate sequence contains different bytes")
            if not existing:
                conn.execute("INSERT INTO chunks VALUES(?,?,?)", (transfer_id, seq, chunk))
                conn.execute("UPDATE transfers SET received=received+1 WHERE id=?", (transfer_id,))
            row = self.get(conn, transfer_id)
            if row["received"] == total:
                self.finish(conn, row)
                row = self.get(conn, transfer_id)
            result = {**self.result(row), "ack": seq, "duplicate": existing is not None}
        # Commit failed status before reporting the integrity error.
        if result["state"] == "failed":
            raise APIError(422, "SHA-256 verification failed; start a new transfer")
        return result

    def finish(self, conn, row):
        target = self.files / row["id"]
        temporary = target.with_suffix(".tmp")
        digest, size = hashlib.sha256(), 0
        try:
            with temporary.open("wb") as file:
                for chunk in conn.execute("SELECT data FROM chunks WHERE id=? ORDER BY seq", (row["id"],)):
                    file.write(chunk[0])
                    digest.update(chunk[0])
                    size += len(chunk[0])
                file.flush()
                os.fsync(file.fileno())
            if size != row["size"] or digest.hexdigest() != row["sha256"]:
                conn.execute("UPDATE transfers SET state='failed' WHERE id=?", (row["id"],))
                conn.execute("UPDATE upload_log SET state='failed' WHERE token=?", (row["token"],))
                conn.execute("DELETE FROM chunks WHERE id=?", (row["id"],))
                return
            os.replace(temporary, target)
            directory_fd = os.open(self.files, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            now = self.clock()
            conn.execute("UPDATE transfers SET state='complete',expires=? WHERE id=?", (now + row["ttl"], row["id"]))
            conn.execute("UPDATE upload_log SET state='complete',completed=?,expires=? WHERE token=?",
                         (now, now + row["ttl"], row["token"]))
            conn.execute("DELETE FROM chunks WHERE id=?", (row["id"],))
        finally:
            temporary.unlink(missing_ok=True)

    def status(self, transfer_id):
        self.transfer_id(transfer_id)
        with self.connect() as conn:
            conn.execute("BEGIN")
            row = self.get(conn, transfer_id)
            result = self.result(row)
            if row["state"] == "uploading":
                received = {r[0] for r in conn.execute("SELECT seq FROM chunks WHERE id=?", (transfer_id,))}
                # Bounded page; clients requery after filling these missing chunks.
                result["missing"] = [i for i in range(row["total"]) if i not in received][:1024]
            return result

    def log_access(self, token, ip, agent, result):
        # Only tokens the service issued are recorded, so random probes cannot grow the log.
        with self.connect() as conn:
            conn.execute("INSERT INTO access_log SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM upload_log WHERE token=?)",
                         (token, self.clock(), ip, result, agent, token))

    def download(self, token, password, ip, agent):
        if not HASH_RE.fullmatch(token):
            raise APIError(404, "Download not found")

        def deny(status, result, message, headers=None):
            self.log_access(token, ip, agent, result)
            return APIError(status, message, headers)

        query = "SELECT * FROM transfers WHERE token=? AND state='complete'"
        with self.connect() as conn:
            row = conn.execute(query, (token,)).fetchone()
        if row is None:
            raise deny(404, "not_found", "Download not found")
        if row["expires"] <= self.clock():
            raise deny(410, "expired", "Download expired")
        # Check the password outside the write lock: scrypt is deliberately slow.
        if row["password"] is not None and not password_matches(row["password"], password):
            raise deny(401, "password_required" if password is None else "wrong_password", "Download password required",
                       {"WWW-Authenticate": 'Basic realm="Let\'s Escape download", charset="UTF-8"'})
        with self.connect() as conn:
            # Coordinate file open with cleanup; streaming can continue on the open descriptor.
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(query, (token,)).fetchone()
            if row is not None and row["expires"] > self.clock():
                return row, (self.files / row["id"]).open("rb")
        raise deny(410, "expired", "Download expired")

    def cleanup(self):
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = self.clock()
            for row in conn.execute("SELECT id, token FROM transfers WHERE expires<=?", (now,)).fetchall():
                (self.files / row[0]).unlink(missing_ok=True)
                conn.execute("DELETE FROM transfers WHERE id=?", (row[0],))
                conn.execute("UPDATE upload_log SET deleted=?, state=CASE state WHEN 'uploading' THEN 'abandoned' "
                             "ELSE state END WHERE token=?", (now, row[1]))
            # Recover file artifacts from interrupted, uncommitted finalization.
            completed = {r[0] for r in conn.execute("SELECT id FROM transfers WHERE state='complete'")}
            for file in self.files.iterdir():
                if file.name not in completed:
                    file.unlink()
        # Reuse free pages rather than keeping one database per transfer.
        with self.connect() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def audit_report(directory, out=sys.stdout):
    """Print every upload and download-link access. Opens the database read-only."""
    db = (Path(directory) / "uploads.sqlite3").resolve()
    if not db.exists():
        raise SystemExit(f"No upload database at {db}")
    conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
    utc = lambda t: "-" if t is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    try:
        print("UPLOADS", file=out)
        print("started_utc\tip\ttransfer_id\tname\tsize\tsha256\tpassword\tttl_hours\tstate"
              "\tcompleted_utc\texpires_utc\tdeleted_utc\tclicks\tdownloads", file=out)
        for r in conn.execute("""
                SELECT u.started, u.ip, u.transfer_id, u.name, u.size, u.sha256, u.password, u.ttl, u.state,
                       u.completed, u.expires, u.deleted, COUNT(a.token), COALESCE(SUM(a.result='downloaded'),0)
                FROM upload_log u LEFT JOIN access_log a ON a.token=u.token
                GROUP BY u.token ORDER BY u.started"""):
            print("\t".join(map(str, (utc(r[0]), r[1], r[2], r[3], r[4], r[5], "yes" if r[6] else "no",
                                      round(r[7] / 3600, 2), r[8], utc(r[9]), utc(r[10]), utc(r[11]), r[12], r[13]))),
                  file=out)
        print("\nACCESSES", file=out)
        print("at_utc\tip\tresult\ttransfer_id\tname\tuser_agent", file=out)
        for r in conn.execute("SELECT a.at, a.ip, a.result, u.transfer_id, u.name, a.user_agent FROM access_log a "
                              "JOIN upload_log u ON u.token=a.token ORDER BY a.at"):
            print("\t".join(map(str, (utc(r[0]), *r[1:]))), file=out)
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Never pass the raw URL (payloads and bearer capabilities) to access/error logs.
        pass

    def client_ip(self):
        # Only trust X-Real-IP when a reverse proxy we control always sets it.
        if self.server.trust_proxy and (forwarded := self.headers.get("X-Real-IP", "").strip()):
            return forwarded[:64]
        return self.client_address[0]

    def basic_password(self):
        scheme, _, value = self.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "basic":
            return None
        try:
            return base64.b64decode(value.strip(), validate=True).decode("utf-8").partition(":")[2]
        except (ValueError, UnicodeError):
            raise APIError(400, "Malformed Authorization header") from None

    def headers_common(self):
        self.send_header("Cache-Control", "no-store, private, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def respond(self, status, body, content_type="application/json; charset=utf-8", extra=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.headers_common()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        self.respond(code, {"error": "Request rejected"})

    def do_HEAD(self):
        self.respond(405, {"error": "Only GET is supported"}, extra={"Allow": "GET"})

    def do_GET(self):
        try:
            if len(self.path.encode()) > 2048:
                raise APIError(414, "URL exceeds the 2048-byte limit")
            url = urlsplit(self.path)
            store = self.server.store
            if url.path in {"/start", "/receive", "/status"}:
                required = {"/start": {"id", "name", "size", "sha256", "ttl_hours"},
                            "/receive": {"id", "seq", "total", "data"}, "/status": {"id"}}[url.path]
                query = parse_qs(url.query, keep_blank_values=True, max_num_fields=8, errors="strict")
                if set(query) != required or any(len(v) != 1 for v in query.values()):
                    raise APIError(400, "Missing, duplicate, or unknown query parameter")
                params = {k: v[0] for k, v in query.items()}
                # The optional download password travels in a Basic Authorization header, never the URL.
                result = store.status(params["id"]) if url.path == "/status" else (
                    store.start(params, self.client_ip(), self.basic_password()) if url.path == "/start"
                    else store.receive(params))
                self.respond(200, result)
            elif url.path.startswith("/download/"):
                token = url.path.removeprefix("/download/")
                ip, agent = self.client_ip(), self.headers.get("User-Agent", "")[:256]
                row, file = store.download(token, self.basic_password(), ip, agent)
                outcome = "interrupted"
                try:
                    with file:
                        self.send_response(200)
                        self.headers_common()
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Length", str(row["size"]))
                        self.send_header("Content-Disposition", "attachment; filename=\"download\"; filename*=UTF-8''" + quote(row["name"], safe=""))
                        self.send_header("X-File-SHA256", row["sha256"])
                        self.end_headers()
                        while chunk := file.read(64 * 1024):
                            self.wfile.write(chunk)
                        self.wfile.flush()
                    outcome = "downloaded"
                finally:
                    store.log_access(token, ip, agent, outcome)
            elif url.path == "/health":
                self.respond(200, {"status": "ok"})
            elif url.path == "/config":
                self.respond(200, {"chunk_size": store.chunk_size, "max_file_size": store.max_file,
                                   "min_ttl_hours": MIN_TTL / 3600, "max_ttl_hours": MAX_TTL / 3600})
            else:
                assets = {"/": ("web/index.html", "text/html; charset=utf-8"),
                          "/app.js": ("web/app.js", "text/javascript; charset=utf-8"),
                          "/style.css": ("web/style.css", "text/css; charset=utf-8"),
                          "/Upload-File.ps1": ("Upload-File.ps1", "text/plain; charset=utf-8"),
                          "/Upload-File.sh": ("Upload-File.sh", "text/plain; charset=utf-8")}
                if url.path not in assets:
                    raise APIError(404, "Not found")
                path, content_type = assets[url.path]
                extra = {"Content-Disposition": 'attachment; filename="' + Path(path).name + '"'} if url.path in {"/Upload-File.ps1", "/Upload-File.sh"} else None
                self.respond(200, (ROOT / path).read_bytes(), content_type, extra)
        except APIError as error:
            self.respond(error.status, {"error": error.message}, extra=error.headers)
        except (ValueError, UnicodeError):
            self.respond(400, {"error": "Malformed request"})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            logging.exception("Internal request failure (URL omitted)")
            self.close_connection = True
            self.respond(500, {"error": "Internal server error"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, store, trust_proxy=False):
        self.store, self.trust_proxy = store, trust_proxy
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, Handler)

    def get_request(self):
        socket, address = super().get_request()
        socket.settimeout(30)
        return socket, address

    def process_request(self, request, address):
        self.slots.acquire()
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def watch(argv):
    """Development mode: run the server in a child process and restart it when server.py changes."""
    source = ROOT / "server.py"
    command = [sys.executable, str(source), *[arg for arg in argv if arg != "--watch"]]

    def mtime():
        try:
            return source.stat().st_mtime_ns
        except OSError:  # Editors may briefly remove the file during an atomic save.
            return None

    while True:
        started = mtime()
        child = subprocess.Popen(command)
        try:
            while mtime() in (started, None):
                time.sleep(1)
        except KeyboardInterrupt:
            return
        finally:
            child.terminate()
            child.wait()
        logging.info("server.py changed; restarting")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(description="GET chunk upload service")
    parser.add_argument("command", nargs="?", choices=("serve", "audit"), default="serve",
                        help="serve (default) or audit: print upload and download history")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")),
                        help="listen port (default: $PORT or 8080)")
    parser.add_argument("--max-file-mb", type=float, default=float(os.environ.get("MAX_FILE_MB", "10")),
                        help="maximum file size in MiB (default: $MAX_FILE_MB or 10)")
    parser.add_argument("--trust-proxy", action="store_true", default=os.environ.get("TRUST_PROXY") == "1",
                        help="log the client IP from X-Real-IP set by your reverse proxy (default: $TRUST_PROXY=1)")
    parser.add_argument("--watch", action="store_true",
                        help="development: restart the server when server.py changes")
    args = parser.parse_args(argv)
    if args.max_file_mb <= 0:
        parser.error("--max-file-mb must be positive")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    data_dir = os.environ.get("DATA_DIR", "data")
    if args.command == "audit":
        audit_report(data_dir)
        return
    if args.watch:
        watch(argv)
        return
    store = Store(data_dir,
                  chunk_size=int(os.environ.get("CHUNK_SIZE", "1024")),
                  max_file=int(args.max_file_mb * 1024**2),
                  max_storage=int(os.environ.get("MAX_STORAGE_BYTES", str(1024**3))),
                  max_transfers=int(os.environ.get("MAX_TRANSFERS", "100")))
    stop = threading.Event()

    def janitor():
        while not stop.wait(60):
            try:
                store.cleanup()
            except Exception:
                logging.exception("Cleanup failed")

    threading.Thread(target=janitor, daemon=True).start()
    server = Server((os.environ.get("HOST", "127.0.0.1"), args.port), store, args.trust_proxy)
    logging.info("Upload service listening on %s:%s", *server.server_address)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()


if __name__ == "__main__":
    main()
