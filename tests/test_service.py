import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode

from server import MAX_TTL, MIN_TTL, UPLOAD_WINDOW, Server, Store, audit_report

HOUR = 60 * 60


def basic(password):
    return {'Authorization': 'Basic ' + base64.b64encode((':' + password).encode()).decode()}


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1700000000
        self.store = Store(self.temp.name, clock=lambda: self.now, max_file=8192, max_storage=16384)
        self.server = Server(('127.0.0.1', 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, path, params=None, method='GET', headers=None):
        if params is not None:
            path += '?' + urlencode(params)
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            response = conn.getresponse()
            body = response.read()
            headers = dict(response.getheaders())
            if headers.get('Content-Type', '').startswith('application/json') and body:
                body = json.loads(body)
            return response.status, body, headers
        finally:
            conn.close()

    def start(self, data, name='example.bin', digest=None, transfer_id=None, ttl_hours='1', password=None):
        transfer_id = transfer_id or secrets.token_hex(16)
        params = dict(id=transfer_id, name=name, size=len(data), sha256=digest or hashlib.sha256(data).hexdigest(),
                      ttl_hours=ttl_hours)
        status, body, _ = self.request('/start', params, headers=password and basic(password))
        self.assertEqual(status, 200, body)
        return body, params

    def chunk(self, transfer, data, seq):
        chunk = data[seq * transfer['chunk_size']:(seq + 1) * transfer['chunk_size']]
        return dict(id=transfer['id'], seq=seq, total=transfer['total'],
                    data=base64.urlsafe_b64encode(chunk).decode().rstrip('='))

    def upload(self, data, **kwargs):
        transfer, _ = self.start(data, **kwargs)
        for seq in range(transfer['total']):
            status, result, _ = self.request('/receive', self.chunk(transfer, data, seq))
            self.assertEqual(status, 200, result)
        return result

    def test_out_of_order_retry_conflict_and_download(self):
        data = bytes(range(256)) * 13
        transfer, params = self.start(data, name='résumé "2026".bin')
        self.assertNotIn('download_url', transfer)
        chunk = self.chunk(transfer, data, 2)
        self.assertEqual(self.request('/receive', chunk)[0], 200)
        retry = self.request('/receive', chunk)[1]
        self.assertTrue(retry['duplicate'])
        self.assertEqual(retry['received'], 1)
        wrong = {**chunk, 'data': base64.urlsafe_b64encode(b'x' * 1024).decode().rstrip('=')}
        self.assertEqual(self.request('/receive', wrong)[0], 409)
        state = self.request('/status', {'id': transfer['id']})[1]
        self.assertEqual(state['missing'], [0, 1, 3])
        for seq in [3, 1, 0]:
            status, result, _ = self.request('/receive', self.chunk(transfer, data, seq))
            self.assertEqual(status, 200)
        self.assertEqual(result['state'], 'complete')
        self.assertEqual(result['expires'], self.now + HOUR)
        self.assertNotIn(transfer['id'], result['download_url'])
        status, downloaded, headers = self.request(result['download_url'])
        self.assertEqual((status, downloaded), (200, data))
        self.assertIn('no-store', headers['Cache-Control'])
        self.assertEqual(headers['X-File-SHA256'], hashlib.sha256(data).hexdigest())
        self.assertIn('filename*=UTF-8', headers['Content-Disposition'])
        # Lost final acknowledgment: safe retry must not renew expiry.
        self.now += 120
        repeat = self.request('/receive', self.chunk(transfer, data, 0))[1]
        self.assertTrue(repeat['duplicate'])
        self.assertEqual(repeat['expires'], result['expires'])
        self.assertEqual(self.request('/receive', wrong)[0], 409)
        self.assertEqual(self.request('/start', params)[1]['download_url'], result['download_url'])

    def test_empty_file(self):
        result = self.upload(b'')
        self.assertEqual(result['total'], 1)
        self.assertEqual(self.request(result['download_url'])[1], b'')

    def test_checksum_failure_never_issues_download(self):
        data = b'wrong checksum'
        transfer, _ = self.start(data, digest='0' * 64)
        params = self.chunk(transfer, data, 0)
        self.assertEqual(self.request('/receive', params)[0], 422)
        status = self.request('/status', {'id': transfer['id']})[1]
        self.assertEqual(status['state'], 'failed')
        self.assertNotIn('download_url', status)
        self.assertEqual(self.request('/receive', params)[0], 422)
        with self.store.connect() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM chunks').fetchone()[0], 0)
            self.assertEqual(conn.execute('SELECT state FROM upload_log').fetchone()[0], 'failed')

    def test_strict_input_url_limit_and_head_has_no_side_effects(self):
        data = b'x' * 1024
        transfer, params = self.start(data)
        chunk = self.chunk(transfer, data, 0)
        variants = [{**chunk, 'seq': -1}, {**chunk, 'seq': 1}, {**chunk, 'total': 2},
                    {**chunk, 'data': 'a'}, {**chunk, 'data': '===='},
                    {**chunk, 'data': 'eA'}, {**chunk, 'data': 'AB'},
                    {**chunk, 'data': 'x' * 1400}, {**chunk, 'id': '../escape'}]
        for bad in variants:
            with self.subTest(bad=bad):
                self.assertEqual(self.request('/receive', bad)[0], 400)
        self.assertEqual(self.request('/receive?' + urlencode(chunk) + '&seq=0')[0], 400)
        self.assertEqual(self.request('/receive', {**chunk, 'other': 'x'})[0], 400)
        self.assertEqual(self.request('/status?' + 'x' * 2048)[0], 414)
        self.assertEqual(self.request('/receive', chunk, method='HEAD')[0], 405)
        self.assertEqual(self.request('/status', {'id': transfer['id']})[1]['received'], 0)
        self.assertEqual(self.request('/receive', chunk, method='POST')[0], 501)
        self.assertEqual(self.request('/start', {**params, 'name': '../file'})[0], 400)
        self.assertEqual(self.request('/start', {**params, 'size': 99999})[0], 413)
        self.assertEqual(self.request('/start', {**params, 'name': 'different'})[0], 409)

    def test_persistence_and_expiry_from_completion(self):
        data = os.urandom(2048)
        transfer, _ = self.start(data)
        self.request('/receive', self.chunk(transfer, data, 0))
        self.server.store = Store(self.temp.name, clock=lambda: self.now)
        self.assertEqual(self.request('/status', {'id': transfer['id']})[1]['missing'], [1])
        self.assertEqual(transfer['expires'], self.now + UPLOAD_WINDOW)
        self.now += UPLOAD_WINDOW - 10
        result = self.request('/receive', self.chunk(transfer, data, 1))[1]
        self.assertEqual(result['expires'], self.now + HOUR)
        self.server.store = Store(self.temp.name, clock=lambda: self.now)
        self.assertEqual(self.request(result['download_url'])[1], data)
        self.now += HOUR
        self.assertEqual(self.request(result['download_url'])[0], 410)
        self.assertEqual(self.request('/status', {'id': transfer['id']})[0], 410)
        self.server.store.cleanup()
        self.assertEqual(list(self.store.files.iterdir()), [])
        self.assertEqual(self.request(result['download_url'])[0], 404)

    def test_abandoned_transfers_expire_and_free_capacity(self):
        transfer, _ = self.start(b'pending')
        self.server.store.max_transfers = 1
        other = dict(id=secrets.token_hex(16), name='other', size=0, sha256=hashlib.sha256(b'').hexdigest(), ttl_hours='1')
        self.assertEqual(self.request('/start', other)[0], 503)
        self.now += UPLOAD_WINDOW
        self.assertEqual(self.request('/receive', self.chunk(transfer, b'pending', 0))[0], 410)
        self.server.store.cleanup()
        self.assertEqual(self.request('/start', other)[0], 200)
        with self.store.connect() as conn:
            states = [r[0] for r in conn.execute('SELECT state FROM upload_log ORDER BY started, rowid')]
        self.assertEqual(states, ['abandoned', 'uploading'])

    def test_storage_reservations_and_orphan_cleanup(self):
        self.server.store.max_storage = 1024
        self.start(b'x' * 1024)
        params = dict(id=secrets.token_hex(16), name='other', size=1, sha256=hashlib.sha256(b'x').hexdigest(), ttl_hours='1')
        self.assertEqual(self.request('/start', params)[0], 503)
        (self.store.files / 'orphan.tmp').write_bytes(b'incomplete')
        self.store.cleanup()
        self.assertFalse((self.store.files / 'orphan.tmp').exists())

    def test_concurrent_duplicates(self):
        data = os.urandom(8192)
        transfer, _ = self.start(data)
        chunks = [self.chunk(transfer, data, i) for i in range(8)] * 2
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda p: self.request('/receive', p), chunks))
        self.assertTrue(all(r[0] == 200 for r in results), results)
        result = self.request('/status', {'id': transfer['id']})[1]
        self.assertEqual(result['received'], 8)
        self.assertEqual(self.request(result['download_url'])[1], data)

    def test_smaller_chunks_and_bounded_missing_page(self):
        self.server.store.chunk_size = 64
        self.server.store.max_file = 100000
        self.server.store.max_storage = 100000
        data = b'x' * (64 * 1025)
        transfer, _ = self.start(data)
        result = self.request('/status', {'id': transfer['id']})[1]
        self.assertEqual(len(result['missing']), 1024)
        self.assertEqual(transfer['total'], 1025)
        self.assertEqual(self.request('/receive', self.chunk(transfer, data, 0))[0], 200)

    def test_assets_and_security_headers(self):
        for asset in ['/', '/app.js', '/style.css', '/Upload-File.ps1', '/Upload-File.sh', '/health', '/config']:
            with self.subTest(asset=asset):
                status, _, headers = self.request(asset)
                self.assertEqual(status, 200)
                self.assertIn('no-store', headers['Cache-Control'])
                self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
                self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
                if asset.endswith(('.ps1', '.sh')):
                    self.assertIn(asset[1:], headers['Content-Disposition'])
        self.assertEqual(self.request('/../server.py')[0], 404)
        self.assertEqual(self.request('/download/' + 'x' * 64)[0], 404)
        config = self.request('/config')[1]
        self.assertEqual((config['min_ttl_hours'], config['max_ttl_hours']), (MIN_TTL / HOUR, MAX_TTL / HOUR))

    def test_default_file_limit_is_10_mib(self):
        self.assertEqual(Store(self.temp.name).max_file, 10 * 1024**2)

    def test_uploader_chooses_expiry(self):
        transfer, params = self.start(b'x', ttl_hours='0.1')
        self.assertEqual(transfer['ttl_hours'], 0.1)
        result = self.request('/receive', self.chunk(transfer, b'x', 0))[1]
        self.assertEqual(result['expires'], self.now + 6 * 60)
        self.assertEqual(self.request('/start', {**params, 'ttl_hours': '2'})[0], 409)
        for bad in ('0.09', '24.01', '25', '1.234', '01', 'abc', '', '1e1'):
            with self.subTest(ttl_hours=bad):
                self.assertEqual(self.request('/start', {**params, 'id': secrets.token_hex(16), 'ttl_hours': bad})[0], 400)
        self.assertEqual(self.start(b'', ttl_hours='24')[0]['ttl_hours'], 24)
        no_ttl = {k: v for k, v in params.items() if k != 'ttl_hours'}
        self.assertEqual(self.request('/start', no_ttl)[0], 400)

    def test_download_password(self):
        data = b'secret bytes'
        transfer, params = self.start(data, password='pässwörd')
        self.assertTrue(transfer['password_protected'])
        # Resuming must present the same password.
        self.assertEqual(self.request('/start', params)[0], 409)
        self.assertEqual(self.request('/start', params, headers=basic('other'))[0], 409)
        self.assertEqual(self.request('/start', params, headers=basic('pässwörd'))[0], 200)
        url = self.request('/receive', self.chunk(transfer, data, 0))[1]['download_url']
        status, _, headers = self.request(url)
        self.assertEqual(status, 401)
        self.assertIn('Basic', headers['WWW-Authenticate'])
        self.assertEqual(self.request(url, headers=basic('wrong'))[0], 401)
        self.assertEqual(self.request(url, headers={'Authorization': 'Basic !!!'})[0], 400)
        self.assertEqual(self.request(url, headers=basic('pässwörd'))[1], data)
        with self.store.connect() as conn:
            stored = conn.execute('SELECT password FROM transfers').fetchone()[0]
        self.assertNotIn('pässwörd', stored)
        fresh = {**params, 'id': secrets.token_hex(16)}
        self.assertEqual(self.request('/start', fresh, headers=basic('x' * 129))[0], 400)
        self.assertEqual(self.request('/start', fresh, headers=basic(''))[0], 400)

    def test_audit_log_outlives_deleted_files(self):
        self.server.trust_proxy = True
        data = b'audited'
        transfer, _ = self.start(data, password='pw')
        url = self.request('/receive', self.chunk(transfer, data, 0))[1]['download_url']
        self.request(url, headers={'X-Real-IP': '203.0.113.7', 'User-Agent': 'probe'})
        self.request(url, headers={'X-Real-IP': '203.0.113.7', **basic('nope')})
        self.request(url, headers={'X-Real-IP': '198.51.100.2', **basic('pw')})
        self.request(url, headers={'X-Real-IP': '198.51.100.2', **basic('pw')})
        self.request('/download/' + secrets.token_hex(32))  # Unknown tokens are not logged.
        self.now += HOUR
        self.request(url, headers=basic('pw'))
        self.store.cleanup()
        self.assertEqual(list(self.store.files.iterdir()), [])
        self.assertEqual(self.request(url, headers=basic('pw'))[0], 404)
        with self.store.connect() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM transfers').fetchone()[0], 0)
            upload = conn.execute('SELECT * FROM upload_log').fetchone()
            accesses = [tuple(r) for r in conn.execute('SELECT ip, result, user_agent FROM access_log ORDER BY rowid')]
        self.assertEqual((upload['transfer_id'], upload['ip'], upload['name'], upload['size'], upload['state'], upload['password']),
                         (transfer['id'], '127.0.0.1', 'example.bin', len(data), 'complete', 1))
        self.assertEqual(upload['deleted'], self.now)
        self.assertEqual(accesses, [
            ('203.0.113.7', 'password_required', 'probe'), ('203.0.113.7', 'wrong_password', ''),
            ('198.51.100.2', 'downloaded', ''), ('198.51.100.2', 'downloaded', ''),
            ('127.0.0.1', 'expired', ''), ('127.0.0.1', 'not_found', '')])
        report = io.StringIO()
        audit_report(self.temp.name, report)
        line = next(l for l in report.getvalue().splitlines() if l.split('\t')[2:3] == [transfer['id']])
        self.assertTrue(line.endswith('\t6\t2'), line)
        self.assertIn('203.0.113.7\twrong_password', report.getvalue())

    def test_client_ip_ignores_proxy_header_unless_trusted(self):
        self.request('/start', dict(id=secrets.token_hex(16), name='a', size=0,
                                    sha256=hashlib.sha256(b'').hexdigest(), ttl_hours='1'),
                     headers={'X-Real-IP': '203.0.113.9'})
        with self.store.connect() as conn:
            self.assertEqual(conn.execute('SELECT ip FROM upload_log').fetchone()[0], '127.0.0.1')

    def test_watch_restarts_server_when_source_changes(self):
        work = Path(self.temp.name) / 'watched'
        work.mkdir()
        source = work / 'server.py'
        shutil.copy(Path(__file__).resolve().parents[1] / 'server.py', source)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        env = {**os.environ, 'DATA_DIR': str(work / 'data')}
        process = subprocess.Popen([sys.executable, str(source), '--watch', '--port', str(port)], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def health():
            deadline = time.time() + 15
            while time.time() < deadline:
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                try:
                    conn.request('GET', '/health')
                    return json.loads(conn.getresponse().read())['status']
                except OSError:
                    time.sleep(0.2)
                finally:
                    conn.close()
            self.fail('watched server did not respond')

        try:
            self.assertEqual(health(), 'ok')
            source.write_text(source.read_text().replace('{"status": "ok"}', '{"status": "reloaded"}'))
            deadline = time.time() + 15
            while health() != 'reloaded':
                self.assertLess(time.time(), deadline)
                time.sleep(0.2)
        finally:
            process.terminate()
            process.wait(timeout=10)

    def shell_upload(self, source, transfer_id, *, environment=None, attempts=1, extra=(), stdin=None, password=None):
        script = Path(__file__).resolve().parents[1] / 'Upload-File.sh'
        url = 'http://%s:%s' % self.server.server_address
        env = dict(os.environ)
        env['NO_PROXY'] = env.get('NO_PROXY', '') + ',127.0.0.1,localhost'
        if environment:
            env.update(environment)
        process = subprocess.run([shutil.which('dash') or 'sh', str(script), '--server-url', url,
                                  '--path', str(source), '--transfer-id', transfer_id, '--expires-hours', '1',
                                  '--max-attempts', str(attempts), *extra], capture_output=True, text=True,
                                 env=env, timeout=45, input=stdin)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result['TransferId'], transfer_id)
        self.assertEqual(result['SHA256'], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(result['PasswordProtected'], password is not None)
        self.assertEqual(self.request(urlsplit_path(result['DownloadUrl']), headers=password and basic(password))[1],
                         source.read_bytes())
        return process, result

    @unittest.skipUnless(all(shutil.which(t) for t in ('sh', 'curl', 'jq', 'base64')), 'Shell client dependencies are not installed')
    def test_posix_shell_binary_resume_and_completed_retry(self):
        data = bytes(range(256)) * 19 + b'\x00\xffend'
        source = Path(self.temp.name) / "résumé 'file' $;.bin"
        source.write_bytes(data)
        transfer, _ = self.start(data, name=source.name)
        self.request('/receive', self.chunk(transfer, data, 2))
        self.shell_upload(source, transfer['id'])
        self.shell_upload(source, transfer['id'])

    @unittest.skipUnless(all(shutil.which(t) for t in ('sh', 'curl', 'jq', 'base64')), 'Shell client dependencies are not installed')
    def test_posix_shell_empty_file_generated_id_and_expiry_validation(self):
        source = Path(self.temp.name) / 'empty.bin'
        source.write_bytes(b'')
        self.shell_upload(source, secrets.token_hex(16))
        script = Path(__file__).resolve().parents[1] / 'Upload-File.sh'
        env = {**os.environ, 'NO_PROXY': '127.0.0.1,localhost'}
        url = 'http://%s:%s' % self.server.server_address
        process = subprocess.run(['sh', str(script), '--server-url', url, '--path', str(source), '--expires-hours', '0.5'],
                                 env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertRegex(json.loads(process.stdout)['TransferId'], r'^[a-f0-9]{32}$')
        missing = subprocess.run(['sh', str(script), '--server-url', url, '--path', str(source)],
                                 env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(missing.returncode, 0)
        for bad in ('0', '25', '1.234', 'x'):
            with self.subTest(expires_hours=bad):
                invalid = subprocess.run(['sh', str(script), '--server-url', url, '--path', str(source),
                                          '--expires-hours', bad], env=env, capture_output=True, text=True, timeout=30)
                self.assertIn('--expires-hours must be', invalid.stderr)

    @unittest.skipUnless(all(shutil.which(t) for t in ('sh', 'curl', 'jq', 'base64')), 'Shell client dependencies are not installed')
    def test_posix_shell_download_password_from_stdin(self):
        source = Path(self.temp.name) / 'protected.bin'
        source.write_bytes(os.urandom(300))
        process, _ = self.shell_upload(source, secrets.token_hex(16), extra=['--ask-password'],
                                       stdin='pä ss:word\n', password='pä ss:word')
        self.assertNotIn('pä ss', process.stderr + process.stdout)

    @unittest.skipUnless(all(shutil.which(t) for t in ('sh', 'curl', 'jq', 'base64')), 'Shell client dependencies are not installed')
    def test_posix_shell_retries_server_error_and_lost_ack(self):
        source = Path(self.temp.name) / 'retry.bin'
        source.write_bytes(os.urandom(137))
        wrappers = Path(self.temp.name) / 'bin'
        wrappers.mkdir()
        wrapper = wrappers / 'curl'
        wrapper.write_text('''#!/bin/sh
for arg in "$@"; do
  case "$arg" in */receive)
    if [ ! -f "$RETRY_STATE" ]; then
      printf '1' > "$RETRY_STATE"
      printf '503'
      exit 0
    elif [ "$(cat "$RETRY_STATE")" = 1 ]; then
      printf '2' > "$RETRY_STATE"
      "$REAL_CURL" "$@"
      exit 7
    fi ;;
  esac
done
exec "$REAL_CURL" "$@"
''')
        wrapper.chmod(0o700)
        state_file = Path(self.temp.name) / 'retry-state'
        process, _ = self.shell_upload(source, secrets.token_hex(16), attempts=3, environment={
            'PATH': str(wrappers) + os.pathsep + os.environ['PATH'],
            'REAL_CURL': shutil.which('curl'), 'RETRY_STATE': str(state_file)})
        self.assertEqual(state_file.read_text(), '2')
        self.assertNotIn('/receive?', process.stderr)

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell is not installed')
    def test_powershell_client_resume_and_password(self):
        data = os.urandom(5007)
        source = Path(self.temp.name) / "résumé 'file'.bin"
        source.write_bytes(data)
        output = Path(self.temp.name) / 'result.json'
        script = Path(__file__).resolve().parents[1] / 'Upload-File.ps1'
        transfer_id = secrets.token_hex(16)
        url = 'http://%s:%s' % self.server.server_address
        password = "pä'ss"
        def ps_quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        command = ('& ' + ps_quote(script) + ' -ServerUrl ' + ps_quote(url) + ' -Path ' + ps_quote(source)
                   + ' -TransferId ' + ps_quote(transfer_id) + ' -ExpiresHours 1.5'
                   + ' -DownloadPassword (ConvertTo-SecureString ' + ps_quote(password) + ' -AsPlainText -Force)'
                   + ' | ConvertTo-Json | Set-Content -LiteralPath ' + ps_quote(output))
        # Pre-upload one chunk to exercise resume, then rerun the fully completed transfer.
        transfer, _ = self.start(data, name=source.name, transfer_id=transfer_id, ttl_hours='1.5', password=password)
        self.request('/receive', self.chunk(transfer, data, 2))
        for _ in range(2):
            process = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command',
                                      "$ErrorActionPreference='Stop'; " + command], capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(output.read_text(encoding='utf-8-sig'))
            self.assertEqual(result['SHA256'], hashlib.sha256(data).hexdigest())
            self.assertTrue(result['PasswordProtected'])
            self.assertEqual(self.request(urlsplit_path(result['DownloadUrl']))[0], 401)
            self.assertEqual(self.request(urlsplit_path(result['DownloadUrl']), headers=basic(password))[1], data)


def urlsplit_path(url):
    from urllib.parse import urlsplit
    return urlsplit(url).path


if __name__ == '__main__':
    unittest.main()
