import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import urlencode

from server import Server, Store, TTL


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

    def request(self, path, params=None, method='GET'):
        if params is not None:
            path += '?' + urlencode(params)
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            conn.request(method, path)
            response = conn.getresponse()
            body = response.read()
            headers = dict(response.getheaders())
            if headers.get('Content-Type', '').startswith('application/json') and body:
                body = json.loads(body)
            return response.status, body, headers
        finally:
            conn.close()

    def start(self, data, name='example.bin', digest=None, transfer_id=None):
        transfer_id = transfer_id or secrets.token_hex(16)
        params = dict(id=transfer_id, name=name, size=len(data), sha256=digest or hashlib.sha256(data).hexdigest())
        status, body, _ = self.request('/start', params)
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
        self.assertEqual(result['expires'], self.now + TTL)
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
        self.now += TTL - 10
        result = self.request('/receive', self.chunk(transfer, data, 1))[1]
        self.assertEqual(result['expires'], self.now + TTL)
        self.server.store = Store(self.temp.name, clock=lambda: self.now)
        self.assertEqual(self.request(result['download_url'])[1], data)
        self.now += TTL
        self.assertEqual(self.request(result['download_url'])[0], 410)
        self.assertEqual(self.request('/status', {'id': transfer['id']})[0], 410)
        self.server.store.cleanup()
        self.assertEqual(list(self.store.files.iterdir()), [])
        self.assertEqual(self.request(result['download_url'])[0], 404)

    def test_abandoned_transfers_expire_and_free_capacity(self):
        transfer, _ = self.start(b'pending')
        self.server.store.max_transfers = 1
        other = dict(id=secrets.token_hex(16), name='other', size=0, sha256=hashlib.sha256(b'').hexdigest())
        self.assertEqual(self.request('/start', other)[0], 503)
        self.now += TTL
        self.assertEqual(self.request('/receive', self.chunk(transfer, b'pending', 0))[0], 410)
        self.server.store.cleanup()
        self.assertEqual(self.request('/start', other)[0], 200)

    def test_storage_reservations_and_orphan_cleanup(self):
        self.server.store.max_storage = 1024
        self.start(b'x' * 1024)
        params = dict(id=secrets.token_hex(16), name='other', size=1, sha256=hashlib.sha256(b'x').hexdigest())
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
        for asset in ['/', '/app.js', '/style.css', '/Upload-File.ps1', '/health', '/config']:
            with self.subTest(asset=asset):
                status, _, headers = self.request(asset)
                self.assertEqual(status, 200)
                self.assertIn('no-store', headers['Cache-Control'])
                self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
                self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(self.request('/../server.py')[0], 404)
        self.assertEqual(self.request('/download/' + 'x' * 64)[0], 404)

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell is not installed')
    def test_powershell_client_and_resume(self):
        data = os.urandom(5007)
        source = Path(self.temp.name) / "résumé 'file'.bin"
        source.write_bytes(data)
        output = Path(self.temp.name) / 'result.json'
        script = Path(__file__).resolve().parents[1] / 'Upload-File.ps1'
        transfer_id = secrets.token_hex(16)
        url = 'http://%s:%s' % self.server.server_address
        def ps_quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        command = ('& ' + ps_quote(script) + ' -ServerUrl ' + ps_quote(url) + ' -Path ' + ps_quote(source)
                   + ' -TransferId ' + ps_quote(transfer_id) + ' | ConvertTo-Json | Set-Content -LiteralPath ' + ps_quote(output))
        # Pre-upload one chunk to exercise resume, then rerun the fully completed transfer.
        transfer, _ = self.start(data, name=source.name, transfer_id=transfer_id)
        self.request('/receive', self.chunk(transfer, data, 2))
        for _ in range(2):
            process = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command',
                                      "$ErrorActionPreference='Stop'; " + command], capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(output.read_text(encoding='utf-8-sig'))
            self.assertEqual(result['SHA256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(self.request(urlsplit_path(result['DownloadUrl']))[1], data)


def urlsplit_path(url):
    from urllib.parse import urlsplit
    return urlsplit(url).path


if __name__ == '__main__':
    unittest.main()
