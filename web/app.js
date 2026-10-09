'use strict';
const $ = (id) => document.getElementById(id);
const baseUrl = new URL('.', window.location.href).href.replace(/\/$/, '');
let transferId;
let seen = false;
let terminal = false;
let polling = false;
let uploading = false;
let maxFileSize = Infinity;
let token = ''; // The signed-in account's script access token, shown for the CLI fallback.
let transferReady; // Settles once setTransfer has chosen the current ID (it may wait for the word list).
function signInAgain() { window.location.assign('/login'); }
const ID_PATTERN = /^(?:[a-f0-9]{32}|[a-z]{3,5}(?:-[a-z]{3,5}){3})$/;
// Transfer IDs are four words from the server's list; fall back to 128 random bits if it is unavailable.
const words = fetch(`${baseUrl}/words.txt`, { cache: 'no-store' })
  .then((r) => (r.ok ? r.text() : Promise.reject(new Error('Word list unavailable'))))
  .then((text) => text.split(/\s+/).filter(Boolean))
  .catch(() => null);

// Accept IDs typed by hand: any case, with spaces or other separators between the words.
function normalizeId(value) {
  return (value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}
async function newId() {
  const list = await words;
  if (!list || list.length < 2) return crypto.randomUUID().replaceAll('-', '');
  // Rejection sampling keeps every word equally likely.
  const limit = 65536 - (65536 % list.length);
  const value = new Uint16Array(1);
  const picked = [];
  while (picked.length < 4) {
    crypto.getRandomValues(value);
    if (value[0] < limit) picked.push(list[value[0] % list.length]);
  }
  return picked.join('-');
}

async function setTransfer() {
  const candidate = normalizeId(new URLSearchParams(window.location.hash.slice(1)).get('id'));
  transferId = ID_PATTERN.test(candidate) ? candidate : await newId();
  history.replaceState(null, '', `#id=${transferId}`);
  seen = false;
  terminal = false;
  $('transfer-id').textContent = transferId;
  $('result').hidden = true;
  $('progress').value = 0;
  $('status').textContent = 'Waiting for an upload';
  $('status-dot').className = 'dot';
  $('detail').textContent = 'Keep this page open while the file uploads. Interrupted uploads can resume with the same transfer ID.';
  $('upload-error').hidden = true;
  command();
}

function psQuote(value) { return "'" + value.replaceAll("'", "''") + "'"; }
function shQuote(value) { return "'" + value.replaceAll("'", "'\"'\"'") + "'"; }
function expiresHours() {
  // Match the server: 0.1 to 24 hours with at most two decimals.
  const hours = Math.round(Number($('expires-hours').value) * 100) / 100;
  return Number.isFinite(hours) ? Math.min(24, Math.max(0.1, hours)) : 1;
}
function command() {
  const hours = expiresHours();
  const ask = $('ask-password').checked;
  const filePath = $('file-path').value || 'C:\\path\\to\\your-file.zip';
  $('command').value = `.\\Upload-File.ps1 -ServerUrl ${psQuote(baseUrl)} -Path ${psQuote(filePath)} -TransferId ${psQuote(transferId)} -ExpiresHours ${hours}`
    + (ask ? " -DownloadPassword (Read-Host 'Download password' -AsSecureString)" : '') + ' -OpenResult';
  const shellPath = $('file-path').value || '/path/to/your-file.zip';
  $('shell-command').value = `sh ./Upload-File.sh --server-url ${shQuote(baseUrl)} --path ${shQuote(shellPath)} --transfer-id ${shQuote(transferId)} --expires-hours ${hours}`
    + (ask ? ' --ask-password' : '') + ' --open-result';
}
function duration(hours) {
  const minutes = Math.round(hours * 60);
  return minutes < 60 ? `${minutes} minutes` : `${+(minutes / 60).toFixed(2)} hour${minutes === 60 ? '' : 's'}`;
}
async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const previous = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = previous; }, 1500);
  } catch {
    button.textContent = 'Select the text to copy';
  }
}
function showError(message) {
  $('status').textContent = message;
  $('status-dot').className = 'dot error';
  $('result').hidden = true;
}
class UploadError extends Error {
  // fallback: a script could succeed where the browser could not (network, proxy, or HTTPS problems).
  constructor(message, fallback = false) { super(message); this.fallback = fallback; }
}
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
// Same protocol and retry policy as the scripts: retry network errors, 408, 429, and 5xx.
async function call(path, params, headers = {}) {
  const url = `${baseUrl}${path}?${new URLSearchParams(params)}`;
  for (let attempt = 1; ; attempt++) {
    let response = null;
    try {
      response = await fetch(url, { cache: 'no-store', referrerPolicy: 'no-referrer', headers });
    } catch { /* Network failure: retry below. */ }
    if (response?.ok) return response.json();
    if (response && response.status === 401) { signInAgain(); throw new UploadError('Your session has expired — sign in again.'); }
    const retry = !response || response.status === 408 || response.status === 429 || response.status >= 500;
    if (!retry || attempt === 5) {
      if (!response) throw new UploadError('The browser could not reach the server.', true);
      const reason = (await response.json().catch(() => ({}))).error || `HTTP ${response.status}`;
      throw new UploadError(`The server did not accept the upload (${reason}).`, retry);
    }
    await sleep(Math.min(8000, 500 * 2 ** (attempt - 1)) + Math.random() * 250);
  }
}
async function browserUpload() {
  const file = $('file').files[0];
  const id = transferId;
  const guard = () => { if (id !== transferId) throw new UploadError('Upload stopped: you started a new transfer.'); };
  if (!file) throw new UploadError('Choose a file first.');
  if (file.size > maxFileSize) throw new UploadError(`The file exceeds the ${(maxFileSize / 1024 / 1024).toLocaleString()} MiB size limit.`);
  const headers = {};
  if ($('ask-password').checked) {
    const password = $('password').value;
    if (![...password].length || [...password].length > 128) throw new UploadError('Enter a download password of 1 to 128 characters.');
    if (password !== $('password-confirm').value) throw new UploadError('The passwords do not match.');
    headers.Authorization = 'Basic ' + btoa(String.fromCharCode(...new TextEncoder().encode(':' + password)));
  }
  if (!crypto.subtle) throw new UploadError('This browser can only calculate SHA-256 over HTTPS.', true);
  $('status').textContent = 'Reading and hashing your file';
  $('status-dot').className = 'dot active';
  const bytes = new Uint8Array(await file.arrayBuffer());
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map((b) => b.toString(16).padStart(2, '0')).join('');
  guard();
  const transfer = await call('/start', { id, name: file.name, size: file.size, sha256: digest, ttl_hours: expiresHours() }, headers);
  const { chunk_size: chunkSize, total } = transfer;
  let state = transfer.state;
  while (state === 'uploading') {
    guard();
    const status = await call('/status', { id });
    state = status.state;
    if (state !== 'uploading') break;
    const missing = status.missing;
    let next = 0;
    let stopped = false;
    // A few requests in flight hide latency without tripping proxy rate limits.
    const worker = async () => {
      while (next < missing.length && !stopped) {
        guard();
        const seq = missing[next++];
        const ack = await call('/receive', { id, seq, total, data: base64url(bytes.subarray(seq * chunkSize, (seq + 1) * chunkSize)) });
        if (id === transferId) $('progress').value = 100 * ack.received / total;
        state = ack.state;
      }
    };
    await Promise.all(Array.from({ length: 4 }, () => worker().catch((error) => { stopped = true; throw error; })));
  }
  if (state === 'failed') throw new UploadError('SHA-256 verification failed. Start a new transfer and try again.');
  poll();
}
function setUploading(active) {
  uploading = active;
  for (const id of ['file', 'expires-hours', 'ask-password', 'password', 'password-confirm', 'upload']) $(id).disabled = active;
}
async function startBrowserUpload() {
  if (uploading) return;
  $('upload-error').hidden = true;
  setUploading(true);
  await transferReady;
  const id = transferId;
  try {
    await browserUpload();
  } catch (error) {
    if (id !== transferId) return; // The user started a new transfer; leave its fresh status alone.
    showError('Upload did not finish');
    const known = error instanceof UploadError;
    const fallback = !known || error.fallback;
    $('upload-error').textContent = (known ? error.message : 'The browser could not upload this file.')
      + (fallback ? ' You can finish with a script below; it resumes the same transfer.' : '');
    $('upload-error').hidden = false;
    if (fallback) $('scripts').open = true;
  } finally {
    setUploading(false);
  }
}

async function poll() {
  if (polling || terminal || !transferId) return;
  polling = true;
  const requestedId = transferId;
  try {
    const response = await fetch(`${baseUrl}/status?id=${requestedId}`, { cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (requestedId !== transferId) return;
    if (response.status === 401) { signInAgain(); return; }
    if (response.status === 404 && !seen) return;
    if (response.status === 404 || response.status === 410) {
      showError('This transfer has expired');
      $('detail').textContent = 'Start a new transfer to upload the file again.';
      terminal = true;
      return;
    }
    if (!response.ok) throw new Error('Status request failed');
    const upload = await response.json();
    if (requestedId !== transferId) return;
    seen = true;
    $('progress').value = 100 * upload.received / upload.total;
    if (upload.state === 'failed') {
      showError('File verification failed');
      $('detail').textContent = 'The SHA-256 checksum did not match. Start a new transfer and upload again.';
      terminal = true;
    } else if (upload.state === 'complete') {
      const expiration = new Date(upload.expires * 1000);
      if (Date.now() >= expiration.getTime()) {
        showError('This download has expired');
        terminal = true;
        return;
      }
      $('status').textContent = 'Uploaded and verified';
      $('status-dot').className = 'dot complete';
      $('detail').textContent = 'Every chunk arrived and the whole-file SHA-256 matches.';
      $('filename').textContent = `${upload.name} · ${new Intl.NumberFormat().format(upload.size)} bytes`;
      const downloadUrl = baseUrl + upload.download_url;
      $('download').href = downloadUrl;
      $('download-link').value = downloadUrl;
      $('expires').textContent = `Available until ${expiration.toLocaleString()} (${duration(upload.ttl_hours)} after upload). The file is then deleted.`;
      $('password-note').hidden = !upload.password_protected;
      $('checksum').textContent = upload.sha256;
      $('result').hidden = false;
      // Keep checking expiry so a tab left open does not advertise an expired link.
    } else {
      $('status').textContent = 'Uploading your file';
      $('status-dot').className = 'dot active';
      $('detail').textContent = `${upload.received.toLocaleString()} of ${upload.total.toLocaleString()} chunks acknowledged · ${upload.name}`;
    }
  } catch {
    if (requestedId === transferId) {
      $('status').textContent = 'Connection interrupted — checking again shortly';
      $('result').hidden = true;
    }
  } finally { polling = false; }
}

$('file-path').addEventListener('input', command);
$('expires-hours').addEventListener('input', command);
$('ask-password').addEventListener('change', () => { $('password-fields').hidden = !$('ask-password').checked; command(); });
$('upload').addEventListener('click', startBrowserUpload);
// Dropping a file on the zone selects it; dropping anywhere else must not navigate away from the page.
for (const type of ['dragover', 'drop']) window.addEventListener(type, (event) => event.preventDefault());
for (const type of ['dragenter', 'dragover']) {
  $('drop-zone').addEventListener(type, (event) => {
    event.preventDefault();
    if (!uploading) $('drop-zone').classList.add('over');
  });
}
$('drop-zone').addEventListener('dragleave', (event) => {
  if (!$('drop-zone').contains(event.relatedTarget)) $('drop-zone').classList.remove('over');
});
$('drop-zone').addEventListener('drop', (event) => {
  event.preventDefault();
  $('drop-zone').classList.remove('over');
  const file = event.dataTransfer.files[0];
  if (uploading || !file) return;
  const selection = new DataTransfer();
  selection.items.add(file);
  $('file').files = selection.files;
});
$('copy').addEventListener('click', () => copy($('command').value, $('copy')));
$('copy-shell').addEventListener('click', () => copy($('shell-command').value, $('copy-shell')));
$('copy-token').addEventListener('click', () => copy(token, $('copy-token')));
$('copy-link').addEventListener('click', () => copy($('download-link').value, $('copy-link')));
$('new-transfer').addEventListener('click', async () => {
  window.location.hash = 'id=' + await newId();
});
window.addEventListener('hashchange', () => { transferReady = setTransfer().then(poll); });
transferReady = setTransfer().then(poll);
setInterval(poll, 2500);
// Confirm the session and show the account; an expired session sends us back to sign in.
fetch(`${baseUrl}/me`, { cache: 'no-store' }).then((r) => {
  if (r.status === 401) { signInAgain(); return null; }
  return r.ok ? r.json() : null;
}).then((me) => {
  if (!me) return;
  token = me.token || '';
  $('who').textContent = me.email || '';
  if (me.is_admin) $('users-link').hidden = false;
  $('cli-token').textContent = token || '(unavailable)';
}).catch(() => {});
fetch(`${baseUrl}/config`, { cache: 'no-store' }).then((r) => r.json()).then((config) => {
  maxFileSize = config.max_file_size;
  $('limits').textContent = `${config.chunk_size.toLocaleString()}-byte chunks · Maximum ${(config.max_file_size / 1024 / 1024).toLocaleString()} MiB per file · You choose when the link disappears (${duration(config.min_ttl_hours)} to ${duration(config.max_ttl_hours)})`;
}).catch(() => {});
