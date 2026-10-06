'use strict';
const $ = (id) => document.getElementById(id);
const baseUrl = new URL('.', window.location.href).href.replace(/\/$/, '');
let transferId;
let seen = false;
let terminal = false;
let polling = false;

function setTransfer() {
  const candidate = new URLSearchParams(window.location.hash.slice(1)).get('id');
  transferId = /^[a-f0-9]{32}$/.test(candidate || '') ? candidate : crypto.randomUUID().replaceAll('-', '');
  history.replaceState(null, '', `#id=${transferId}`);
  seen = false;
  terminal = false;
  $('transfer-id').textContent = transferId;
  $('result').hidden = true;
  $('progress').value = 0;
  $('status').textContent = 'Waiting for your script';
  $('status-dot').className = 'dot';
  $('detail').textContent = 'Keep this page open while the script uploads. Interrupted uploads can resume with the same transfer ID.';
  command();
}

function psQuote(value) { return "'" + value.replaceAll("'", "''") + "'"; }
function shQuote(value) { return "'" + value.replaceAll("'", "'\"'\"'") + "'"; }
function command() {
  const filePath = $('file-path').value || 'C:\\path\\to\\your-file.zip';
  $('command').value = `.\\Upload-File.ps1 -ServerUrl ${psQuote(baseUrl)} -Path ${psQuote(filePath)} -TransferId ${psQuote(transferId)} -OpenResult`;
  const shellPath = $('file-path').value || '/path/to/your-file.zip';
  $('shell-command').value = `sh ./Upload-File.sh --server-url ${shQuote(baseUrl)} --path ${shQuote(shellPath)} --transfer-id ${shQuote(transferId)} --open-result`;
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
async function poll() {
  if (polling || terminal) return;
  polling = true;
  const requestedId = transferId;
  try {
    const response = await fetch(`${baseUrl}/status?id=${requestedId}`, { cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (requestedId !== transferId) return;
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
      $('detail').textContent = 'The SHA-256 checksum did not match. Start a new transfer and run the script again.';
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
      $('expires').textContent = `Available until ${expiration.toLocaleString()} (24 hours after upload).`;
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
$('copy').addEventListener('click', () => copy($('command').value, $('copy')));
$('copy-shell').addEventListener('click', () => copy($('shell-command').value, $('copy-shell')));
$('copy-link').addEventListener('click', () => copy($('download-link').value, $('copy-link')));
$('new-transfer').addEventListener('click', () => {
  window.location.hash = 'id=' + crypto.randomUUID().replaceAll('-', '');
});
window.addEventListener('hashchange', () => { setTransfer(); poll(); });
setTransfer();
poll();
setInterval(poll, 2500);
fetch(`${baseUrl}/config`, { cache: 'no-store' }).then((r) => r.json()).then((config) => {
  $('limits').textContent = `${config.chunk_size.toLocaleString()}-byte chunks · Maximum ${(config.max_file_size / 1024 / 1024).toLocaleString()} MiB per file · Downloads expire in 24 hours`;
}).catch(() => {});
