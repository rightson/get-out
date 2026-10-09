// Runs web/app.js against a live server with a minimal DOM stub and clicks Upload.
// Usage: node browser_upload.mjs <app.js> <server-url> <file> [password]
// Prints the resulting page state as JSON.
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import vm from 'node:vm';

const [appPath, base, filePath, password] = process.argv.slice(2);
const elements = new Map();
const element = (id) => {
  if (!elements.has(id)) {
    const listeners = {};
    elements.set(id, {
      value: '', textContent: '', hidden: id === 'password-note' || id === 'upload-error', checked: false,
      disabled: false, open: false, files: [], className: '', listeners,
      addEventListener(type, fn) { listeners[type] = fn; },
    });
  }
  return elements.get(id);
};
element('expires-hours').value = '0.5';
const intervals = [];
// A real browser attaches the session cookie automatically; here we inject the account's token.
const token = process.env.GETOUT_TOKEN;
const authFetch = (url, opts = {}) => {
  const headers = new Headers(opts.headers || {});
  if (token) headers.set('Cookie', 'getout_session=' + token);
  return globalThis.fetch(url, { ...opts, headers });
};
const context = {
  document: { getElementById: element },
  window: { location: { href: base + '/', hash: '', assign() {} }, addEventListener() {} },
  history: { replaceState(_state, _title, url) { context.window.location.hash = url; } },
  crypto: globalThis.crypto, fetch: authFetch, btoa: globalThis.btoa, TextEncoder, URL, URLSearchParams, Headers,
  Intl, Date, Math, Number, Promise, Uint8Array, Error, Array, String, console, setTimeout,
  setInterval: (fn, ms) => { intervals.push(setInterval(fn, ms)); },
  navigator: {},
};
vm.createContext(context);
vm.runInContext(readFileSync(appPath, 'utf8'), context);

element('file').files = [new File([readFileSync(filePath)], basename(filePath))];
if (password !== undefined) {
  element('ask-password').checked = true;
  element('password').value = element('password-confirm').value = password;
}
await element('upload').listeners.click();
await new Promise((resolve) => { setTimeout(resolve, 500); }); // Let the final status poll land.
intervals.forEach(clearInterval);
console.log(JSON.stringify({
  transferId: element('transfer-id').textContent,
  status: element('status').textContent,
  error: element('upload-error').hidden ? null : element('upload-error').textContent,
  scriptsOpen: element('scripts').open,
  downloadLink: element('download-link').value,
  passwordProtected: !element('password-note').hidden,
}));
