# Finora

A tiny personal budget app: budgets, income, expenses, weekly/monthly recurring items and a monthly in/out report. Plain HTML/CSS/JS, no dependencies, no build step.

## Security model

- All data is encrypted in the browser with AES-256-GCM. The key is derived from your passphrase with PBKDF2-SHA256 (600,000 iterations) and never leaves memory.
- Only ciphertext is stored, both in the browser (localStorage) and in the private data repo on GitHub. The GitHub token is stored encrypted too.
- A strict Content-Security-Policy allows only this site's own files and `api.github.com`. No third-party scripts, fonts or trackers.
- All text is rendered with `textContent`, never as HTML. Synced data is validated before use.
- The app locks itself after 5 minutes without activity. Locking reloads the page, which drops the key and data from memory.
- If you forget the passphrase, the data cannot be recovered. Use **Settings → Export** now and then for a backup (that file is not encrypted).

## Setup

1. Publish this repo with GitHub Pages: **Settings → Pages → Deploy from a branch → `main` / root**.
2. Create a **private** repo for the data, e.g. `finora-data` (it can be empty).
3. Create a fine-grained token at **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**:
   - Repository access: **Only select repositories → `finora-data`**
   - Permissions: **Contents: Read and write** (nothing else)
   - Expiration: e.g. 1 year (you'll then create a new one and paste it in Settings)
4. Open the app, choose a passphrase, then go to **Settings → Sync** and enter `your-name/finora-data` and the token.
5. On your iPhone, open the same URL in Safari, enter the **same passphrase**, and the same repo and token. Use **Share → Add to Home Screen** for an app-like icon.

## Releasing

GitHub Pages lets browsers cache files for up to 10 minutes. When `app.js` or `style.css` changes, bump the `?v=` number on both in `index.html` so browsers fetch the new files together.
