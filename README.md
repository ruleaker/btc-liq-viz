# btc-liq-viz

Personal BTC dashboard.

The bundled dataset is encrypted (AES-GCM, PBKDF2-SHA256 200k iter). Open the
page, enter the passphrase, decrypt locally — no server, no analytics.

## Stack

- Vanilla HTML / CSS / JS — no framework, no build step
- [`lightweight-charts`](https://github.com/tradingview/lightweight-charts) v5 via CDN
- Web Crypto API (browser-native) for decryption
- Hosted on GitHub Pages
