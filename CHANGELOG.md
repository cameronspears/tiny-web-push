# Changelog

All notable changes to this package are listed here. It follows [semantic versioning](https://semver.org).

## 0.1.0 (unreleased)

First release.

- Runs anywhere with `fetch` and Web Crypto: Node 20 or later, Deno, Bun, Cloudflare Workers and Vercel Edge. The library imports nothing from Node.
- `sendWebPush` encrypts and sends one push message, and returns a plain result (`sent`, `gone`, `throttled`, `auth`, `invalid` or `failed`) instead of throwing.
- `encryptWebPushPayload` (RFC 8291, `aes128gcm`), checked against the RFC's own test data.
- `vapidAuthorization` (RFC 8292), with tokens reused for an hour per push service.
- `generateVapidKeys`, `classifyPushStatus` and `isKnownPushService`.
- `encryptWebPushPayload`, `vapidAuthorization` and `generateVapidKeys` return promises, since Web Crypto is async.
- Sends only to known browser push services over https by default.
- `tiny-web-push keys` prints a new VAPID key pair. The CLI needs Node 20 or later.
- No runtime dependencies.
