# Changelog

All notable changes to this package are listed here. It follows [semantic versioning](https://semver.org).

## 0.1.0 (unreleased)

First release.

- `sendWebPush` encrypts and sends one push message, and returns a plain result (`sent`, `gone`, `throttled`, `auth`, `invalid` or `failed`) instead of throwing.
- `encryptWebPushPayload` (RFC 8291, `aes128gcm`), checked against the RFC's own test data.
- `vapidAuthorization` (RFC 8292), with tokens reused for an hour per push service.
- `generateVapidKeys`, `classifyPushStatus` and `isKnownPushService`.
- Sends only to known browser push services over https by default.
- `tiny-web-push keys` prints a new VAPID key pair.
- No runtime dependencies.
