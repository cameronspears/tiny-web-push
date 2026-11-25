# tiny-web-push

Send web push notifications from Node, built on `node:crypto` and `fetch`. No dependencies.

To try it, clone this repo, run `pnpm install && pnpm demo` and open http://localhost:4174. Press
the button and your own machine sends your browser a real notification.

```bash
npm install tiny-web-push
npx tiny-web-push keys >> .env
```

```js
import { sendWebPush } from 'tiny-web-push';

const { result } = await sendWebPush(subscription, JSON.stringify({ title: 'Hello' }), {
  vapid: {
    publicKey: process.env.VAPID_PUBLIC_KEY,
    privateKey: process.env.VAPID_PRIVATE_KEY,
    subject: 'mailto:you@example.com',
  },
});
```

`subscription` is what the browser gives you when it subscribes:

```js
const registration = await navigator.serviceWorker.register('/sw.js');
const subscription = await registration.pushManager.subscribe({
  userVisibleOnly: true,
  applicationServerKey: 'YOUR_VAPID_PUBLIC_KEY',
});
await fetch('/api/push-subscriptions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(subscription),
});
```

And the service worker shows it:

```js
self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};
  event.waitUntil(self.registration.showNotification(data.title ?? 'New message', data));
});
```

Needs Node 20.12 or later. ESM only.

## Results

A failed send never throws. It comes back as one of six results:

- `sent`: the push service has it. Nothing to do.
- `gone` (404 or 410): the subscription is dead. Delete it.
- `throttled` (429): you're sending too fast. Try again later.
- `auth` (401 or 403): the push service rejected your VAPID keys. A 403 can also mean the browser
  subscribed with a different public key.
- `invalid` (400 or 413, or refused before sending): a bad endpoint, unreadable keys, a payload
  that's too long or a bad topic. Don't retry it as is.
- `failed` (a network error, a timeout or any other status): try again later.

Only `gone` means you should delete the subscription. The result also has `status` (`null` if no
response came back) and `host`, which is safe to log. Don't log the endpoint: anyone who has it can
send to that browser.

The one thing that does throw is bad `vapid` options, because then every send would fail the same
way.

## Options

`sendWebPush(subscription, payload, options)` takes:

- `vapid` (required): `{ publicKey, privateKey, subject }`. The subject is a `mailto:` or `https:`
  URL where the push service can reach you.
- `ttl` (default 4 weeks): seconds the push service holds the message for a browser that's offline.
- `urgency` (default `'normal'`): `'very-low'`, `'low'`, `'normal'` or `'high'`.
- `topic`: a newer message with the same topic replaces one that hasn't been delivered yet.
- `timeoutMs` (default `10000`): how long to wait for the push service.
- `fetch`: your own fetch, for tests or a proxy.
- `allowEndpoint` (default `isKnownPushService`): which endpoints it will send to. Out of the box
  that's only the push services of Chrome, Firefox, Safari and Edge, so a forged subscription can't
  make your server send requests anywhere else. Https is always required.

The payload can be a string or bytes, up to 3993 bytes. If you need more, send an ID and fetch the
rest.

`encryptWebPushPayload`, `vapidAuthorization`, `generateVapidKeys`, `classifyPushStatus` and
`isKnownPushService` are exported too, if you want to send the request yourself.

## Keys

```bash
npx tiny-web-push keys
```

Prints a new VAPID key pair as `.env` lines. The public key goes to the browser. Keep the private
key secret, and keep the pair for good: a new pair breaks every existing subscription.

## How it's tested

The tests reproduce the example in RFC 8291 Appendix A byte for byte, using the RFC's own keys and
salt. They also decrypt each message the way a browser would.

## Why not web-push

[web-push](https://www.npmjs.com/package/web-push) is the well-known library for this and has years
of production use. It's bigger and has dependencies. If you need the older `aesgcm` encoding or a
built-in proxy option, use web-push.

## License

MIT
