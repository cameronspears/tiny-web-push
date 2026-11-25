import {
  createCipheriv,
  createECDH,
  createPrivateKey,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  type KeyObject,
} from 'node:crypto';

/**
 * Standard Web Push on node:crypto, with no dependencies:
 * - RFC 8291 message encryption (aes128gcm, RFC 8188), pinned by the RFC's Appendix A test;
 * - RFC 8292 VAPID, an ES256 JWT that tells the push service who is sending.
 */

/** The browser's `PushSubscription.toJSON()`. Other fields (like expirationTime) are ignored. */
export type PushSubscriptionJSON = {
  endpoint: string;
  keys: { p256dh: string; auth: string };
};

/** Your VAPID key pair (base64url, as `generateVapidKeys` prints it) and a contact URL. */
export type VapidOptions = {
  /** The 65-byte uncompressed P-256 public key, base64url. The browser subscribes with this. */
  publicKey: string;
  /** The 32-byte P-256 private key, base64url. Keep it secret. */
  privateKey: string;
  /** `mailto:you@example.com` or an `https:` URL the push service can reach you at. */
  subject: string;
};

/** How urgent a message is (RFC 8030). Lower urgency lets phones save battery. */
export type Urgency = 'very-low' | 'low' | 'normal' | 'high';

/** The part of `fetch` this package uses. Pass your own for tests or a proxy. */
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

/** Options for `sendWebPush`. Only `vapid` is required. */
export type SendWebPushOptions = {
  /** Your VAPID keys and contact URL. */
  vapid: VapidOptions;
  /** Seconds the push service keeps the message for an offline browser. Default 4 weeks. */
  ttl?: number;
  /** How urgent the message is. Default `'normal'`. */
  urgency?: Urgency;
  /** Replaces an undelivered message with the same topic (RFC 8030). Up to 32 base64url characters. */
  topic?: string;
  /** Gives up on the push service after this many milliseconds. Default 10 000. */
  timeoutMs?: number;
  /** The fetch to send with. Default the global `fetch`. */
  fetch?: FetchLike;
  /**
   * Which endpoints you are willing to POST to. Default `isKnownPushService`. The endpoint must
   * always be https, whatever this returns.
   */
  allowEndpoint?: (url: URL) => boolean;
};

/**
 * How a send ended:
 * - `sent`: the push service accepted the message.
 * - `gone`: 404 or 410. The subscription is dead; delete it.
 * - `throttled`: 429. Slow down and try later.
 * - `auth`: 401 or 403. The push service rejected your VAPID keys.
 * - `invalid`: 400 or 413, or the subscription was refused before sending.
 * - `failed`: a network error, a timeout or any other status. Try later.
 */
export type WebPushResult = 'sent' | 'gone' | 'throttled' | 'auth' | 'invalid' | 'failed';

/** What `sendWebPush` resolves to. */
export type WebPushSendResult = {
  /** How the send ended. Only `gone` means the subscription should be deleted. */
  result: WebPushResult;
  /** The HTTP status, or null if no response came back. */
  status: number | null;
  /** The push service host, safe to log. Never log the endpoint: it works like a password. */
  host: string | null;
};

const RECORD_SIZE = 4096;
const HEADER_SIZE = 86;
const TAG_SIZE = 16;
/** The longest payload one record can carry: 4096 - 86 header - 1 delimiter - 16 tag. */
export const MAX_PAYLOAD_BYTES = RECORD_SIZE - HEADER_SIZE - 1 - TAG_SIZE;

const KEY_INFO = Buffer.from('WebPush: info\0', 'latin1');
const CEK_INFO = Buffer.from('Content-Encoding: aes128gcm\0', 'latin1');
const NONCE_INFO = Buffer.from('Content-Encoding: nonce\0', 'latin1');
/** RFC 8188: the last (and here only) record ends with 0x02 before encryption. */
const LAST_RECORD_DELIMITER = Buffer.from([0x02]);

function hkdf(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
  return Buffer.from(hkdfSync('sha256', ikm, salt, info, length));
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Strict base64url of an exact length. Trailing `=` padding is accepted and ignored. */
function decodeBase64Url(value: unknown, bytes: number): Buffer | null {
  if (typeof value !== 'string') return null;
  const unpadded = value.replace(/={1,2}$/, '');
  if (!BASE64URL.test(unpadded)) return null;
  const decoded = Buffer.from(unpadded, 'base64url');
  if (decoded.length !== bytes || decoded.toString('base64url') !== unpadded) return null;
  return decoded;
}

/** Fixed inputs for known-answer tests. Real sends always use fresh randomness. */
export type WebPushFixedInputs = {
  /** 16 random bytes in real use. */
  salt: Uint8Array;
  /** The sender's one-time ECDH private key (32 bytes). */
  senderPrivateKey: Uint8Array;
};

/**
 * Encrypts one push message for one browser (RFC 8291, `aes128gcm`). `sendWebPush` calls this
 * for you; use it directly only if you send the request yourself.
 *
 * @param plaintext - The message, at most `MAX_PAYLOAD_BYTES` long.
 * @param browserPublicKey - The subscription's `keys.p256dh`, decoded: 65 bytes.
 * @param authSecret - The subscription's `keys.auth`, decoded: 16 bytes.
 * @param fixed - Fixed salt and sender key, for known-answer tests only.
 * @returns The whole request body: an 86-byte header (salt, record size, the sender's one-time
 *   public key) followed by the ciphertext.
 * @throws If a key is the wrong size or not on the curve, or the message is too long.
 */
export function encryptWebPushPayload(
  plaintext: Uint8Array,
  browserPublicKey: Uint8Array,
  authSecret: Uint8Array,
  fixed?: WebPushFixedInputs
): Buffer {
  const uaPublic = Buffer.from(browserPublicKey);
  if (uaPublic.length !== 65 || uaPublic[0] !== 0x04) throw new Error('Invalid browser key');
  if (authSecret.length !== 16) throw new Error('Invalid auth secret');
  if (plaintext.length > MAX_PAYLOAD_BYTES) throw new Error('Push message too long');

  const ecdh = createECDH('prime256v1');
  if (fixed) ecdh.setPrivateKey(Buffer.from(fixed.senderPrivateKey));
  else ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const salt = fixed ? Buffer.from(fixed.salt) : randomBytes(16);

  // computeSecret throws if the browser key is not on the curve.
  const ecdhSecret = ecdh.computeSecret(uaPublic);
  const ikm = hkdf(
    ecdhSecret,
    Buffer.from(authSecret),
    Buffer.concat([KEY_INFO, uaPublic, asPublic]),
    32
  );
  const cek = hkdf(ikm, salt, CEK_INFO, 16);
  const nonce = hkdf(ikm, salt, NONCE_INFO, 12);

  const cipher = createCipheriv('aes-128-gcm', cek, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.concat([plaintext, LAST_RECORD_DELIMITER])),
    cipher.final(),
    cipher.getAuthTag(),
  ]);

  const header = Buffer.alloc(16 + 4 + 1);
  salt.copy(header, 0);
  header.writeUInt32BE(RECORD_SIZE, 16);
  header.writeUInt8(asPublic.length, 20);
  return Buffer.concat([header, asPublic, ciphertext]);
}

const signingKeys = new Map<string, KeyObject>();

/** The private key as a KeyObject. Throws unless both keys are valid and belong together. */
function vapidSigningKey(vapid: VapidOptions): KeyObject {
  const cacheKey = `${vapid.publicKey}|${vapid.privateKey}`;
  const cached = signingKeys.get(cacheKey);
  if (cached) return cached;

  const publicKey = decodeBase64Url(vapid.publicKey, 65);
  const d = decodeBase64Url(vapid.privateKey, 32);
  if (!publicKey || publicKey[0] !== 0x04 || !d) throw new TypeError('Invalid VAPID keys');
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  if (!ecdh.getPublicKey().equals(publicKey)) {
    throw new TypeError('VAPID public and private keys do not match');
  }
  const key = createPrivateKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: d.toString('base64url'),
      x: publicKey.subarray(1, 33).toString('base64url'),
      y: publicKey.subarray(33, 65).toString('base64url'),
    },
    format: 'jwk',
  });
  if (signingKeys.size > 32) signingKeys.clear();
  signingKeys.set(cacheKey, key);
  return key;
}

const VAPID_TOKEN_LIFETIME_SECONDS = 12 * 60 * 60;
const VAPID_TOKEN_REUSE_SECONDS = 60 * 60;
const vapidTokens = new Map<string, { header: string; issuedAt: number }>();

/**
 * Builds the VAPID `Authorization` header for one push service (RFC 8292). The token lasts
 * 12 hours (the RFC allows up to 24) and is reused for an hour per push service, so a batch of
 * sends signs once. `sendWebPush` calls this for you.
 *
 * @param endpoint - The subscription endpoint. Only its origin is signed.
 * @param vapid - Your VAPID keys and contact URL.
 * @param nowSec - The current time in Unix seconds. Defaults to now.
 * @returns The header value: `vapid t=<jwt>, k=<public key>`.
 * @throws TypeError if the keys are invalid or don't match, or the subject isn't mailto: or https:.
 */
export function vapidAuthorization(
  endpoint: string,
  vapid: VapidOptions,
  nowSec: number = Math.floor(Date.now() / 1000)
): string {
  if (!/^(mailto:|https:)/.test(vapid.subject)) {
    throw new TypeError('VAPID subject must be a mailto: or https: URL');
  }
  const key = vapidSigningKey(vapid);
  const audience = new URL(endpoint).origin;
  const cacheKey = `${vapid.publicKey}|${vapid.subject}|${audience}`;
  const cached = vapidTokens.get(cacheKey);
  if (cached && nowSec >= cached.issuedAt && nowSec - cached.issuedAt < VAPID_TOKEN_REUSE_SECONDS) {
    return cached.header;
  }

  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const unsigned = `${encode({ typ: 'JWT', alg: 'ES256' })}.${encode({
    aud: audience,
    exp: nowSec + VAPID_TOKEN_LIFETIME_SECONDS,
    sub: vapid.subject,
  })}`;
  const signature = sign('sha256', Buffer.from(unsigned), {
    key,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  const header = `vapid t=${unsigned}.${signature}, k=${vapid.publicKey}`;
  if (vapidTokens.size > 32) vapidTokens.clear();
  vapidTokens.set(cacheKey, { header, issuedAt: nowSec });
  return header;
}

/**
 * Makes a new VAPID key pair. Do this once and keep the pair: a new pair breaks every existing
 * subscription.
 *
 * @returns `publicKey` (65-byte P-256 point) and `privateKey` (32 bytes), both base64url.
 */
export function generateVapidKeys(): { publicKey: string; privateKey: string } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  // JWK coordinates and the scalar are always padded to 32 bytes.
  const jwk = privateKey.export({ format: 'jwk' });
  if (!jwk.d || !jwk.x || !jwk.y) throw new Error('Key generation failed');
  return {
    publicKey: Buffer.concat([
      Buffer.from([0x04]),
      Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url'),
    ]).toString('base64url'),
    privateKey: jwk.d,
  };
}

const PUSH_SERVICE_HOSTS = new Set([
  'fcm.googleapis.com',
  'updates.push.services.mozilla.com',
  'web.push.apple.com',
]);
const WINDOWS_PUSH_HOST = /^[a-z0-9-]+\.notify\.windows\.com$/;

/**
 * The default endpoint check. It allows only the push services of Chrome, Firefox, Safari and
 * Edge, over https on the default port. It stops a forged subscription from making your server
 * POST anywhere else.
 *
 * @param url - The parsed subscription endpoint.
 * @returns True if the endpoint belongs to a known push service.
 */
export function isKnownPushService(url: URL): boolean {
  if (url.protocol !== 'https:' || url.port !== '' || url.hash !== '') return false;
  const host = url.hostname.toLowerCase();
  return PUSH_SERVICE_HOSTS.has(host) || WINDOWS_PUSH_HOST.test(host);
}

/**
 * Maps a push service's HTTP status to a result.
 *
 * @param status - The HTTP status code.
 * @returns `sent` for 2xx, `gone` for 404/410, `throttled` for 429, `auth` for 401/403,
 *   `invalid` for 400/413 and `failed` for anything else.
 */
export function classifyPushStatus(status: number): WebPushResult {
  if (status >= 200 && status < 300) return 'sent';
  if (status === 404 || status === 410) return 'gone';
  if (status === 429) return 'throttled';
  if (status === 401 || status === 403) return 'auth';
  if (status === 400 || status === 413) return 'invalid';
  return 'failed';
}

const MAX_ENDPOINT_LENGTH = 1024;

function parseEndpoint(value: unknown): URL | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_ENDPOINT_LENGTH ||
    value.includes('#')
  ) {
    return null;
  }
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}

/**
 * Encrypts and sends one push message to one browser.
 *
 * Anything about the subscription, the push service or the network comes back as a result,
 * never as a throw. It throws only if your VAPID options are wrong, since then every send would
 * fail the same way.
 *
 * @param subscription - The browser's `PushSubscription` as JSON: `{ endpoint, keys }`.
 * @param payload - The message, as a string (sent as UTF-8) or bytes. At most 3993 bytes.
 * @param options - Your VAPID keys plus optional TTL, urgency, topic, timeout, fetch and
 *   endpoint check.
 * @returns `{ result, status, host }`. See `WebPushResult` for what to do with each result.
 * @throws TypeError if `options.vapid` is invalid.
 *
 * @example
 * ```ts
 * import { sendWebPush } from 'tiny-web-push';
 *
 * const { result } = await sendWebPush(subscription, JSON.stringify({ title: 'Hello' }), {
 *   vapid: {
 *     publicKey: process.env.VAPID_PUBLIC_KEY!,
 *     privateKey: process.env.VAPID_PRIVATE_KEY!,
 *     subject: 'mailto:push@example.com',
 *   },
 * });
 * if (result === 'gone') await deleteSubscription(subscription.endpoint);
 * ```
 */
export async function sendWebPush(
  subscription: PushSubscriptionJSON,
  payload: string | Uint8Array,
  options: SendWebPushOptions
): Promise<WebPushSendResult> {
  const endpoint = parseEndpoint(subscription?.endpoint);
  const allow = options.allowEndpoint ?? isKnownPushService;
  if (!endpoint || !allow(endpoint)) return { result: 'invalid', status: null, host: null };
  const host = endpoint.hostname;

  // Bad VAPID options throw here, before anything is sent.
  const authorization = vapidAuthorization(endpoint.href, options.vapid);

  const browserKey = decodeBase64Url(subscription.keys?.p256dh, 65);
  const authSecret = decodeBase64Url(subscription.keys?.auth, 16);
  if (!browserKey || !authSecret) return { result: 'invalid', status: null, host };

  let body: Buffer;
  try {
    const plaintext = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
    body = encryptWebPushPayload(plaintext, browserKey, authSecret);
  } catch {
    return { result: 'invalid', status: null, host };
  }

  const headers: Record<string, string> = {
    Authorization: authorization,
    TTL: String(Math.max(0, Math.floor(options.ttl ?? 4 * 7 * 24 * 60 * 60))),
    Urgency: options.urgency ?? 'normal',
    'Content-Encoding': 'aes128gcm',
    'Content-Type': 'application/octet-stream',
  };
  if (options.topic) headers.Topic = options.topic;

  const fetchImpl: FetchLike = options.fetch ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(subscription.endpoint, {
      method: 'POST',
      headers,
      body: new Uint8Array(body),
      redirect: 'error',
      signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
    });
  } catch {
    return { result: 'failed', status: null, host };
  }
  // Always release the body: an unread body can hold the connection open in Node's fetch.
  // Not awaited, so a cancel that never settles can't hold the send either.
  try {
    response.body?.cancel().catch(() => {});
  } catch {
    // Nothing to release.
  }
  return { result: classifyPushStatus(response.status), status: response.status, host };
}
