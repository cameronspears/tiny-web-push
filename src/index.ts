/**
 * Standard Web Push on Web Crypto and fetch, with no dependencies. It runs anywhere both exist:
 * Node 20+, Deno, Bun, Cloudflare Workers and Vercel Edge.
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

type Bytes = Uint8Array<ArrayBuffer>;

const utf8 = (text: string): Bytes => new TextEncoder().encode(text) as Bytes;

const KEY_INFO = utf8('WebPush: info\0');
const CEK_INFO = utf8('Content-Encoding: aes128gcm\0');
const NONCE_INFO = utf8('Content-Encoding: nonce\0');
/** RFC 8188: the last (and here only) record ends with 0x02 before encryption. */
const LAST_RECORD_DELIMITER = new Uint8Array([0x02]);

const subtle = () => globalThis.crypto.subtle;
const P256_ECDH = { name: 'ECDH', namedCurve: 'P-256' } as const;
const P256_ECDSA = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ES256 = { name: 'ECDSA', hash: 'SHA-256' } as const;

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const BASE64URL_VALUES = new Map([...BASE64URL_ALPHABET].map((char, index) => [char, index]));

/** Unpadded base64url. */
function encodeBase64Url(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const chunk = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = Math.min(4, Math.ceil(((bytes.length - i) * 8) / 6));
    for (let j = 0; j < chars; j++) out += BASE64URL_ALPHABET[(chunk >> (18 - 6 * j)) & 63];
  }
  return out;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Strict base64url of an exact length. Trailing `=` padding is accepted and ignored. */
function decodeBase64Url(value: unknown, bytes: number): Bytes | null {
  if (typeof value !== 'string') return null;
  const unpadded = value.replace(/={1,2}$/, '');
  if (!BASE64URL.test(unpadded) || Math.floor((unpadded.length * 6) / 8) !== bytes) return null;
  const decoded = new Uint8Array(bytes);
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of unpadded) {
    buffer = ((buffer << 6) | BASE64URL_VALUES.get(char)!) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      decoded[index++] = (buffer >> bits) & 0xff;
    }
  }
  // Leftover bits must be zero, so each key has exactly one spelling.
  return encodeBase64Url(decoded) === unpadded ? decoded : null;
}

async function hkdf(ikm: Bytes, salt: Bytes, info: Bytes, length: number): Promise<Bytes> {
  const key = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const params = { name: 'HKDF', hash: 'SHA-256', salt, info };
  return new Uint8Array(await subtle().deriveBits(params, key, length * 8));
}

/**
 * PKCS#8 for a P-256 private key with no public key in it. Web Crypto can't import a bare
 * scalar, so this is how a fixed test key gets in; the runtime works out the public key.
 */
const P256_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
  0x01, 0x04, 0x20,
]);

/** A one-time ECDH key pair for the sender, and its public key as a 65-byte point. */
async function senderKeyPair(
  fixed?: Uint8Array
): Promise<{ privateKey: CryptoKey; publicKey: Bytes }> {
  if (!fixed) {
    const pair = await subtle().generateKey(P256_ECDH, true, ['deriveBits']);
    const publicKey = new Uint8Array(await subtle().exportKey('raw', pair.publicKey));
    return { privateKey: pair.privateKey, publicKey };
  }
  if (fixed.length !== 32) throw new Error('Invalid sender key');
  const pkcs8 = concat(P256_PKCS8_PREFIX, fixed);
  const privateKey = await subtle().importKey('pkcs8', pkcs8, P256_ECDH, true, ['deriveBits']);
  const jwk = await subtle().exportKey('jwk', privateKey);
  const x = decodeBase64Url(jwk.x, 32);
  const y = decodeBase64Url(jwk.y, 32);
  if (!x || !y) throw new Error('Invalid sender key');
  return { privateKey, publicKey: concat(new Uint8Array([0x04]), x, y) };
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
 * @throws If a key is the wrong size or not on the curve, or the message is too long. As a
 *   rejected promise, like every other error here.
 */
export async function encryptWebPushPayload(
  plaintext: Uint8Array,
  browserPublicKey: Uint8Array,
  authSecret: Uint8Array,
  fixed?: WebPushFixedInputs
): Promise<Uint8Array> {
  const uaPublic = concat(browserPublicKey);
  if (uaPublic.length !== 65 || uaPublic[0] !== 0x04) throw new Error('Invalid browser key');
  if (authSecret.length !== 16) throw new Error('Invalid auth secret');
  if (plaintext.length > MAX_PAYLOAD_BYTES) throw new Error('Push message too long');
  if (fixed && fixed.salt.length !== 16) throw new Error('Invalid salt');

  let uaKey: CryptoKey;
  try {
    // Import refuses a point that is not on the curve.
    uaKey = await subtle().importKey('raw', uaPublic, P256_ECDH, false, []);
  } catch {
    throw new Error('Invalid browser key');
  }
  const sender = await senderKeyPair(fixed?.senderPrivateKey);
  const salt = fixed ? concat(fixed.salt) : globalThis.crypto.getRandomValues(new Uint8Array(16));

  const ecdhSecret = new Uint8Array(
    await subtle().deriveBits({ name: 'ECDH', public: uaKey }, sender.privateKey, 256)
  );
  const keyInfo = concat(KEY_INFO, uaPublic, sender.publicKey);
  const ikm = await hkdf(ecdhSecret, concat(authSecret), keyInfo, 32);
  const cek = await hkdf(ikm, salt, CEK_INFO, 16);
  const nonce = await hkdf(ikm, salt, NONCE_INFO, 12);

  const aesKey = await subtle().importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  // Web Crypto appends the 16-byte tag to the ciphertext, as aes128gcm wants.
  const ciphertext = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv: nonce, tagLength: TAG_SIZE * 8 },
      aesKey,
      concat(plaintext, LAST_RECORD_DELIMITER)
    )
  );

  const header = new Uint8Array(16 + 4 + 1);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, RECORD_SIZE);
  header[20] = sender.publicKey.length;
  return concat(header, sender.publicKey, ciphertext);
}

const signingKeys = new Map<string, CryptoKey>();

/** The private key, ready to sign. Rejects unless both keys are valid and belong together. */
async function vapidSigningKey(vapid: VapidOptions): Promise<CryptoKey> {
  const cacheKey = `${vapid.publicKey}|${vapid.privateKey}`;
  const cached = signingKeys.get(cacheKey);
  if (cached) return cached;

  const publicKey = decodeBase64Url(vapid.publicKey, 65);
  const d = decodeBase64Url(vapid.privateKey, 32);
  if (!publicKey || publicKey[0] !== 0x04 || !d) throw new TypeError('Invalid VAPID keys');
  let verifyKey: CryptoKey;
  try {
    verifyKey = await subtle().importKey('raw', publicKey, P256_ECDSA, false, ['verify']);
  } catch {
    throw new TypeError('Invalid VAPID keys');
  }

  // Not every runtime checks that d matches x and y on import, so sign something and verify it.
  let key: CryptoKey | undefined;
  let matches = false;
  try {
    key = await subtle().importKey(
      'jwk',
      {
        kty: 'EC',
        crv: 'P-256',
        d: encodeBase64Url(d),
        x: encodeBase64Url(publicKey.subarray(1, 33)),
        y: encodeBase64Url(publicKey.subarray(33, 65)),
      },
      P256_ECDSA,
      false,
      ['sign']
    );
    const probe = utf8('tiny-web-push key check');
    const signature = await subtle().sign(ES256, key, probe);
    matches = await subtle().verify(ES256, verifyKey, signature, probe);
  } catch {
    // A runtime that does check refuses the import; that is a mismatch too.
  }
  if (!matches || !key) throw new TypeError('VAPID public and private keys do not match');
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
 * @throws TypeError (as a rejected promise) if the keys are invalid or don't match, or the
 *   subject isn't mailto: or https:.
 */
export async function vapidAuthorization(
  endpoint: string,
  vapid: VapidOptions,
  nowSec: number = Math.floor(Date.now() / 1000)
): Promise<string> {
  if (!/^(mailto:|https:)/.test(vapid.subject)) {
    throw new TypeError('VAPID subject must be a mailto: or https: URL');
  }
  const key = await vapidSigningKey(vapid);
  const audience = new URL(endpoint).origin;
  const cacheKey = `${vapid.publicKey}|${vapid.subject}|${audience}`;
  const cached = vapidTokens.get(cacheKey);
  if (cached && nowSec >= cached.issuedAt && nowSec - cached.issuedAt < VAPID_TOKEN_REUSE_SECONDS) {
    return cached.header;
  }

  const encode = (value: unknown) => encodeBase64Url(utf8(JSON.stringify(value)));
  const unsigned = `${encode({ typ: 'JWT', alg: 'ES256' })}.${encode({
    aud: audience,
    exp: nowSec + VAPID_TOKEN_LIFETIME_SECONDS,
    sub: vapid.subject,
  })}`;
  // Web Crypto signs ECDSA as raw r || s (64 bytes), which is exactly what a JWT wants.
  const raw = new Uint8Array(await subtle().sign(ES256, key, utf8(unsigned)));
  const signature = encodeBase64Url(raw);
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
export async function generateVapidKeys(): Promise<{ publicKey: string; privateKey: string }> {
  const pair = await subtle().generateKey(P256_ECDSA, true, ['sign', 'verify']);
  const publicKey = new Uint8Array(await subtle().exportKey('raw', pair.publicKey));
  // JWK pads the scalar to 32 bytes. Decoding checks that, and drops any padding.
  const d = decodeBase64Url((await subtle().exportKey('jwk', pair.privateKey)).d, 32);
  if (!d || publicKey.length !== 65) throw new Error('Key generation failed');
  return { publicKey: encodeBase64Url(publicKey), privateKey: encodeBase64Url(d) };
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
  const authorization = await vapidAuthorization(endpoint.href, options.vapid);

  const browserKey = decodeBase64Url(subscription.keys?.p256dh, 65);
  const authSecret = decodeBase64Url(subscription.keys?.auth, 16);
  if (!browserKey || !authSecret) return { result: 'invalid', status: null, host };

  let body: Uint8Array;
  try {
    const plaintext = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload;
    body = await encryptWebPushPayload(plaintext, browserKey, authSecret);
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
      body: body as Uint8Array<ArrayBuffer>,
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
