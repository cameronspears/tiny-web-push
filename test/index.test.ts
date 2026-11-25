import { createDecipheriv, createECDH, createPublicKey, hkdfSync, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';

import { runCli, shouldUseColor } from '../src/cli.js';

import {
  classifyPushStatus,
  encryptWebPushPayload,
  generateVapidKeys,
  isKnownPushService,
  MAX_PAYLOAD_BYTES,
  sendWebPush,
  vapidAuthorization,
  type FetchLike,
  type VapidOptions,
} from '../src/index.js';

/** base64url with the RFC's presentation whitespace removed. */
const b64 = (value: string) => Buffer.from(value.replace(/\s+/g, ''), 'base64url');

// RFC 8291 Appendix A, inputs copied verbatim (whitespace is the RFC's line wrapping).
const RFC = {
  plaintext: 'V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24',
  asPublic: `BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg
      Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8`,
  asPrivate: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
  uaPublic: `BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-
      JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4`,
  uaPrivate: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94',
  salt: 'DGv6ra1nlYgDCS1FRnbzlw',
  authSecret: 'BTBZMqHH6r4Tts7J_aSIgg',
  header: `DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
   mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8`,
  ciphertext: `8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs
   bI_0LpXMuGvnzQ`,
  // Section 5: the whole request body.
  message: `DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
   mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT
   pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN`,
};

function makeVapid(): VapidOptions {
  return { ...generateVapidKeys(), subject: 'mailto:push@example.com' };
}

function makeBrowser() {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const auth = Buffer.alloc(16, 7);
  return {
    ecdh,
    auth,
    subscription: {
      endpoint: 'https://fcm.googleapis.com/fcm/send/abc123',
      keys: {
        p256dh: ecdh.getPublicKey().toString('base64url'),
        auth: auth.toString('base64url'),
      },
    },
  };
}

/** What a browser does with a push body: RFC 8291 decryption with its private key. */
function decrypt(body: Buffer, uaEcdh: ReturnType<typeof createECDH>, authSecret: Buffer) {
  const salt = body.subarray(0, 16);
  const recordSize = body.readUInt32BE(16);
  const keyLength = body.readUInt8(20);
  const asPublic = body.subarray(21, 21 + keyLength);
  const ciphertext = body.subarray(21 + keyLength);
  const ecdhSecret = uaEcdh.computeSecret(asPublic);
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaEcdh.getPublicKey(), asPublic]);
  const ikm = Buffer.from(hkdfSync('sha256', ecdhSecret, authSecret, keyInfo, 32));
  const cek = Buffer.from(hkdfSync('sha256', ikm, salt, 'Content-Encoding: aes128gcm\0', 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, 'Content-Encoding: nonce\0', 12));
  const decipher = createDecipheriv('aes-128-gcm', cek, nonce);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  const padded = Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.length - 16)),
    decipher.final(),
  ]);
  expect(padded[padded.length - 1]).toBe(0x02);
  return { recordSize, keyLength, plaintext: padded.subarray(0, padded.length - 1) };
}

function okResponse(status = 201) {
  const cancel = vi.fn().mockResolvedValue(undefined);
  const response = { status, body: { cancel } } as unknown as Response;
  return { response, cancel };
}

describe('RFC 8291 message encryption', () => {
  it('reproduces the Appendix A example byte for byte', () => {
    const body = encryptWebPushPayload(b64(RFC.plaintext), b64(RFC.uaPublic), b64(RFC.authSecret), {
      salt: b64(RFC.salt),
      senderPrivateKey: b64(RFC.asPrivate),
    });

    expect(body.subarray(0, 86).toString('base64url')).toBe(b64(RFC.header).toString('base64url'));
    expect(body.subarray(86).toString('base64url')).toBe(b64(RFC.ciphertext).toString('base64url'));
    expect(body.toString('base64url')).toBe(b64(RFC.message).toString('base64url'));
    // The sender key in the header is the RFC's application server public key.
    expect(body.subarray(21, 86).equals(b64(RFC.asPublic))).toBe(true);
  });

  it('decrypts with the RFC receiver key back to the RFC sentence', () => {
    const ua = createECDH('prime256v1');
    ua.setPrivateKey(b64(RFC.uaPrivate));
    const { plaintext } = decrypt(b64(RFC.message), ua, b64(RFC.authSecret));
    expect(plaintext.toString('utf8')).toBe('When I grow up, I want to be a watermelon');
  });

  it('round-trips a fresh message and writes the aes128gcm header', () => {
    const browser = makeBrowser();
    const message = '{"title":"Hello"}';
    const body = encryptWebPushPayload(
      Buffer.from(message),
      browser.ecdh.getPublicKey(),
      browser.auth
    );
    const result = decrypt(body, browser.ecdh, browser.auth);
    expect(result.recordSize).toBe(4096);
    expect(result.keyLength).toBe(65);
    expect(result.plaintext.toString()).toBe(message);
    // A fresh salt and sender key every time.
    const again = encryptWebPushPayload(
      Buffer.from(message),
      browser.ecdh.getPublicKey(),
      browser.auth
    );
    expect(again.subarray(0, 16).equals(body.subarray(0, 16))).toBe(false);
  });

  it('refuses bad keys and oversized messages, and fits exactly MAX_PAYLOAD_BYTES', () => {
    const browser = makeBrowser();
    const key = browser.ecdh.getPublicKey();
    expect(() => encryptWebPushPayload(Buffer.from('x'), Buffer.alloc(65), browser.auth)).toThrow();
    expect(() => encryptWebPushPayload(Buffer.from('x'), key, Buffer.alloc(8))).toThrow();
    expect(() =>
      encryptWebPushPayload(Buffer.alloc(MAX_PAYLOAD_BYTES + 1), key, browser.auth)
    ).toThrow();
    const full = encryptWebPushPayload(Buffer.alloc(MAX_PAYLOAD_BYTES), key, browser.auth);
    expect(full.length).toBe(4096);
  });
});

describe('RFC 8292 VAPID', () => {
  it('signs an ES256 JWT for the push service origin that verifies with the public key', () => {
    const vapid = makeVapid();
    const nowSec = 1_800_000_000;
    const header = vapidAuthorization('https://fcm.googleapis.com/fcm/send/abc', vapid, nowSec);
    const match = /^vapid t=([^,]+), k=([A-Za-z0-9_-]+)$/.exec(header);
    expect(match).not.toBeNull();
    const [, token, k] = match!;
    expect(k).toBe(vapid.publicKey);

    const [encodedHeader, encodedClaims, signature] = token!.split('.') as [string, string, string];
    expect(JSON.parse(Buffer.from(encodedHeader, 'base64url').toString())).toEqual({
      typ: 'JWT',
      alg: 'ES256',
    });
    const claims = JSON.parse(Buffer.from(encodedClaims, 'base64url').toString());
    expect(claims.aud).toBe('https://fcm.googleapis.com');
    expect(claims.sub).toBe('mailto:push@example.com');
    // README: tokens last 12 hours (RFC 8292 allows up to 24).
    expect(claims.exp - nowSec).toBe(12 * 60 * 60);

    const publicKeyBytes = Buffer.from(vapid.publicKey, 'base64url');
    const publicKey = createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: publicKeyBytes.subarray(1, 33).toString('base64url'),
        y: publicKeyBytes.subarray(33).toString('base64url'),
      },
      format: 'jwk',
    });
    expect(Buffer.from(signature, 'base64url')).toHaveLength(64);
    expect(
      verify(
        'sha256',
        Buffer.from(`${encodedHeader}.${encodedClaims}`),
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signature, 'base64url')
      )
    ).toBe(true);
  });

  it('reuses a token for an hour per origin', () => {
    const vapid = makeVapid();
    const first = vapidAuthorization('https://fcm.googleapis.com/a', vapid, 1000);
    expect(vapidAuthorization('https://fcm.googleapis.com/b', vapid, 1000 + 3599)).toBe(first);
    expect(vapidAuthorization('https://fcm.googleapis.com/b', vapid, 1000 + 3600)).not.toBe(first);
    expect(vapidAuthorization('https://web.push.apple.com/b', vapid, 1000)).not.toBe(first);
  });

  it('throws on mismatched keys or a bad subject', () => {
    const vapid = makeVapid();
    const other = generateVapidKeys();
    const url = 'https://fcm.googleapis.com/a';
    expect(() => vapidAuthorization(url, { ...vapid, privateKey: other.privateKey })).toThrow(
      /do not match/
    );
    expect(() => vapidAuthorization(url, { ...vapid, publicKey: 'nope' })).toThrow();
    expect(() => vapidAuthorization(url, { ...vapid, subject: 'push@example.com' })).toThrow(
      /subject/
    );
  });
});

describe('sendWebPush', () => {
  it('POSTs the encrypted body with the Web Push headers and no redirects', async () => {
    const vapid = makeVapid();
    const browser = makeBrowser();
    const { response, cancel } = okResponse(201);
    const fetchImpl = vi.fn<FetchLike>().mockResolvedValue(response);

    const result = await sendWebPush(browser.subscription, '{"title":"Hi"}', {
      vapid,
      ttl: 1800,
      urgency: 'high',
      topic: 'news',
      fetch: fetchImpl,
    });

    expect(result).toEqual({ result: 'sent', status: 201, host: 'fcm.googleapis.com' });
    expect(cancel).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(browser.subscription.endpoint);
    expect(init.method).toBe('POST');
    expect(init.redirect).toBe('error');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    const headers = init.headers as Record<string, string>;
    expect(headers.TTL).toBe('1800');
    expect(headers.Urgency).toBe('high');
    expect(headers.Topic).toBe('news');
    expect(headers['Content-Encoding']).toBe('aes128gcm');
    expect(headers['Content-Type']).toBe('application/octet-stream');
    expect(headers.Authorization).toMatch(/^vapid t=.+, k=/);
    const body = Buffer.from(init.body as Uint8Array);
    expect(decrypt(body, browser.ecdh, browser.auth).plaintext.toString()).toBe('{"title":"Hi"}');
  });

  it('uses a 4-week TTL and normal urgency by default, and accepts padded keys', async () => {
    const browser = makeBrowser();
    const fetchImpl = vi.fn<FetchLike>().mockResolvedValue(okResponse(201).response);
    const padded = {
      ...browser.subscription,
      keys: { p256dh: `${browser.subscription.keys.p256dh}=`, auth: `${browser.subscription.keys.auth}==` },
    };
    const result = await sendWebPush(padded, new Uint8Array([1, 2]), {
      vapid: makeVapid(),
      fetch: fetchImpl,
    });
    expect(result.result).toBe('sent');
    const headers = fetchImpl.mock.calls[0]![1].headers as Record<string, string>;
    expect(headers.TTL).toBe(String(28 * 24 * 60 * 60));
    expect(headers.Urgency).toBe('normal');
    expect(headers.Topic).toBeUndefined();
  });

  it('classifies every push service answer', async () => {
    const vapid = makeVapid();
    const browser = makeBrowser();
    const cases: Array<[number, string]> = [
      [201, 'sent'],
      [404, 'gone'],
      [410, 'gone'],
      [429, 'throttled'],
      [401, 'auth'],
      [403, 'auth'],
      [400, 'invalid'],
      [413, 'invalid'],
      [500, 'failed'],
      [503, 'failed'],
    ];
    for (const [status, expected] of cases) {
      const { response, cancel } = okResponse(status);
      const result = await sendWebPush(browser.subscription, '{}', {
        vapid,
        fetch: vi.fn<FetchLike>().mockResolvedValue(response),
      });
      expect(result.result).toBe(expected);
      expect(cancel).toHaveBeenCalledTimes(1);
      expect(classifyPushStatus(status)).toBe(expected);
    }
  });

  it('turns a throw or a timeout into failed', async () => {
    const vapid = makeVapid();
    const browser = makeBrowser();
    const thrown = await sendWebPush(browser.subscription, '{}', {
      vapid,
      fetch: vi.fn<FetchLike>().mockRejectedValue(new TypeError('fetch failed')),
    });
    expect(thrown).toEqual({ result: 'failed', status: null, host: 'fcm.googleapis.com' });

    const timedOut = await sendWebPush(browser.subscription, '{}', {
      vapid,
      timeoutMs: 5,
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(init.signal?.reason));
        }),
    });
    expect(timedOut.result).toBe('failed');
  });

  it('never fetches an endpoint off the allowlist, unless the caller widens it', async () => {
    const vapid = makeVapid();
    const browser = makeBrowser();
    const fetchImpl = vi.fn<FetchLike>().mockResolvedValue(okResponse(201).response);
    for (const endpoint of [
      'https://fcm.googleapis.com.evil.example.com/x',
      'http://fcm.googleapis.com/x',
      'https://fcm.googleapis.com:8443/x',
      'https://user:pass@fcm.googleapis.com/x',
      'https://169.254.169.254/latest',
      'not a url',
    ]) {
      const result = await sendWebPush({ ...browser.subscription, endpoint }, '{}', {
        vapid,
        fetch: fetchImpl,
      });
      expect(result).toEqual({ result: 'invalid', status: null, host: null });
    }
    expect(fetchImpl).not.toHaveBeenCalled();

    // A caller-run push service is allowed by its own check, but http never is.
    const allowEndpoint = (url: URL) => url.hostname === 'push.example.com';
    const own = await sendWebPush(
      { ...browser.subscription, endpoint: 'https://push.example.com/s/1' },
      '{}',
      { vapid, fetch: fetchImpl, allowEndpoint }
    );
    expect(own).toEqual({ result: 'sent', status: 201, host: 'push.example.com' });
    const plain = await sendWebPush(
      { ...browser.subscription, endpoint: 'http://push.example.com/s/1' },
      '{}',
      { vapid, fetch: fetchImpl, allowEndpoint: () => true }
    );
    expect(plain.result).toBe('invalid');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('knows the major push services', () => {
    for (const endpoint of [
      'https://fcm.googleapis.com/fcm/send/x',
      'https://updates.push.services.mozilla.com/wpush/v2/x',
      'https://web.push.apple.com/x',
      'https://wns2-par02p.notify.windows.com/w/?token=x',
    ]) {
      expect(isKnownPushService(new URL(endpoint))).toBe(true);
    }
    expect(isKnownPushService(new URL('https://push.example.com/x'))).toBe(false);
  });

  it('treats unreadable browser keys and oversized payloads as invalid without fetching', async () => {
    const vapid = makeVapid();
    const browser = makeBrowser();
    const fetchImpl = vi.fn<FetchLike>();
    const badKey = await sendWebPush(
      { ...browser.subscription, keys: { ...browser.subscription.keys, p256dh: 'not-a-key' } },
      '{}',
      { vapid, fetch: fetchImpl }
    );
    expect(badKey.result).toBe('invalid');
    const tooLong = await sendWebPush(browser.subscription, 'x'.repeat(MAX_PAYLOAD_BYTES + 1), {
      vapid,
      fetch: fetchImpl,
    });
    expect(tooLong.result).toBe('invalid');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('throws on bad VAPID options instead of reporting every send as invalid', async () => {
    const browser = makeBrowser();
    const fetchImpl = vi.fn<FetchLike>();
    await expect(
      sendWebPush(browser.subscription, '{}', {
        vapid: { ...makeVapid(), subject: 'nobody' },
        fetch: fetchImpl,
      })
    ).rejects.toThrow(TypeError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

describe('package promises', () => {
  it('has no runtime dependencies and is ESM only', () => {
    expect(pkg.dependencies).toBeUndefined();
    expect(pkg.peerDependencies).toBeUndefined();
    expect(pkg.type).toBe('module');
    expect(MAX_PAYLOAD_BYTES).toBe(3993);
  });

  it('generates key pairs that sign and verify, and are fresh every time', () => {
    const a = generateVapidKeys();
    const b = generateVapidKeys();
    expect(Buffer.from(a.publicKey, 'base64url')).toHaveLength(65);
    expect(Buffer.from(a.privateKey, 'base64url')).toHaveLength(32);
    expect(a.privateKey).not.toBe(b.privateKey);
    expect(() =>
      vapidAuthorization('https://fcm.googleapis.com/a', { ...a, subject: 'https://example.com' })
    ).not.toThrow();
  });
});

describe('CLI', () => {
  function run(args: string[], color = false) {
    let out = '';
    let err = '';
    const code = runCli(args, { out: (t) => (out += t), err: (t) => (err += t), color });
    return { code, out, err };
  }

  it('prints a matching key pair as .env lines, with nothing else on stdout', () => {
    const { code, out, err } = run(['keys']);
    expect(code).toBe(0);
    expect(err).toBe('');
    const match = /^VAPID_PUBLIC_KEY=([\w-]+)\nVAPID_PRIVATE_KEY=([\w-]+)\n$/.exec(out);
    expect(match).not.toBeNull();
    const [, publicKey, privateKey] = match!;
    expect(() =>
      vapidAuthorization('https://fcm.googleapis.com/a', {
        publicKey: publicKey!,
        privateKey: privateKey!,
        subject: 'mailto:push@example.com',
      })
    ).not.toThrow();
  });

  it('shows help and the version', () => {
    for (const args of [[], ['--help'], ['-h']]) {
      const { code, out } = run(args);
      expect(code).toBe(0);
      expect(out).toContain('tiny-web-push keys');
      expect(out).toContain('Examples');
    }
    expect(run(['--version']).out).toBe(`${pkg.version}\n`);
    expect(run(['-v']).code).toBe(0);
  });

  it('uses colour only in a terminal without NO_COLOR, and never in the key lines', () => {
    expect(shouldUseColor(true, {})).toBe(true);
    expect(shouldUseColor(false, {})).toBe(false);
    expect(shouldUseColor(undefined, {})).toBe(false);
    expect(shouldUseColor(true, { NO_COLOR: '1' })).toBe(false);
    expect(run(['--help']).out).not.toContain('\u001b[');
    const colored = run(['keys'], true);
    expect(colored.out).not.toContain('\u001b[');
    expect(colored.err).toContain('Keep the private key secret');
  });

  it('explains a usage error and exits 2', () => {
    const unknown = run(['nope']);
    expect(unknown.code).toBe(2);
    expect(unknown.out).toBe('');
    expect(unknown.err).toContain('unknown command "nope"');
    expect(unknown.err).toContain('--help');
    expect(run(['keys', 'extra']).err).toContain('unexpected argument "extra"');
  });
});
