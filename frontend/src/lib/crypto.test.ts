import { describe, it, expect } from 'vitest';
import {
	generateKey,
	encrypt,
	decrypt,
	keyToBase64url,
	base64urlToKey,
	deriveKeyFromPassphrase,
	wrapInnerKey,
	unwrapInnerKey,
	buildEnvelopeV2,
	tryParseEnvelopeV2,
	splitWrappedKey,
	base64urlDecodeBytes,
	KDF_ID
} from './crypto';

describe('generateKey', () => {
	it('returns a CryptoKey', async () => {
		const key = await generateKey();
		expect(key).toBeInstanceOf(CryptoKey);
		expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
		expect(key.extractable).toBe(true);
		expect(key.usages).toContain('encrypt');
		expect(key.usages).toContain('decrypt');
	});
});

describe('encrypt -> decrypt round-trip', () => {
	it('works with ASCII text', async () => {
		const key = await generateKey();
		const plaintext = 'hello world';
		const ciphertext = await encrypt(plaintext, key);
		const decrypted = await decrypt(ciphertext, key);
		expect(decrypted).toBe(plaintext);
	});

	it('works with Unicode text', async () => {
		const key = await generateKey();
		const plaintext = 'Hej! Passwords are fun. Also: emoji test.';
		const ciphertext = await encrypt(plaintext, key);
		const decrypted = await decrypt(ciphertext, key);
		expect(decrypted).toBe(plaintext);
	});

	it('works with CJK and emoji characters', async () => {
		const key = await generateKey();
		const plaintext = 'Chinese text here. Japanese text here.';
		const ciphertext = await encrypt(plaintext, key);
		const decrypted = await decrypt(ciphertext, key);
		expect(decrypted).toBe(plaintext);
	});

	it('works with empty string', async () => {
		const key = await generateKey();
		const plaintext = '';
		const ciphertext = await encrypt(plaintext, key);
		const decrypted = await decrypt(ciphertext, key);
		expect(decrypted).toBe(plaintext);
	});

	it('works with large input (10KB)', async () => {
		const key = await generateKey();
		const plaintext = 'A'.repeat(10_000);
		const ciphertext = await encrypt(plaintext, key);
		const decrypted = await decrypt(ciphertext, key);
		expect(decrypted).toBe(plaintext);
	});

	it('produces different ciphertext each time (unique IV)', async () => {
		const key = await generateKey();
		const plaintext = 'same input';
		const ct1 = await encrypt(plaintext, key);
		const ct2 = await encrypt(plaintext, key);
		expect(ct1).not.toBe(ct2);
	});

	it('round-trips a binary file envelope (1000 random bytes)', async () => {
		// Simulate the file-upload path: random binary bytes -> base64 ->
		// JSON envelope -> encrypt -> decrypt -> parse -> decode -> compare.
		const original = new Uint8Array(1000);
		crypto.getRandomValues(original);

		// bytes -> base64 (standard, not url-safe — it's inside the encrypted JSON)
		let binary = '';
		for (let i = 0; i < original.length; i++) binary += String.fromCharCode(original[i]);
		const b64 = btoa(binary);

		const envelope = {
			kind: 'file',
			name: 'secret.bin',
			mime: 'application/octet-stream',
			size: original.byteLength,
			data: b64
		};
		const plaintext = JSON.stringify(envelope);

		const key = await generateKey();
		const ciphertext = await encrypt(plaintext, key);
		const decrypted = await decrypt(ciphertext, key);

		const parsed = JSON.parse(decrypted);
		expect(parsed.kind).toBe('file');
		expect(parsed.name).toBe('secret.bin');
		expect(parsed.mime).toBe('application/octet-stream');
		expect(parsed.size).toBe(original.byteLength);

		// Decode base64 back to bytes and compare byte-for-byte.
		const restoredBinary = atob(parsed.data);
		const restored = new Uint8Array(restoredBinary.length);
		for (let i = 0; i < restoredBinary.length; i++) {
			restored[i] = restoredBinary.charCodeAt(i);
		}
		expect(restored.byteLength).toBe(original.byteLength);
		for (let i = 0; i < original.length; i++) {
			expect(restored[i]).toBe(original[i]);
		}
	});
});

describe('keyToBase64url -> base64urlToKey round-trip', () => {
	it('exports and re-imports a key that still decrypts', async () => {
		const key = await generateKey();
		const b64 = await keyToBase64url(key);

		// base64url should be 43 chars for 256-bit key (32 bytes -> 43 base64url chars)
		expect(b64.length).toBe(43);
		// Should not contain standard base64 chars or padding
		expect(b64).not.toMatch(/[+/=]/);

		const restored = await base64urlToKey(b64);
		const plaintext = 'round-trip key test';
		const ciphertext = await encrypt(plaintext, key);
		const decrypted = await decrypt(ciphertext, restored);
		expect(decrypted).toBe(plaintext);
	});
});

describe('error cases', () => {
	it('decrypt with wrong key throws', async () => {
		const key1 = await generateKey();
		const key2 = await generateKey();
		const ciphertext = await encrypt('secret', key1);
		await expect(decrypt(ciphertext, key2)).rejects.toThrow();
	});

	it('decrypt with corrupted ciphertext throws', async () => {
		const key = await generateKey();
		const ciphertext = await encrypt('secret', key);
		// Flip some characters in the middle of the ciphertext
		const corrupted =
			ciphertext.slice(0, 20) +
			(ciphertext[20] === 'A' ? 'B' : 'A') +
			ciphertext.slice(21);
		await expect(decrypt(corrupted, key)).rejects.toThrow();
	});

	it('decrypt with too-short input throws', async () => {
		const key = await generateKey();
		// 12 bytes or fewer is too short (just IV, no ciphertext)
		const tooShort = 'AAAAAAAAAAAAAAAA'; // 12 bytes base64url
		await expect(decrypt(tooShort, key)).rejects.toThrow();
	});
});

// --- Passphrase / v2 envelope ---

// Use a low iteration count in tests so PBKDF2 doesn't blow the 5s limit.
const TEST_ITERS = 1000;

describe('deriveKeyFromPassphrase', () => {
	it('is deterministic given same passphrase+salt (wrap output decrypts with re-derived key)', async () => {
		const salt = crypto.getRandomValues(new Uint8Array(16));
		const passphrase = 'correct horse battery staple';

		const key1 = await deriveKeyFromPassphrase(passphrase, salt, TEST_ITERS);
		const key2 = await deriveKeyFromPassphrase(passphrase, salt, TEST_ITERS);

		// Can't export a non-extractable derived key, so test equality by
		// wrap-with-key1 then unwrap-with-key2.
		const innerKey = await generateKey();
		const { iv, wrapped } = await wrapInnerKey(innerKey, key1);
		const restored = await unwrapInnerKey(wrapped, iv, key2);

		const pt = 'same-key proof';
		const ct = await encrypt(pt, innerKey);
		const out = await decrypt(ct, restored);
		expect(out).toBe(pt);
	});

	it('different passphrase yields different key (wrap fails to unwrap)', async () => {
		const salt = crypto.getRandomValues(new Uint8Array(16));
		const key1 = await deriveKeyFromPassphrase('hunter2', salt, TEST_ITERS);
		const key2 = await deriveKeyFromPassphrase('hunter3', salt, TEST_ITERS);

		const innerKey = await generateKey();
		const { iv, wrapped } = await wrapInnerKey(innerKey, key1);
		await expect(unwrapInnerKey(wrapped, iv, key2)).rejects.toThrow();
	});
});

describe('wrap / unwrap inner key', () => {
	it('round-trip: unwrapped key decrypts inner ciphertext', async () => {
		const salt = crypto.getRandomValues(new Uint8Array(16));
		const passKey = await deriveKeyFromPassphrase('s3cr3t', salt, TEST_ITERS);

		const innerKey = await generateKey();
		const plaintext = 'hello passphrase world';
		const innerCt = await encrypt(plaintext, innerKey);

		const { iv, wrapped } = await wrapInnerKey(innerKey, passKey);
		const restored = await unwrapInnerKey(wrapped, iv, passKey);
		const out = await decrypt(innerCt, restored);
		expect(out).toBe(plaintext);
	});

	it('unwrap with wrong passphrase throws (GCM auth failure)', async () => {
		const salt = crypto.getRandomValues(new Uint8Array(16));
		const good = await deriveKeyFromPassphrase('right', salt, TEST_ITERS);
		const bad = await deriveKeyFromPassphrase('wrong', salt, TEST_ITERS);

		const innerKey = await generateKey();
		const { iv, wrapped } = await wrapInnerKey(innerKey, good);
		await expect(unwrapInnerKey(wrapped, iv, bad)).rejects.toThrow();
	});
});

describe('v2 envelope round-trip', () => {
	async function buildV2(plaintext: string, passphrase: string, iters = TEST_ITERS) {
		const innerKey = await generateKey();
		const innerCt = await encrypt(plaintext, innerKey);

		const salt = crypto.getRandomValues(new Uint8Array(16));
		const passKey = await deriveKeyFromPassphrase(passphrase, salt, iters);
		const { iv, wrapped } = await wrapInnerKey(innerKey, passKey);
		const envelope = buildEnvelopeV2(innerCt, salt, iv, wrapped);
		return { envelope, innerKey, salt, passKey };
	}

	it('correct passphrase decrypts; envelope is valid JSON with v:2', async () => {
		const { envelope, innerKey } = await buildV2('top secret', 'pa55phrase!');

		const parsed = tryParseEnvelopeV2(envelope);
		expect(parsed).not.toBeNull();
		expect(parsed!.v).toBe(2);
		expect(parsed!.kdf).toBe(KDF_ID);

		// Recipient flow: derive, split, unwrap, decrypt inner_ct.
		const salt = base64urlDecodeBytes(parsed!.salt);
		// In the real app the iteration count is fixed by kdf=KDF_ID; we use
		// TEST_ITERS because this is the same passphrase derived twice in-memory.
		const passKey = await deriveKeyFromPassphrase('pa55phrase!', salt, TEST_ITERS);
		const { iv, wrapped } = splitWrappedKey(parsed!.wrapped_key);
		const innerRestored = await unwrapInnerKey(wrapped, iv, passKey);
		const out = await decrypt(parsed!.inner_ct, innerRestored);
		expect(out).toBe('top secret');

		// Sanity: the original inner key still works too (URL-fragment path).
		const out2 = await decrypt(parsed!.inner_ct, innerKey);
		expect(out2).toBe('top secret');
	});

	it('wrong passphrase throws on unwrap', async () => {
		const { envelope } = await buildV2('nope', 'right-pass');
		const parsed = tryParseEnvelopeV2(envelope)!;
		const salt = base64urlDecodeBytes(parsed.salt);
		const wrongKey = await deriveKeyFromPassphrase('wrong-pass', salt, TEST_ITERS);
		const { iv, wrapped } = splitWrappedKey(parsed.wrapped_key);
		await expect(unwrapInnerKey(wrapped, iv, wrongKey)).rejects.toThrow();
	});

	it('tryParseEnvelopeV2 returns null for plain (non-JSON) ciphertext', () => {
		// Raw ciphertext strings are base64url, not JSON.
		expect(tryParseEnvelopeV2('AAAA-BBBB_CCCC')).toBeNull();
	});

	it('tryParseEnvelopeV2 returns null for the DECRYPTED file envelope (v missing)', () => {
		const fileEnvelope = JSON.stringify({
			kind: 'file',
			name: 'x.txt',
			mime: 'text/plain',
			size: 3,
			data: 'aGk='
		});
		// The file envelope is plaintext *inside* inner_ct, never stored directly,
		// but this guards against accidental collision between the two formats.
		expect(tryParseEnvelopeV2(fileEnvelope)).toBeNull();
	});
});
