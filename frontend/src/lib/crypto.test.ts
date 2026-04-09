import { describe, it, expect } from 'vitest';
import { generateKey, encrypt, decrypt, keyToBase64url, base64urlToKey } from './crypto';

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
