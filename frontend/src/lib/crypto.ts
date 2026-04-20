// Client-side encryption/decryption using Web Crypto API only — NO external crypto libraries

const AES_GCM = 'AES-GCM';
const KEY_LENGTH = 256;
const IV_LENGTH = 12; // 96 bits

// --- Base64url helpers (no padding, URL-safe) ---

function toBase64url(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = '';
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64url(b64: string): ArrayBuffer {
	// Restore standard base64
	const padded = b64.replace(/-/g, '+').replace(/_/g, '/');
	const paddingNeeded = (4 - (padded.length % 4)) % 4;
	const base64 = padded + '='.repeat(paddingNeeded);
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer;
}

// --- Key generation and management ---

/**
 * Generate a 256-bit AES-GCM key using crypto.subtle.generateKey
 */
export async function generateKey(): Promise<CryptoKey> {
	return crypto.subtle.generateKey(
		{ name: AES_GCM, length: KEY_LENGTH },
		true, // extractable — needed for exporting to URL fragment
		['encrypt', 'decrypt']
	);
}

/**
 * Export a CryptoKey as raw bytes, base64url encoded
 */
export async function keyToBase64url(key: CryptoKey): Promise<string> {
	const raw = await crypto.subtle.exportKey('raw', key);
	return toBase64url(raw);
}

/**
 * Import a base64url-encoded string as an AES-GCM CryptoKey
 */
export async function base64urlToKey(b64: string): Promise<CryptoKey> {
	const raw = fromBase64url(b64);
	return crypto.subtle.importKey('raw', raw, { name: AES_GCM, length: KEY_LENGTH }, true, [
		'encrypt',
		'decrypt'
	]);
}

// --- Encrypt / Decrypt ---

/**
 * Encrypt plaintext with AES-GCM.
 *
 * 1. Generate random 96-bit IV (12 bytes) via crypto.getRandomValues
 * 2. Encode plaintext to UTF-8
 * 3. Encrypt with AES-GCM (key, iv, plaintext)
 * 4. Concatenate: IV (12 bytes) + ciphertext (includes GCM auth tag)
 * 5. Return base64url encoded string
 */
export async function encrypt(plaintext: string, key: CryptoKey): Promise<string> {
	const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
	const encoded = new TextEncoder().encode(plaintext);

	const ciphertext = await crypto.subtle.encrypt({ name: AES_GCM, iv }, key, encoded);

	// Concatenate IV + ciphertext (ciphertext already includes GCM auth tag)
	const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
	combined.set(iv, 0);
	combined.set(new Uint8Array(ciphertext), IV_LENGTH);

	return toBase64url(combined.buffer);
}

/**
 * Decrypt a base64url-encoded ciphertext with AES-GCM.
 *
 * 1. base64url decode
 * 2. Extract IV (first 12 bytes) and ciphertext (rest)
 * 3. Decrypt with AES-GCM
 * 4. Decode UTF-8 and return plaintext
 */
export async function decrypt(encoded: string, key: CryptoKey): Promise<string> {
	const combined = new Uint8Array(fromBase64url(encoded));

	if (combined.byteLength <= IV_LENGTH) {
		throw new Error('Invalid ciphertext: too short');
	}

	const iv = combined.slice(0, IV_LENGTH);
	const ciphertext = combined.slice(IV_LENGTH);

	const plaintext = await crypto.subtle.decrypt({ name: AES_GCM, iv }, key, ciphertext);

	return new TextDecoder().decode(plaintext);
}

// --- Passphrase wrapping (v2 envelope) ---
//
// Stacked encryption:
//   inner_key   = random 256-bit AES-GCM key (still lives in URL fragment)
//   inner_ct    = AES-256-GCM(inner_key, plaintext)
//   pass_key    = PBKDF2-SHA256(passphrase, salt, 600_000 iters) -> 256-bit
//   wrapped_key = AES-256-GCM(pass_key, raw(inner_key))     // iv || ct || tag
//
// The passphrase never leaves the browser. Server only sees the JSON envelope
// string; it has no way to unwrap without the passphrase.

export const KDF_ID = 'pbkdf2-sha256-600k';
export const KDF_ITERATIONS = 600_000;
export const SALT_LENGTH = 16;

export type EnvelopeV2 = {
	v: 2;
	inner_ct: string; // base64url of IV || ct || tag (the inner AES-GCM output)
	salt: string; // base64url of the PBKDF2 salt (16 bytes)
	kdf: typeof KDF_ID;
	wrapped_key: string; // base64url of IV || ct || tag for the wrapped inner key
};

export function base64urlEncodeBytes(bytes: Uint8Array): string {
	return toBase64url(
		bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
	);
}

export function base64urlDecodeBytes(b64: string): Uint8Array {
	return new Uint8Array(fromBase64url(b64));
}

/**
 * Derive a 256-bit AES-GCM key from a passphrase via PBKDF2-SHA256.
 * Returns a non-extractable CryptoKey usable for encrypt/decrypt.
 */
export async function deriveKeyFromPassphrase(
	passphrase: string,
	salt: Uint8Array,
	iterations: number = KDF_ITERATIONS
): Promise<CryptoKey> {
	const passBytes = new TextEncoder().encode(passphrase);
	const baseKey = await crypto.subtle.importKey(
		'raw',
		passBytes,
		{ name: 'PBKDF2' },
		false,
		['deriveBits', 'deriveKey']
	);
	return crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: salt as BufferSource,
			iterations,
			hash: 'SHA-256'
		},
		baseKey,
		{ name: AES_GCM, length: KEY_LENGTH },
		false, // not extractable — no need to export derived key
		['encrypt', 'decrypt']
	);
}

/**
 * Wrap the inner (random) key with a passphrase-derived key.
 * Accepts either a CryptoKey (extractable) or raw 32 bytes.
 * Returns the IV used and the wrapped ciphertext (including GCM tag).
 */
export async function wrapInnerKey(
	innerKey: CryptoKey | Uint8Array,
	passphraseKey: CryptoKey
): Promise<{ iv: Uint8Array; wrapped: Uint8Array }> {
	let raw: Uint8Array;
	if (innerKey instanceof Uint8Array) {
		raw = innerKey;
	} else {
		const buf = await crypto.subtle.exportKey('raw', innerKey);
		raw = new Uint8Array(buf);
	}
	const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
	const ct = await crypto.subtle.encrypt(
		{ name: AES_GCM, iv },
		passphraseKey,
		raw as BufferSource
	);
	return { iv, wrapped: new Uint8Array(ct) };
}

/**
 * Unwrap an inner key with the passphrase-derived key.
 * Throws on GCM authentication failure (wrong passphrase).
 */
export async function unwrapInnerKey(
	wrapped: Uint8Array,
	iv: Uint8Array,
	passphraseKey: CryptoKey
): Promise<CryptoKey> {
	const raw = await crypto.subtle.decrypt(
		{ name: AES_GCM, iv },
		passphraseKey,
		wrapped as BufferSource
	);
	return crypto.subtle.importKey(
		'raw',
		raw,
		{ name: AES_GCM, length: KEY_LENGTH },
		true,
		['encrypt', 'decrypt']
	);
}

/**
 * Build a v2 envelope JSON string given an already-encrypted inner ciphertext
 * and a wrapped inner key.
 */
export function buildEnvelopeV2(
	innerCtBase64url: string,
	salt: Uint8Array,
	wrappedIv: Uint8Array,
	wrapped: Uint8Array
): string {
	// Pack iv || ct || tag as a single blob for the wrapped_key field (GCM
	// output already includes the tag at the end of ct; we just prepend iv).
	const combined = new Uint8Array(wrappedIv.byteLength + wrapped.byteLength);
	combined.set(wrappedIv, 0);
	combined.set(wrapped, wrappedIv.byteLength);
	const envelope: EnvelopeV2 = {
		v: 2,
		inner_ct: innerCtBase64url,
		salt: base64urlEncodeBytes(salt),
		kdf: KDF_ID,
		wrapped_key: base64urlEncodeBytes(combined)
	};
	return JSON.stringify(envelope);
}

/**
 * Narrow-test whether a string parses as a v2 passphrase envelope.
 * Returns the parsed envelope or null (for any deviation — plain ciphertext,
 * file envelope plaintext, malformed JSON, wrong version).
 */
export function tryParseEnvelopeV2(text: string): EnvelopeV2 | null {
	try {
		const obj = JSON.parse(text);
		if (
			obj &&
			typeof obj === 'object' &&
			obj.v === 2 &&
			typeof obj.inner_ct === 'string' &&
			typeof obj.salt === 'string' &&
			typeof obj.wrapped_key === 'string' &&
			typeof obj.kdf === 'string'
		) {
			return obj as EnvelopeV2;
		}
	} catch {
		// not JSON — plain ciphertext
	}
	return null;
}

/**
 * Split the packed wrapped_key field (IV || ct || tag) into its components.
 */
export function splitWrappedKey(
	wrappedBase64url: string
): { iv: Uint8Array; wrapped: Uint8Array } {
	const bytes = base64urlDecodeBytes(wrappedBase64url);
	if (bytes.byteLength <= IV_LENGTH) {
		throw new Error('Invalid wrapped_key: too short');
	}
	return {
		iv: bytes.slice(0, IV_LENGTH),
		wrapped: bytes.slice(IV_LENGTH)
	};
}
