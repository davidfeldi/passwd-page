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
