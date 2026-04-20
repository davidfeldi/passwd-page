// API client for passwd.page backend

const API_BASE = '/api';

export type SecretType =
	| 'text'
	| 'file'
	| 'postgres_url'
	| 'api_key'
	| 'ssh_key'
	| 'env_file'
	| 'jwt'
	| 'oauth_token';

export const SECRET_TYPES: SecretType[] = [
	'text',
	'file',
	'postgres_url',
	'api_key',
	'ssh_key',
	'env_file',
	'jwt',
	'oauth_token'
];

export interface CreateSecretResponse {
	id: string;
	expiresAt: string;
}

export interface GetSecretResponse {
	ciphertext: string;
	burnAfterRead: boolean;
	type: SecretType;
}

/**
 * Create a new encrypted secret on the server.
 * The server only stores ciphertext — the key never leaves the client.
 * `type` is an optional schema hint for receiving agents.
 */
export async function createSecret(
	ciphertext: string,
	expiresIn: string,
	burnAfterRead: boolean,
	type: SecretType = 'text'
): Promise<CreateSecretResponse> {
	const res = await fetch(`${API_BASE}/secrets`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ ciphertext, expiresIn, burnAfterRead, type })
	});

	if (!res.ok) {
		const body = await res.text();
		throw new Error(`Failed to create secret: ${res.status} ${body}`);
	}

	return res.json();
}

/**
 * Retrieve an encrypted secret by ID.
 * If burnAfterRead is true, the server deletes the secret after this call.
 */
export async function getSecret(id: string): Promise<GetSecretResponse> {
	const res = await fetch(`${API_BASE}/secrets/${encodeURIComponent(id)}`);

	if (res.status === 404) {
		throw new Error('Secret not found or already burned');
	}

	if (!res.ok) {
		const body = await res.text();
		throw new Error(`Failed to get secret: ${res.status} ${body}`);
	}

	const raw = await res.json();
	// Backwards compat: coerce missing/unknown type to "text".
	const t: SecretType =
		raw && typeof raw.type === 'string' && (SECRET_TYPES as string[]).includes(raw.type)
			? (raw.type as SecretType)
			: 'text';
	return {
		ciphertext: raw.ciphertext,
		burnAfterRead: !!raw.burnAfterRead,
		type: t
	};
}
