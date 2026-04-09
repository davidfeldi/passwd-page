// API client for passwd.page backend

const API_BASE = '/api';

export interface CreateSecretResponse {
	id: string;
	expiresAt: string;
}

export interface GetSecretResponse {
	ciphertext: string;
	burnAfterRead: boolean;
}

/**
 * Create a new encrypted secret on the server.
 * The server only stores ciphertext — the key never leaves the client.
 */
export async function createSecret(
	ciphertext: string,
	expiresIn: string,
	burnAfterRead: boolean
): Promise<CreateSecretResponse> {
	const res = await fetch(`${API_BASE}/secrets`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ ciphertext, expiresIn, burnAfterRead })
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

	return res.json();
}
