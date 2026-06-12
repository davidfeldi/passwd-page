<script lang="ts">
	import { page } from '$app/stores';
	import {
		base64urlToKey,
		decrypt,
		tryParseEnvelopeV2,
		deriveKeyFromPassphrase,
		unwrapInnerKey,
		splitWrappedKey,
		base64urlDecodeBytes,
		type EnvelopeV2
	} from '$lib/crypto';
	import { getSecret, type SecretType } from '$lib/api';

	type FilePayload = {
		kind: 'file';
		name: string;
		mime: string;
		size: number;
		data: string; // base64
	};

	type ViewState =
		| { kind: 'ready' }
		| { kind: 'loading' }
		| {
				kind: 'passphrase';
				envelope: EnvelopeV2;
				innerKey: CryptoKey;
				burnAfterRead: boolean;
				type: SecretType;
		  }
		| {
				kind: 'revealed';
				secret: string;
				burnAfterRead: boolean;
				expiresAt?: string;
				file: FilePayload | null;
				type: SecretType;
		  }
		| { kind: 'error'; code: 'not-found' | 'invalid-link' | 'decrypt-failed' | 'server-error' };

	// Small human-friendly labels per type. Falls back to the raw value.
	const typeLabels: Record<SecretType, string> = {
		text: 'text',
		file: 'file',
		postgres_url: 'Postgres URL',
		api_key: 'API key',
		ssh_key: 'SSH key',
		env_file: '.env file',
		jwt: 'JWT',
		oauth_token: 'OAuth token'
	};

	let state: ViewState = $state({ kind: 'ready' });
	let copied = $state(false);
	let passphraseInput = $state('');
	let passphraseError = $state('');
	let unlocking = $state(false);

	function formatBytes(n: number): string {
		if (n < 1024) return `${n} B`;
		if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
		return `${(n / 1024 / 1024).toFixed(2)} MiB`;
	}

	function tryParseFileEnvelope(text: string): FilePayload | null {
		try {
			const obj = JSON.parse(text);
			if (
				obj &&
				typeof obj === 'object' &&
				obj.kind === 'file' &&
				typeof obj.name === 'string' &&
				typeof obj.mime === 'string' &&
				typeof obj.data === 'string'
			) {
				return obj as FilePayload;
			}
		} catch {
			// Not JSON — treat as plain text.
		}
		return null;
	}

	function downloadFile() {
		if (state.kind !== 'revealed' || !state.file) return;
		const f = state.file;
		try {
			const binary = atob(f.data);
			const bytes = new Uint8Array(binary.length);
			for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
			const blob = new Blob([bytes], { type: f.mime || 'application/octet-stream' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = f.name;
			document.body.appendChild(a);
			a.click();
			a.remove();
			setTimeout(() => URL.revokeObjectURL(url), 1000);
		} catch {
			// decoding failure: ignore — UI still offers retry via re-click.
		}
	}

	async function handleReveal() {
		const keyStr = window.location.hash.slice(1);
		if (!keyStr) {
			state = { kind: 'error', code: 'invalid-link' };
			return;
		}

		const id = $page.params.id;
		state = { kind: 'loading' };

		try {
			let key: CryptoKey;
			try {
				key = await base64urlToKey(keyStr);
			} catch {
				state = { kind: 'error', code: 'invalid-link' };
				return;
			}

			let res: Awaited<ReturnType<typeof getSecret>>;
			try {
				res = await getSecret(id);
			} catch (e: any) {
				if (e?.message?.includes('not found') || e?.message?.includes('burned')) {
					state = { kind: 'error', code: 'not-found' };
				} else {
					state = { kind: 'error', code: 'server-error' };
				}
				return;
			}

			// Check for v2 passphrase envelope. The stored ciphertext is normally
			// a base64url blob, but for v2 it's a JSON string with { v: 2, ... }.
			// Note: the file envelope lives INSIDE the inner plaintext, not here —
			// tryParseEnvelopeV2 rejects non-v2 JSON so the two formats cannot
			// collide.
			const envelope = tryParseEnvelopeV2(res.ciphertext);
			if (envelope) {
				state = {
					kind: 'passphrase',
					envelope,
					innerKey: key,
					burnAfterRead: res.burnAfterRead,
					type: res.type
				};
				return;
			}

			let plaintext: string;
			try {
				plaintext = await decrypt(res.ciphertext, key);
			} catch {
				state = { kind: 'error', code: 'decrypt-failed' };
				return;
			}

			const file = tryParseFileEnvelope(plaintext);
			state = {
				kind: 'revealed',
				secret: plaintext,
				burnAfterRead: res.burnAfterRead,
				file,
				type: res.type
			};
		} catch {
			state = { kind: 'error', code: 'server-error' };
		}
	}

	async function handleUnlock() {
		if (state.kind !== 'passphrase') return;
		if (passphraseInput.length === 0) return;
		unlocking = true;
		passphraseError = '';
		try {
			const env = state.envelope;
			const salt = base64urlDecodeBytes(env.salt);
			const passKey = await deriveKeyFromPassphrase(passphraseInput, salt);
			const { iv, wrapped } = splitWrappedKey(env.wrapped_key);

			let innerKey: CryptoKey;
			try {
				innerKey = await unwrapInnerKey(wrapped, iv, passKey);
			} catch {
				passphraseError =
					'Wrong passphrase. Note: this secret may have already been consumed by the server (burn-after-read). If you cannot unlock it, the secret is lost.';
				unlocking = false;
				return;
			}

			let plaintext: string;
			try {
				plaintext = await decrypt(env.inner_ct, innerKey);
			} catch {
				// Inner GCM failed even though unwrap succeeded — link/envelope corruption.
				state = { kind: 'error', code: 'decrypt-failed' };
				return;
			}

			const file = tryParseFileEnvelope(plaintext);
			const burn = state.burnAfterRead;
			const revealedType = state.type;
			passphraseInput = '';
			state = {
				kind: 'revealed',
				secret: plaintext,
				burnAfterRead: burn,
				file,
				type: revealedType
			};
		} catch {
			passphraseError = 'Unlock failed. Please try again.';
		} finally {
			unlocking = false;
		}
	}

	async function copySecret() {
		if (state.kind !== 'revealed') return;
		try {
			await navigator.clipboard.writeText(state.secret);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch {
			// fallback: do nothing
		}
	}

	const errorMessages: Record<string, { icon: string; title: string; detail: string }> = {
		'not-found': {
			icon: '\u26A0',
			title: 'Secret not found',
			detail: 'This secret no longer exists. It may have been viewed already or expired.'
		},
		'invalid-link': {
			icon: '\u26D4',
			title: 'Invalid link',
			detail: 'The decryption key is missing from the URL.'
		},
		'decrypt-failed': {
			icon: '\u2716',
			title: 'Decryption failed',
			detail: 'Could not decrypt this secret. The link may be corrupted.'
		},
		'server-error': {
			icon: '\u26A1',
			title: 'Something went wrong',
			detail: 'Something went wrong. Please try again.'
		}
	};
</script>

<svelte:head>
	<title>passwd.page — View secret</title>
	<meta name="description" content="View a shared secret securely." />
</svelte:head>

<main>
	<div class="container">
		<header>
			<div class="brand-pill">
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#18E299" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
					<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
					<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
				</svg>
				<span class="brand-name">passwd.page</span>
			</div>
		</header>

		{#if state.kind === 'ready'}
			<div class="ready">
				<p class="ready-msg">Someone shared a secret with you.</p>
				<button type="button" class="btn-reveal" onclick={handleReveal}>
					Reveal Secret
				</button>
			</div>

		{:else if state.kind === 'loading'}
			<div class="loading-state">
				<span class="spinner" aria-hidden="true"></span>
				<p>Decrypting...</p>
			</div>

		{:else if state.kind === 'passphrase'}
			<div class="passphrase-prompt" role="group" aria-label="Passphrase required">
				<p class="passphrase-title">Passphrase required</p>
				<p class="passphrase-sub">
					The sender protected this secret with a passphrase. Enter it to unlock.
				</p>
				<form
					onsubmit={(e) => {
						e.preventDefault();
						handleUnlock();
					}}
				>
					<label for="unlock-input" class="sr-only">Passphrase</label>
					<input
						id="unlock-input"
						type="password"
						bind:value={passphraseInput}
						placeholder="Enter passphrase"
						autocomplete="off"
						disabled={unlocking}
					/>
					<button
						type="submit"
						class="btn-unlock"
						disabled={unlocking || passphraseInput.length === 0}
					>
						{#if unlocking}
							<span class="spinner-sm" aria-hidden="true"></span>
							Deriving key...
						{:else}
							Unlock
						{/if}
					</button>
				</form>
				{#if passphraseError}
					<p class="passphrase-err" role="alert">{passphraseError}</p>
				{/if}
			</div>

		{:else if state.kind === 'revealed'}
			<div class="revealed" role="status">
				<div class="type-label" aria-label="Secret type">
					<span class="type-dot" aria-hidden="true"></span>
					<span>{typeLabels[state.type] ?? state.type}</span>
				</div>
				{#if state.file}
					<div class="secret-card file-card">
						<div class="file-info">
							<p class="file-line">
								<strong>File:</strong> {state.file.name}
								<span class="file-meta">({state.file.mime}, {formatBytes(state.file.size)})</span>
							</p>
						</div>
						<button type="button" class="btn-download" onclick={downloadFile}>
							Download {state.file.name}
						</button>
					</div>
				{:else}
					<div class="secret-card">
						<pre class="secret-text">{state.secret}</pre>
						<button type="button" class="btn-copy" class:copied onclick={copySecret}>
							{#if copied}
								<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
								Copied!
							{:else}
								Copy
							{/if}
						</button>
					</div>
				{/if}
				<div class="warning-box" class:burn={state.burnAfterRead}>
					{#if state.burnAfterRead}
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="flex-shrink:0"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
						<p>This secret has been destroyed. It cannot be viewed again.</p>
					{:else}
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="flex-shrink:0"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
						<p>This secret will remain available until it expires.</p>
					{/if}
				</div>
				<a href="/share" class="link-home">Share a secret</a>
			</div>

		{:else if state.kind === 'error'}
			<div class="error-card" role="alert">
				<div class="error-icon-wrap">
					<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#d45656" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<circle cx="12" cy="12" r="10"/>
						<line x1="15" y1="9" x2="9" y2="15"/>
						<line x1="9" y1="9" x2="15" y2="15"/>
					</svg>
				</div>
				<h2 class="error-title">{errorMessages[state.code].title}</h2>
				<p class="error-detail">{errorMessages[state.code].detail}</p>
				<a href="/share" class="link-home">Share a secret</a>
			</div>
		{/if}
	</div>
</main>

<style>
	main {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem 1.5rem;
		font-family: var(--font-body);
	}

	.container {
		width: 100%;
		max-width: 500px;
		animation: rise 0.6s cubic-bezier(0.2, 0.7, 0.2, 1) both;
	}

	header {
		text-align: center;
		margin-bottom: 2.5rem;
	}

	/* --- State: Ready (the sealed chamber) --- */

	.ready {
		text-align: center;
		background: var(--glass-bg);
		border: 1px solid var(--line);
		border-radius: var(--r-card);
		box-shadow: var(--glass-shadow);
		backdrop-filter: blur(24px);
		-webkit-backdrop-filter: blur(24px);
		padding: 2.5rem 2rem;
		animation: rise 0.45s cubic-bezier(0.2, 0.7, 0.2, 1) both;
	}

	.ready-msg {
		color: var(--ink);
		font-family: var(--font-display);
		font-size: 19px;
		font-weight: 600;
		letter-spacing: -0.01em;
		margin: 0 0 1.75rem;
		line-height: 1.4;
	}

	.btn-reveal {
		width: 100%;
		padding: 0.95rem 1rem;
		background: linear-gradient(180deg, var(--mint), var(--mint-deep));
		color: #04140d;
		font-family: var(--font-body);
		font-size: 15px;
		font-weight: 600;
		border: none;
		border-radius: var(--r-pill);
		cursor: pointer;
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.4),
			0 12px 28px -10px var(--mint-glow);
		transition: filter 0.2s, transform 0.1s, box-shadow 0.2s;
	}

	.btn-reveal:hover {
		filter: brightness(1.06);
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.4),
			0 16px 36px -10px var(--mint-glow);
	}

	.btn-reveal:active { transform: scale(0.99); }

	.btn-reveal:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 3px;
	}

	/* --- State: Loading --- */

	.loading-state {
		text-align: center;
		animation: rise 0.35s ease both;
	}

	.loading-state p {
		color: var(--ink-dim);
		font-size: 14px;
		margin: 0.75rem 0 0;
	}

	.spinner {
		display: inline-block;
		width: 24px;
		height: 24px;
		border: 2px solid var(--mint);
		border-top-color: transparent;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	@keyframes rise {
		from { opacity: 0; transform: translateY(14px); filter: blur(3px); }
		to { opacity: 1; transform: translateY(0); filter: blur(0); }
	}

	/* --- State: Passphrase prompt --- */

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}

	.passphrase-prompt {
		background: var(--glass-bg);
		border: 1px solid var(--line);
		border-radius: var(--r-card);
		padding: 1.5rem 1.25rem;
		box-shadow: var(--glass-shadow);
		backdrop-filter: blur(24px);
		-webkit-backdrop-filter: blur(24px);
		animation: rise 0.4s cubic-bezier(0.2, 0.7, 0.2, 1) both;
	}

	.passphrase-title {
		margin: 0 0 0.25rem;
		font-family: var(--font-display);
		font-size: 17px;
		font-weight: 600;
		color: var(--ink);
	}

	.passphrase-sub {
		margin: 0 0 1rem;
		font-size: 13px;
		color: var(--ink-dim);
		line-height: 1.5;
	}

	.passphrase-prompt form {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}

	.passphrase-prompt input[type="password"] {
		width: 100%;
		box-sizing: border-box;
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 10px;
		color: var(--ink);
		font-family: var(--font-body);
		font-size: 14px;
		padding: 0.65rem 0.85rem;
		outline: none;
		transition: border-color 0.2s, box-shadow 0.2s;
	}

	.passphrase-prompt input[type="password"]:focus {
		border-color: var(--mint);
		box-shadow: 0 0 0 3px rgba(60, 242, 176, 0.12);
	}

	.btn-unlock {
		width: 100%;
		padding: 0.8rem 1rem;
		background: linear-gradient(180deg, var(--mint), var(--mint-deep));
		color: #04140d;
		font-family: var(--font-body);
		font-size: 14px;
		font-weight: 600;
		border: none;
		border-radius: var(--r-pill);
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.4),
			0 12px 28px -12px var(--mint-glow);
		transition: filter 0.2s, transform 0.1s;
	}

	.btn-unlock:hover:not(:disabled) { filter: brightness(1.06); }

	.btn-unlock:active:not(:disabled) { transform: scale(0.99); }

	.btn-unlock:disabled {
		opacity: 0.35;
		cursor: not-allowed;
	}

	.btn-unlock:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 3px;
	}

	.spinner-sm {
		width: 14px;
		height: 14px;
		border: 2px solid #04140d;
		border-top-color: transparent;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	.passphrase-err {
		margin: 0.75rem 0 0;
		color: var(--danger);
		font-size: 13px;
		line-height: 1.5;
	}

	/* --- State: Revealed --- */

	.revealed {
		animation: rise 0.45s cubic-bezier(0.2, 0.7, 0.2, 1) both;
	}

	.type-label {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		margin: 0 0 0.6rem;
		padding: 0.3rem 0.7rem;
		border: 1px solid rgba(60, 242, 176, 0.22);
		border-radius: var(--r-pill);
		background: rgba(60, 242, 176, 0.07);
		color: var(--ink-dim);
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 500;
		letter-spacing: 0.04em;
	}

	.type-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: var(--mint);
		box-shadow: 0 0 8px var(--mint-glow);
		display: inline-block;
	}

	.secret-card {
		background: var(--glass-bg-strong);
		border: 1px solid rgba(60, 242, 176, 0.2);
		border-radius: var(--r-card);
		position: relative;
		overflow: hidden;
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.08),
			0 24px 48px -24px rgba(0, 0, 0, 0.65),
			0 0 40px -16px var(--mint-glow);
		backdrop-filter: blur(24px);
		-webkit-backdrop-filter: blur(24px);
	}

	.secret-text {
		margin: 0;
		padding: 1.25rem;
		padding-right: 5rem;
		color: var(--ink);
		font-family: var(--font-mono);
		font-size: 14px;
		white-space: pre-wrap;
		word-break: break-all;
		line-height: 1.6;
		max-height: 300px;
		overflow-y: auto;
		animation: decrypt 0.8s cubic-bezier(0.2, 0.7, 0.2, 1) both;
	}

	@keyframes decrypt {
		from { opacity: 0; filter: blur(8px); letter-spacing: 0.08em; }
		to { opacity: 1; filter: blur(0); letter-spacing: 0; }
	}

	.btn-copy {
		position: absolute;
		top: 0.75rem;
		right: 0.75rem;
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		background: rgba(255, 255, 255, 0.1);
		border: 1px solid rgba(255, 255, 255, 0.12);
		color: var(--ink);
		font-family: var(--font-body);
		font-size: 12px;
		font-weight: 500;
		padding: 0.35rem 0.85rem;
		border-radius: var(--r-pill);
		cursor: pointer;
		white-space: nowrap;
		backdrop-filter: blur(8px);
		-webkit-backdrop-filter: blur(8px);
		transition: background 0.15s, color 0.15s, border-color 0.15s;
	}

	.btn-copy:hover { background: rgba(255, 255, 255, 0.16); }

	.btn-copy.copied {
		background: rgba(60, 242, 176, 0.15);
		border-color: rgba(60, 242, 176, 0.4);
		color: var(--mint);
	}

	.btn-copy:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 2px;
	}

	.file-card {
		padding: 1.25rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.file-info { font-family: var(--font-body); }

	.file-line {
		margin: 0;
		color: var(--ink);
		font-size: 14px;
		line-height: 1.5;
		word-break: break-all;
	}

	.file-line strong { font-weight: 600; }

	.file-meta {
		color: var(--ink-faint);
		font-size: 12px;
		margin-left: 0.25rem;
	}

	.btn-download {
		align-self: stretch;
		padding: 0.8rem 1rem;
		background: linear-gradient(180deg, var(--mint), var(--mint-deep));
		color: #04140d;
		font-family: var(--font-body);
		font-size: 14px;
		font-weight: 600;
		border: none;
		border-radius: var(--r-pill);
		cursor: pointer;
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.4),
			0 12px 28px -12px var(--mint-glow);
		transition: filter 0.2s, transform 0.1s;
		word-break: break-all;
	}

	.btn-download:hover { filter: brightness(1.06); }

	.btn-download:active { transform: scale(0.99); }

	.btn-download:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 3px;
	}

	.warning-box {
		margin-top: 1rem;
		padding: 0.8rem 1rem;
		border-radius: var(--r-field);
		font-size: 13px;
		line-height: 1.5;
		display: flex;
		align-items: flex-start;
		gap: 0.5rem;
		backdrop-filter: blur(16px);
		-webkit-backdrop-filter: blur(16px);
	}

	.warning-box p { margin: 0; }

	.warning-box.burn {
		background: rgba(255, 197, 107, 0.06);
		border: 1px solid rgba(255, 197, 107, 0.25);
		color: var(--warning);
	}

	.warning-box:not(.burn) {
		background: rgba(60, 242, 176, 0.05);
		border: 1px solid rgba(60, 242, 176, 0.18);
		color: var(--ink-dim);
	}

	/* --- State: Error --- */

	.error-card {
		text-align: center;
		background: var(--glass-bg);
		border: 1px solid rgba(255, 115, 115, 0.18);
		border-radius: var(--r-card);
		padding: 2.5rem 2rem;
		box-shadow: var(--glass-shadow);
		backdrop-filter: blur(24px);
		-webkit-backdrop-filter: blur(24px);
		animation: rise 0.4s ease both;
	}

	.error-icon-wrap { margin-bottom: 1rem; }

	.error-title {
		margin: 0 0 0.5rem;
		font-family: var(--font-display);
		font-size: 19px;
		font-weight: 600;
		color: var(--danger);
	}

	.error-detail {
		color: var(--ink-dim);
		font-size: 14px;
		margin: 0 0 1.5rem;
		line-height: 1.5;
	}

	/* --- Shared --- */

	.link-home {
		display: inline-block;
		margin-top: 1.5rem;
		color: var(--mint);
		font-size: 13px;
		font-weight: 500;
		text-decoration: none;
	}

	.link-home:hover { color: var(--mint-deep); }

	.link-home:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 2px;
	}
</style>
