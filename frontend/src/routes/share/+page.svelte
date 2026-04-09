<script lang="ts">
	import { generateKey, encrypt, keyToBase64url } from '$lib/crypto';
	import { createSecret } from '$lib/api';

	let secret = $state('');
	let expiresIn = $state('1h');
	let burnAfterRead = $state(true);
	let loading = $state(false);
	let errorMsg = $state('');
	let resultUrl = $state('');
	let resultExpiresAt = $state('');
	let copied = $state(false);

	const expiryLabel = $derived(
		expiresIn === '1h' ? '1 hour' : expiresIn === '24h' ? '24 hours' : '7 days'
	);

	const burnLabel = $derived(burnAfterRead ? 'once' : 'until expiry');

	async function handleCreate() {
		if (!secret.trim()) return;
		loading = true;
		errorMsg = '';
		try {
			const key = await generateKey();
			const ciphertext = await encrypt(secret, key);
			const { id, expiresAt } = await createSecret(ciphertext, expiresIn, burnAfterRead);
			const keyB64 = await keyToBase64url(key);
			resultUrl = `${window.location.origin}/s/${id}#${keyB64}`;
			resultExpiresAt = expiresAt;
		} catch (e: any) {
			errorMsg = e?.message || 'Something went wrong. Please try again.';
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		secret = '';
		resultUrl = '';
		resultExpiresAt = '';
		errorMsg = '';
		copied = false;
		requestAnimationFrame(() => {
			document.getElementById('secret-input')?.focus();
		});
	}

	async function copyUrl() {
		try {
			await navigator.clipboard.writeText(resultUrl);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch {
			const el = document.getElementById('result-url') as HTMLInputElement | null;
			el?.select();
		}
	}

	function formatExpiry(iso: string): string {
		try {
			const d = new Date(iso);
			const now = new Date();
			const diffMs = d.getTime() - now.getTime();
			if (diffMs <= 0) return 'soon';
			const hours = Math.floor(diffMs / 3600000);
			if (hours < 1) {
				const mins = Math.max(1, Math.floor(diffMs / 60000));
				return `${mins} minute${mins !== 1 ? 's' : ''}`;
			}
			if (hours < 48) return `${hours} hour${hours !== 1 ? 's' : ''}`;
			const days = Math.floor(hours / 24);
			return `${days} day${days !== 1 ? 's' : ''}`;
		} catch {
			return expiryLabel;
		}
	}
</script>

<svelte:head>
	<title>passwd.page — Share a secret</title>
	<meta name="description" content="Zero-knowledge password sharing. Encrypted client-side, auto-expires, optional burn after reading." />
	<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet" />
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
			<p class="subtitle">Share a secret</p>
		</header>

		{#if !resultUrl}
			<form onsubmit={(e) => { e.preventDefault(); handleCreate(); }}>
				<div class="field">
					<label for="secret-input" class="sr-only">Your secret</label>
					<textarea
						id="secret-input"
						bind:value={secret}
						placeholder="Paste your secret here..."
						rows="5"
						required
						disabled={loading}
					></textarea>
				</div>

				<div class="controls">
					<div class="control-group">
						<label for="expiry-select">Expires in</label>
						<select id="expiry-select" bind:value={expiresIn} disabled={loading}>
							<option value="1h">1 hour</option>
							<option value="24h">24 hours</option>
							<option value="7d">7 days</option>
						</select>
					</div>

					<div class="control-group">
						<label class="toggle-label">
							<input
								type="checkbox"
								bind:checked={burnAfterRead}
								disabled={loading}
								class="toggle-input"
							/>
							<span class="toggle-switch" aria-hidden="true"></span>
							Burn after reading
						</label>
					</div>
				</div>

				{#if errorMsg}
					<div class="error" role="alert">{errorMsg}</div>
				{/if}

				<button type="submit" class="btn-create" disabled={loading || !secret.trim()}>
					{#if loading}
						<span class="spinner" aria-hidden="true"></span>
						Encrypting...
					{:else}
						Create Secret Link
					{/if}
				</button>
			</form>
		{:else}
			<div class="result" role="status">
				<div class="result-card">
					<label for="result-url" class="sr-only">Secret link</label>
					<input
						id="result-url"
						type="text"
						value={resultUrl}
						readonly
						class="result-url"
						onclick={(e) => (e.currentTarget as HTMLInputElement).select()}
					/>
					<button type="button" class="btn-copy" onclick={copyUrl}>
						{copied ? 'Copied!' : 'Copy'}
					</button>
				</div>

				<p class="result-info">
					This link will expire in <strong>{formatExpiry(resultExpiresAt)}</strong>.
					Anyone with it can view the secret <strong>{burnLabel}</strong>.
				</p>

				<button type="button" class="btn-reset" onclick={resetForm}>
					Create another
				</button>
			</div>
		{/if}
	</div>
</main>

<style>
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

	main {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem 1.5rem;
		background: #ffffff;
		font-family: 'Inter', sans-serif;
	}

	.container {
		width: 100%;
		max-width: 480px;
	}

	header {
		text-align: center;
		margin-bottom: 2.5rem;
	}

	.brand-pill {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.4rem 0.85rem;
		border: 1px solid rgba(0, 0, 0, 0.08);
		border-radius: 9999px;
		margin-bottom: 0.75rem;
	}

	.brand-name {
		font-size: 14px;
		font-weight: 600;
		color: #0d0d0d;
		letter-spacing: -0.01em;
	}

	.subtitle {
		margin: 0;
		color: #666666;
		font-size: 14px;
		font-weight: 400;
	}

	/* --- Form --- */

	form {
		display: flex;
		flex-direction: column;
		gap: 1.25rem;
	}

	textarea {
		width: 100%;
		background: #ffffff;
		border: 1px solid rgba(0, 0, 0, 0.08);
		border-radius: 8px;
		color: #0d0d0d;
		font-family: 'Inter', sans-serif;
		font-size: 15px;
		padding: 0.85rem 1rem;
		resize: vertical;
		min-height: 130px;
		outline: none;
		transition: border-color 0.2s, box-shadow 0.2s;
		box-shadow: rgba(0, 0, 0, 0.03) 0px 2px 4px;
	}

	textarea::placeholder {
		color: #888888;
	}

	textarea:focus {
		border-color: #18E299;
		box-shadow: 0 0 0 3px rgba(24, 226, 153, 0.1);
	}

	textarea:disabled {
		opacity: 0.5;
	}

	/* --- Controls row --- */

	.controls {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		flex-wrap: wrap;
	}

	.control-group {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 13px;
		color: #666666;
	}

	.control-group label {
		white-space: nowrap;
	}

	select {
		background: #ffffff;
		border: 1px solid rgba(0, 0, 0, 0.08);
		border-radius: 9999px;
		color: #0d0d0d;
		font-family: 'Inter', sans-serif;
		font-size: 13px;
		font-weight: 500;
		padding: 0.35rem 0.75rem;
		outline: none;
		cursor: pointer;
		appearance: auto;
	}

	select:focus {
		border-color: #18E299;
		box-shadow: 0 0 0 3px rgba(24, 226, 153, 0.1);
	}

	/* --- Toggle switch --- */

	.toggle-label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		user-select: none;
		white-space: nowrap;
		font-size: 13px;
		color: #666666;
	}

	.toggle-input {
		position: absolute;
		opacity: 0;
		width: 0;
		height: 0;
	}

	.toggle-switch {
		width: 34px;
		height: 18px;
		background: rgba(0, 0, 0, 0.08);
		border-radius: 9px;
		position: relative;
		transition: background 0.2s;
		flex-shrink: 0;
	}

	.toggle-switch::after {
		content: '';
		position: absolute;
		top: 2px;
		left: 2px;
		width: 14px;
		height: 14px;
		border-radius: 50%;
		background: #888888;
		transition: transform 0.2s, background 0.2s;
	}

	.toggle-input:checked + .toggle-switch {
		background: #d4fae8;
	}

	.toggle-input:checked + .toggle-switch::after {
		transform: translateX(16px);
		background: #18E299;
	}

	.toggle-input:focus-visible + .toggle-switch {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}

	/* --- Create button --- */

	.btn-create {
		width: 100%;
		padding: 0.85rem 1rem;
		background: #0d0d0d;
		color: #ffffff;
		font-family: 'Inter', sans-serif;
		font-size: 15px;
		font-weight: 500;
		border: none;
		border-radius: 9999px;
		cursor: pointer;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		transition: opacity 0.2s, transform 0.1s;
	}

	.btn-create:hover:not(:disabled) {
		opacity: 0.85;
	}

	.btn-create:active:not(:disabled) {
		transform: scale(0.99);
	}

	.btn-create:disabled {
		opacity: 0.35;
		cursor: not-allowed;
	}

	.btn-create:focus-visible {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}

	/* --- Spinner --- */

	.spinner {
		width: 16px;
		height: 16px;
		border: 2px solid #ffffff;
		border-top-color: transparent;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	/* --- Error --- */

	.error {
		color: #d45656;
		font-size: 13px;
		padding: 0.5rem 0;
	}

	/* --- Result --- */

	.result {
		animation: fadeIn 0.35s ease;
	}

	@keyframes fadeIn {
		from { opacity: 0; transform: translateY(8px); }
		to { opacity: 1; transform: translateY(0); }
	}

	.result-card {
		background: #fafafa;
		border: 1px solid rgba(0, 0, 0, 0.05);
		border-radius: 16px;
		padding: 1.25rem;
		box-shadow: rgba(0, 0, 0, 0.03) 0px 2px 4px;
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.result-url {
		width: 100%;
		background: #ffffff;
		border: 1px solid rgba(0, 0, 0, 0.08);
		border-radius: 8px;
		color: #0d0d0d;
		font-family: 'Inter', sans-serif;
		font-size: 13px;
		padding: 0.65rem 0.85rem;
		outline: none;
		text-overflow: ellipsis;
		overflow: hidden;
		white-space: nowrap;
	}

	.btn-copy {
		align-self: flex-end;
		background: #0d0d0d;
		border: none;
		color: #ffffff;
		font-family: 'Inter', sans-serif;
		font-size: 13px;
		font-weight: 500;
		padding: 0.5rem 1.25rem;
		border-radius: 9999px;
		cursor: pointer;
		white-space: nowrap;
		transition: opacity 0.15s;
	}

	.btn-copy:hover {
		opacity: 0.85;
	}

	.btn-copy:focus-visible {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}

	.result-info {
		color: #666666;
		font-size: 13px;
		margin: 1rem 0 0.5rem;
		line-height: 1.7;
	}

	.result-info strong {
		color: #0d0d0d;
		font-weight: 600;
	}

	.btn-reset {
		background: none;
		border: none;
		color: #18E299;
		font-family: 'Inter', sans-serif;
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		padding: 0.4rem 0;
	}

	.btn-reset:hover {
		color: #0fa76e;
	}

	.btn-reset:focus-visible {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}

	/* --- Responsive --- */

	@media (max-width: 480px) {
		.controls {
			flex-direction: column;
			align-items: flex-start;
		}
	}
</style>
