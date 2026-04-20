<script lang="ts">
	import {
		generateKey,
		encrypt,
		keyToBase64url,
		deriveKeyFromPassphrase,
		wrapInnerKey,
		buildEnvelopeV2,
		SALT_LENGTH
	} from '$lib/crypto';
	import { createSecret, SECRET_TYPES, type SecretType } from '$lib/api';
	import QRCode from 'qrcode';

	const MAX_FILE_BYTES = 1_048_576; // 1 MiB

	type Mode = 'text' | 'file';

	// Types the user can pick when sending text. The `file` value is
	// auto-applied whenever the File tab is active, so it's excluded here.
	const TEXT_TYPES: SecretType[] = SECRET_TYPES.filter((t) => t !== 'file') as SecretType[];

	let mode: Mode = $state('text');
	let secret = $state('');
	let selectedFile: File | null = $state(null);
	let dragActive = $state(false);
	let expiresIn = $state('24h');
	let burnAfterRead = $state(true);
	let secretType: SecretType = $state('text');
	let loading = $state(false);
	let errorMsg = $state('');
	let resultUrl = $state('');
	let resultExpiresAt = $state('');
	let copied = $state(false);
	let qrSvg = $state('');

	// When File tab is active the type must be "file"; revert to "text"
	// whenever the user switches back (unless they picked something else).
	const effectiveType: SecretType = $derived(mode === 'file' ? 'file' : secretType);

	// --- Passphrase (optional, client-side only) ---
	let passphraseOpen = $state(false);
	let passphrase = $state('');
	let passphraseConfirm = $state('');

	const passphraseMismatch = $derived(
		passphraseOpen &&
			passphrase.length > 0 &&
			passphraseConfirm.length > 0 &&
			passphrase !== passphraseConfirm
	);

	const passphraseEnabled = $derived(
		passphraseOpen &&
			passphrase.length > 0 &&
			passphraseConfirm.length > 0 &&
			passphrase === passphraseConfirm
	);

	const EXPIRY_LABELS: Record<string, string> = {
		'5m': '5 minutes',
		'15m': '15 minutes',
		'1h': '1 hour',
		'24h': '24 hours',
		'7d': '7 days',
		'30d': '30 days'
	};

	const expiryLabel = $derived(EXPIRY_LABELS[expiresIn] ?? '24 hours');

	const burnLabel = $derived(burnAfterRead ? 'once' : 'until expiry');

	const canSubmit = $derived(
		(mode === 'text' ? secret.trim().length > 0 : selectedFile !== null) &&
			!passphraseMismatch &&
			!(passphraseOpen && (passphrase.length === 0 || passphraseConfirm.length === 0))
	);

	function formatBytes(n: number): string {
		if (n < 1024) return `${n} B`;
		if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
		return `${(n / 1024 / 1024).toFixed(2)} MiB`;
	}

	// ArrayBuffer -> base64 (standard, for JSON transport). btoa is fine for
	// small-ish payloads; we chunk to avoid call-stack limits on 1 MiB inputs.
	function bytesToBase64(buf: ArrayBuffer): string {
		const bytes = new Uint8Array(buf);
		const CHUNK = 0x8000;
		let binary = '';
		for (let i = 0; i < bytes.length; i += CHUNK) {
			binary += String.fromCharCode.apply(
				null,
				bytes.subarray(i, i + CHUNK) as unknown as number[]
			);
		}
		return btoa(binary);
	}

	function pickFile(files: FileList | null | undefined) {
		errorMsg = '';
		if (!files || files.length === 0) return;
		const f = files[0];
		if (f.size > MAX_FILE_BYTES) {
			selectedFile = null;
			errorMsg = 'File too large (max 1 MiB)';
			return;
		}
		selectedFile = f;
	}

	function onFileInput(e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		pickFile(input.files);
	}

	function onDrop(e: DragEvent) {
		e.preventDefault();
		dragActive = false;
		pickFile(e.dataTransfer?.files ?? null);
	}

	function onDragOver(e: DragEvent) {
		e.preventDefault();
		dragActive = true;
	}

	function onDragLeave(e: DragEvent) {
		e.preventDefault();
		dragActive = false;
	}

	function setMode(m: Mode) {
		mode = m;
		errorMsg = '';
	}

	async function handleCreate() {
		if (!canSubmit) return;
		loading = true;
		errorMsg = '';
		try {
			let plaintext: string;

			if (mode === 'file') {
				if (!selectedFile) throw new Error('No file selected');
				// Defense-in-depth: re-check size before reading.
				if (selectedFile.size > MAX_FILE_BYTES) {
					throw new Error('File too large (max 1 MiB)');
				}
				const buf = await selectedFile.arrayBuffer();
				const b64 = bytesToBase64(buf);
				plaintext = JSON.stringify({
					kind: 'file',
					name: selectedFile.name,
					mime: selectedFile.type || 'application/octet-stream',
					size: selectedFile.size,
					data: b64
				});
			} else {
				plaintext = secret;
			}

			const key = await generateKey();
			const innerCt = await encrypt(plaintext, key);

			let ciphertext: string;
			if (passphraseEnabled) {
				// Stacked encryption: wrap the inner key with a passphrase-derived key.
				const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
				const passKey = await deriveKeyFromPassphrase(passphrase, salt);
				const { iv, wrapped } = await wrapInnerKey(key, passKey);
				ciphertext = buildEnvelopeV2(innerCt, salt, iv, wrapped);
			} else {
				ciphertext = innerCt;
			}

			const { id, expiresAt } = await createSecret(
				ciphertext,
				expiresIn,
				burnAfterRead,
				effectiveType
			);
			const keyB64 = await keyToBase64url(key);
			resultUrl = `${window.location.origin}/s/${id}#${keyB64}`;
			resultExpiresAt = expiresAt;
			try {
				qrSvg = await QRCode.toString(resultUrl, {
					type: 'svg',
					margin: 1,
					width: 240,
					errorCorrectionLevel: 'M'
				});
			} catch {
				qrSvg = '';
			}
		} catch (e: any) {
			errorMsg = e?.message || 'Something went wrong. Please try again.';
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		secret = '';
		selectedFile = null;
		resultUrl = '';
		resultExpiresAt = '';
		errorMsg = '';
		copied = false;
		qrSvg = '';
		passphrase = '';
		passphraseConfirm = '';
		passphraseOpen = false;
		requestAnimationFrame(() => {
			if (mode === 'text') document.getElementById('secret-input')?.focus();
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
				<div class="tabs" role="tablist" aria-label="Secret type">
					<button
						type="button"
						role="tab"
						aria-selected={mode === 'text'}
						class="tab"
						class:active={mode === 'text'}
						onclick={() => setMode('text')}
						disabled={loading}
					>
						Text
					</button>
					<button
						type="button"
						role="tab"
						aria-selected={mode === 'file'}
						class="tab"
						class:active={mode === 'file'}
						onclick={() => setMode('file')}
						disabled={loading}
					>
						File
					</button>
				</div>

				{#if mode === 'text'}
					<div class="field">
						<label for="secret-input" class="sr-only">Your secret</label>
						<textarea
							id="secret-input"
							bind:value={secret}
							placeholder="Paste your secret here..."
							rows="5"
							disabled={loading}
						></textarea>
					</div>
				{:else}
					<div class="field">
						<label
							class="drop-zone"
							class:dragover={dragActive}
							class:has-file={selectedFile !== null}
							ondragover={onDragOver}
							ondragleave={onDragLeave}
							ondrop={onDrop}
						>
							<input
								type="file"
								class="file-input"
								onchange={onFileInput}
								disabled={loading}
							/>
							{#if selectedFile}
								<div class="drop-label">
									<strong>{selectedFile.name}</strong>
									<span class="drop-sub">{formatBytes(selectedFile.size)} - click or drop to replace</span>
								</div>
							{:else}
								<div class="drop-label">
									<strong>Drop a file here</strong>
									<span class="drop-sub">or click to choose (max 1 MiB)</span>
								</div>
							{/if}
						</label>
					</div>
				{/if}

				<div class="controls">
					<div class="control-group">
						<label for="expiry-select">Expires in</label>
						<select id="expiry-select" bind:value={expiresIn} disabled={loading}>
							<option value="5m">5 minutes</option>
							<option value="15m">15 minutes</option>
							<option value="1h">1 hour</option>
							<option value="24h">24 hours</option>
							<option value="7d">7 days</option>
							<option value="30d">30 days</option>
						</select>
					</div>

					{#if mode === 'text'}
						<div class="control-group">
							<label for="type-select">Type</label>
							<select id="type-select" bind:value={secretType} disabled={loading}>
								{#each TEXT_TYPES as t}
									<option value={t}>{t}</option>
								{/each}
							</select>
						</div>
					{/if}

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

				<details
					class="passphrase-section"
					open={passphraseOpen}
					ontoggle={(e) => (passphraseOpen = (e.currentTarget as HTMLDetailsElement).open)}
				>
					<summary class="passphrase-summary">
						<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
						Require passphrase (optional)
					</summary>
					<div class="passphrase-body">
						<p class="passphrase-hint">
							Recipient must enter this passphrase to unlock. It's derived to a
							key in their browser and never sent to the server.
						</p>
						<div class="passphrase-row">
							<label for="passphrase-input" class="sr-only">Passphrase</label>
							<input
								id="passphrase-input"
								type="password"
								bind:value={passphrase}
								placeholder="Passphrase"
								autocomplete="new-password"
								disabled={loading}
							/>
						</div>
						<div class="passphrase-row">
							<label for="passphrase-confirm-input" class="sr-only">Confirm passphrase</label>
							<input
								id="passphrase-confirm-input"
								type="password"
								bind:value={passphraseConfirm}
								placeholder="Confirm passphrase"
								autocomplete="new-password"
								disabled={loading}
							/>
						</div>
						{#if passphraseMismatch}
							<p class="passphrase-mismatch" role="alert">Passphrases do not match.</p>
						{:else if passphraseEnabled}
							<p class="passphrase-ok">Passphrase set. Share it out-of-band (not in the link).</p>
						{/if}
					</div>
				</details>

				{#if errorMsg}
					<div class="error" role="alert">{errorMsg}</div>
				{/if}

				<button type="submit" class="btn-create" disabled={loading || !canSubmit}>
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

				{#if qrSvg}
					<div class="qr-wrap">
						<div class="qr-frame">
							<div class="qr-svg">{@html qrSvg}</div>
						</div>
						<p class="qr-caption">Scan to open on another device</p>
					</div>
				{/if}

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

	/* --- Tabs --- */

	.tabs {
		display: inline-flex;
		align-self: flex-start;
		gap: 0.25rem;
		padding: 0.25rem;
		background: #f3f4f6;
		border-radius: 9999px;
	}

	.tab {
		appearance: none;
		border: none;
		background: transparent;
		color: #666666;
		font-family: 'Inter', sans-serif;
		font-size: 13px;
		font-weight: 500;
		padding: 0.4rem 1rem;
		border-radius: 9999px;
		cursor: pointer;
		transition: background 0.15s, color 0.15s;
	}

	.tab:hover:not(:disabled):not(.active) {
		color: #0d0d0d;
	}

	.tab.active {
		background: #ffffff;
		color: #0d0d0d;
		box-shadow: rgba(0, 0, 0, 0.05) 0px 1px 3px;
	}

	.tab:focus-visible {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}

	.tab:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* --- Drop zone --- */

	.drop-zone {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 100%;
		min-height: 130px;
		padding: 1.5rem 1rem;
		border: 1.5px dashed rgba(0, 0, 0, 0.18);
		border-radius: 8px;
		background: #ffffff;
		cursor: pointer;
		text-align: center;
		transition: border-color 0.15s, background 0.15s;
		box-sizing: border-box;
	}

	.drop-zone:hover,
	.drop-zone.dragover {
		border-color: #18E299;
		background: rgba(24, 226, 153, 0.04);
	}

	.drop-zone.has-file {
		border-style: solid;
		border-color: rgba(24, 226, 153, 0.35);
		background: rgba(24, 226, 153, 0.04);
	}

	.drop-zone:focus-within {
		border-color: #18E299;
		box-shadow: 0 0 0 3px rgba(24, 226, 153, 0.1);
	}

	.file-input {
		position: absolute;
		width: 1px;
		height: 1px;
		opacity: 0;
		pointer-events: none;
	}

	.drop-label {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		font-family: 'Inter', sans-serif;
	}

	.drop-label strong {
		color: #0d0d0d;
		font-size: 14px;
		font-weight: 600;
		word-break: break-all;
	}

	.drop-sub {
		color: #888888;
		font-size: 12px;
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

	/* --- Passphrase section --- */

	.passphrase-section {
		border: 1px solid rgba(0, 0, 0, 0.08);
		border-radius: 12px;
		background: #fafafa;
		padding: 0;
		overflow: hidden;
	}

	.passphrase-summary {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		list-style: none;
		padding: 0.65rem 0.9rem;
		cursor: pointer;
		font-size: 13px;
		font-weight: 500;
		color: #0d0d0d;
		user-select: none;
	}

	.passphrase-summary::-webkit-details-marker {
		display: none;
	}

	.passphrase-summary::after {
		content: '';
		margin-left: auto;
		width: 7px;
		height: 7px;
		border-right: 1.5px solid #888888;
		border-bottom: 1.5px solid #888888;
		transform: rotate(45deg) translate(-2px, -2px);
		transition: transform 0.15s;
	}

	.passphrase-section[open] .passphrase-summary::after {
		transform: rotate(-135deg) translate(-2px, -2px);
	}

	.passphrase-summary:focus-visible {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}

	.passphrase-body {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
		padding: 0.25rem 0.9rem 0.85rem;
		border-top: 1px solid rgba(0, 0, 0, 0.05);
	}

	.passphrase-hint {
		margin: 0.5rem 0 0.1rem;
		font-size: 12px;
		color: #666666;
		line-height: 1.5;
	}

	.passphrase-row input[type="password"] {
		width: 100%;
		box-sizing: border-box;
		background: #ffffff;
		border: 1px solid rgba(0, 0, 0, 0.08);
		border-radius: 8px;
		color: #0d0d0d;
		font-family: 'Inter', sans-serif;
		font-size: 14px;
		padding: 0.55rem 0.8rem;
		outline: none;
		transition: border-color 0.2s, box-shadow 0.2s;
	}

	.passphrase-row input[type="password"]:focus {
		border-color: #18E299;
		box-shadow: 0 0 0 3px rgba(24, 226, 153, 0.1);
	}

	.passphrase-row input[type="password"]:disabled {
		opacity: 0.5;
	}

	.passphrase-mismatch {
		margin: 0;
		color: #d45656;
		font-size: 12px;
	}

	.passphrase-ok {
		margin: 0;
		color: #0fa76e;
		font-size: 12px;
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

	/* --- QR code --- */

	.qr-wrap {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 0.5rem;
		margin-top: 1.25rem;
	}

	.qr-frame {
		background: #ffffff;
		border: 1px solid rgba(0, 0, 0, 0.08);
		border-radius: 12px;
		padding: 12px;
		box-shadow: rgba(0, 0, 0, 0.03) 0px 2px 4px;
		width: 100%;
		max-width: 240px;
		box-sizing: content-box;
	}

	.qr-svg {
		width: 100%;
		line-height: 0;
	}

	.qr-svg :global(svg) {
		display: block;
		width: 100%;
		height: auto;
		max-width: 100%;
	}

	.qr-caption {
		margin: 0;
		font-size: 12px;
		color: #888888;
		text-align: center;
	}

	/* --- Responsive --- */

	@media (max-width: 480px) {
		.controls {
			flex-direction: column;
			align-items: flex-start;
		}

		.qr-frame {
			max-width: 200px;
		}
	}
</style>
