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
					<button type="button" class="btn-copy" class:copied onclick={copyUrl}>
						{#if copied}
							<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
							Copied!
						{:else}
							Copy
						{/if}
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
		font-family: var(--font-body);
	}

	.container {
		width: 100%;
		max-width: 500px;
		animation: rise 0.6s cubic-bezier(0.2, 0.7, 0.2, 1) both;
	}

	@keyframes rise {
		from { opacity: 0; transform: translateY(16px); filter: blur(3px); }
		to { opacity: 1; transform: translateY(0); filter: blur(0); }
	}

	header {
		text-align: center;
		margin-bottom: 2rem;
	}

	.subtitle {
		margin: 0.85rem 0 0;
		color: var(--ink-dim);
		font-family: var(--font-display);
		font-size: 22px;
		font-weight: 600;
		letter-spacing: -0.01em;
		color: var(--ink);
	}

	/* --- Form: the glass vault panel --- */

	form {
		display: flex;
		flex-direction: column;
		gap: 1.25rem;
		background: var(--glass-bg);
		border: 1px solid var(--line);
		border-radius: var(--r-card);
		box-shadow: var(--glass-shadow);
		backdrop-filter: blur(24px);
		-webkit-backdrop-filter: blur(24px);
		padding: 1.5rem;
	}

	/* --- Tabs --- */

	.tabs {
		display: inline-flex;
		align-self: flex-start;
		gap: 0.25rem;
		padding: 0.25rem;
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.05);
		border-radius: var(--r-pill);
	}

	.tab {
		appearance: none;
		border: none;
		background: transparent;
		color: var(--ink-faint);
		font-family: var(--font-body);
		font-size: 13px;
		font-weight: 500;
		padding: 0.4rem 1.1rem;
		border-radius: var(--r-pill);
		cursor: pointer;
		transition: background 0.15s, color 0.15s;
	}

	.tab:hover:not(:disabled):not(.active) { color: var(--ink); }

	.tab.active {
		background: rgba(60, 242, 176, 0.12);
		color: var(--mint);
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08);
	}

	.tab:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 2px;
	}

	.tab:disabled { opacity: 0.5; cursor: not-allowed; }

	/* --- Drop zone --- */

	.drop-zone {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 100%;
		min-height: 130px;
		padding: 1.5rem 1rem;
		border: 1.5px dashed rgba(255, 255, 255, 0.16);
		border-radius: var(--r-field);
		background: rgba(0, 0, 0, 0.2);
		cursor: pointer;
		text-align: center;
		transition: border-color 0.15s, background 0.15s, box-shadow 0.15s;
		box-sizing: border-box;
	}

	.drop-zone:hover,
	.drop-zone.dragover {
		border-color: var(--mint);
		background: rgba(60, 242, 176, 0.05);
		box-shadow: 0 0 28px -10px var(--mint-glow);
	}

	.drop-zone.has-file {
		border-style: solid;
		border-color: rgba(60, 242, 176, 0.4);
		background: rgba(60, 242, 176, 0.05);
	}

	.drop-zone:focus-within {
		border-color: var(--mint);
		box-shadow: 0 0 0 3px rgba(60, 242, 176, 0.15);
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
	}

	.drop-label strong {
		color: var(--ink);
		font-size: 14px;
		font-weight: 600;
		word-break: break-all;
	}

	.drop-sub {
		color: var(--ink-faint);
		font-size: 12px;
	}

	textarea {
		width: 100%;
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: var(--r-field);
		color: var(--ink);
		font-family: var(--font-mono);
		font-size: 14px;
		padding: 0.85rem 1rem;
		resize: vertical;
		min-height: 130px;
		outline: none;
		transition: border-color 0.2s, box-shadow 0.2s;
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
	}

	textarea::placeholder { color: var(--ink-faint); }

	textarea:focus {
		border-color: var(--mint);
		box-shadow: 0 0 0 3px rgba(60, 242, 176, 0.12);
	}

	textarea:disabled { opacity: 0.5; }

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
		color: var(--ink-dim);
	}

	.control-group label { white-space: nowrap; }

	select {
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: var(--r-pill);
		color: var(--ink);
		font-family: var(--font-body);
		font-size: 13px;
		font-weight: 500;
		padding: 0.35rem 0.75rem;
		outline: none;
		cursor: pointer;
		appearance: auto;
	}

	select:focus {
		border-color: var(--mint);
		box-shadow: 0 0 0 3px rgba(60, 242, 176, 0.12);
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
		color: var(--ink-dim);
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
		background: rgba(255, 255, 255, 0.1);
		border-radius: 9px;
		position: relative;
		transition: background 0.2s, box-shadow 0.2s;
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
		background: var(--ink-faint);
		transition: transform 0.2s, background 0.2s;
	}

	.toggle-input:checked + .toggle-switch {
		background: rgba(60, 242, 176, 0.25);
		box-shadow: 0 0 14px -4px var(--mint-glow);
	}

	.toggle-input:checked + .toggle-switch::after {
		transform: translateX(16px);
		background: var(--mint);
	}

	.toggle-input:focus-visible + .toggle-switch {
		outline: 2px solid var(--mint);
		outline-offset: 2px;
	}

	/* --- Passphrase section --- */

	.passphrase-section {
		border: 1px solid rgba(255, 255, 255, 0.07);
		border-radius: var(--r-field);
		background: rgba(0, 0, 0, 0.22);
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
		color: var(--ink);
		user-select: none;
	}

	.passphrase-summary::-webkit-details-marker { display: none; }

	.passphrase-summary::after {
		content: '';
		margin-left: auto;
		width: 7px;
		height: 7px;
		border-right: 1.5px solid var(--ink-faint);
		border-bottom: 1.5px solid var(--ink-faint);
		transform: rotate(45deg) translate(-2px, -2px);
		transition: transform 0.15s;
	}

	.passphrase-section[open] .passphrase-summary::after {
		transform: rotate(-135deg) translate(-2px, -2px);
	}

	.passphrase-summary:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 2px;
	}

	.passphrase-body {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
		padding: 0.25rem 0.9rem 0.85rem;
		border-top: 1px solid rgba(255, 255, 255, 0.05);
	}

	.passphrase-hint {
		margin: 0.5rem 0 0.1rem;
		font-size: 12px;
		color: var(--ink-dim);
		line-height: 1.5;
	}

	.passphrase-row input[type="password"] {
		width: 100%;
		box-sizing: border-box;
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.08);
		border-radius: 10px;
		color: var(--ink);
		font-family: var(--font-body);
		font-size: 14px;
		padding: 0.55rem 0.8rem;
		outline: none;
		transition: border-color 0.2s, box-shadow 0.2s;
	}

	.passphrase-row input[type="password"]:focus {
		border-color: var(--mint);
		box-shadow: 0 0 0 3px rgba(60, 242, 176, 0.12);
	}

	.passphrase-row input[type="password"]:disabled { opacity: 0.5; }

	.passphrase-mismatch {
		margin: 0;
		color: var(--danger);
		font-size: 12px;
	}

	.passphrase-ok {
		margin: 0;
		color: var(--mint-dark);
		font-size: 12px;
	}

	/* --- Create button --- */

	.btn-create {
		width: 100%;
		padding: 0.9rem 1rem;
		background: linear-gradient(180deg, var(--mint), var(--mint-deep));
		color: #04140d;
		font-family: var(--font-body);
		font-size: 15px;
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
			0 12px 28px -10px var(--mint-glow);
		transition: filter 0.2s, transform 0.1s, box-shadow 0.2s;
	}

	.btn-create:hover:not(:disabled) {
		filter: brightness(1.06);
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.4),
			0 16px 36px -10px var(--mint-glow);
	}

	.btn-create:active:not(:disabled) { transform: scale(0.99); }

	.btn-create:disabled {
		opacity: 0.35;
		cursor: not-allowed;
	}

	.btn-create:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 3px;
	}

	/* --- Spinner --- */

	.spinner {
		width: 16px;
		height: 16px;
		border: 2px solid #04140d;
		border-top-color: transparent;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	/* --- Error --- */

	.error {
		color: var(--danger);
		font-size: 13px;
		padding: 0.5rem 0;
	}

	/* --- Result --- */

	.result {
		animation: rise 0.45s cubic-bezier(0.2, 0.7, 0.2, 1) both;
	}

	.result-card {
		background: var(--glass-bg-strong);
		border: 1px solid rgba(60, 242, 176, 0.2);
		border-radius: var(--r-card);
		padding: 1.25rem;
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.08),
			0 24px 48px -24px rgba(0, 0, 0, 0.65),
			0 0 40px -16px var(--mint-glow);
		backdrop-filter: blur(24px);
		-webkit-backdrop-filter: blur(24px);
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}

	.result-url {
		width: 100%;
		background: rgba(0, 0, 0, 0.35);
		border: 1px solid rgba(255, 255, 255, 0.1);
		border-radius: 10px;
		color: var(--mint);
		font-family: var(--font-mono);
		font-size: 13px;
		padding: 0.7rem 0.85rem;
		outline: none;
		text-overflow: ellipsis;
		overflow: hidden;
		white-space: nowrap;
	}

	.btn-copy {
		align-self: flex-end;
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		background: rgba(255, 255, 255, 0.1);
		border: 1px solid rgba(255, 255, 255, 0.12);
		color: var(--ink);
		font-family: var(--font-body);
		font-size: 13px;
		font-weight: 500;
		padding: 0.5rem 1.25rem;
		border-radius: var(--r-pill);
		cursor: pointer;
		white-space: nowrap;
		transition: background 0.15s, color 0.15s, border-color 0.15s;
	}

	.btn-copy:hover {
		background: rgba(255, 255, 255, 0.16);
	}

	.btn-copy.copied {
		background: rgba(60, 242, 176, 0.15);
		border-color: rgba(60, 242, 176, 0.4);
		color: var(--mint);
	}

	.btn-copy:focus-visible {
		outline: 2px solid var(--mint);
		outline-offset: 2px;
	}

	.result-info {
		color: var(--ink-dim);
		font-size: 13px;
		margin: 1rem 0 0.5rem;
		line-height: 1.7;
	}

	.result-info strong {
		color: var(--ink);
		font-weight: 600;
	}

	.btn-reset {
		background: none;
		border: none;
		color: var(--mint);
		font-family: var(--font-body);
		font-size: 13px;
		font-weight: 500;
		cursor: pointer;
		padding: 0.4rem 0;
	}

	.btn-reset:hover { color: var(--mint-deep); }

	.btn-reset:focus-visible {
		outline: 2px solid var(--mint);
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
		border: 1px solid rgba(255, 255, 255, 0.2);
		border-radius: 14px;
		padding: 12px;
		box-shadow: 0 20px 44px -18px rgba(0, 0, 0, 0.7);
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
		color: var(--ink-faint);
		text-align: center;
	}

	/* --- Responsive --- */

	@media (max-width: 480px) {
		.controls {
			flex-direction: column;
			align-items: flex-start;
		}

		.qr-frame { max-width: 200px; }
	}
</style>
