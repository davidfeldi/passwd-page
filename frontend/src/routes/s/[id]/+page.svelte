<script lang="ts">
	import { page } from '$app/stores';
	import { base64urlToKey, decrypt } from '$lib/crypto';
	import { getSecret } from '$lib/api';

	type ViewState =
		| { kind: 'ready' }
		| { kind: 'loading' }
		| { kind: 'revealed'; secret: string; burnAfterRead: boolean; expiresAt?: string }
		| { kind: 'error'; code: 'not-found' | 'invalid-link' | 'decrypt-failed' | 'server-error' };

	let state: ViewState = $state({ kind: 'ready' });
	let copied = $state(false);

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

			let plaintext: string;
			try {
				plaintext = await decrypt(res.ciphertext, key);
			} catch {
				state = { kind: 'error', code: 'decrypt-failed' };
				return;
			}

			state = { kind: 'revealed', secret: plaintext, burnAfterRead: res.burnAfterRead };
		} catch {
			state = { kind: 'error', code: 'server-error' };
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

		{:else if state.kind === 'revealed'}
			<div class="revealed" role="status">
				<div class="secret-card">
					<pre class="secret-text">{state.secret}</pre>
					<button type="button" class="btn-copy" onclick={copySecret}>
						{copied ? 'Copied!' : 'Copy'}
					</button>
				</div>
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
	}

	.brand-name {
		font-size: 14px;
		font-weight: 600;
		color: #0d0d0d;
		letter-spacing: -0.01em;
	}

	/* --- State: Ready --- */

	.ready {
		text-align: center;
		animation: fadeIn 0.35s ease;
	}

	.ready-msg {
		color: #333333;
		font-size: 16px;
		font-weight: 400;
		margin: 0 0 1.75rem;
		line-height: 1.5;
	}

	.btn-reveal {
		width: 100%;
		padding: 0.9rem 1rem;
		background: #0d0d0d;
		color: #ffffff;
		font-family: 'Inter', sans-serif;
		font-size: 15px;
		font-weight: 500;
		border: none;
		border-radius: 9999px;
		cursor: pointer;
		transition: opacity 0.2s, transform 0.1s;
	}

	.btn-reveal:hover {
		opacity: 0.85;
	}

	.btn-reveal:active {
		transform: scale(0.99);
	}

	.btn-reveal:focus-visible {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}

	/* --- State: Loading --- */

	.loading-state {
		text-align: center;
		animation: fadeIn 0.35s ease;
	}

	.loading-state p {
		color: #666666;
		font-size: 14px;
		margin: 0.75rem 0 0;
	}

	.spinner {
		display: inline-block;
		width: 24px;
		height: 24px;
		border: 2px solid #18E299;
		border-top-color: transparent;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	/* --- State: Revealed --- */

	.revealed {
		animation: fadeIn 0.35s ease;
	}

	.secret-card {
		background: #fafafa;
		border: 1px solid rgba(0, 0, 0, 0.05);
		border-radius: 16px;
		position: relative;
		overflow: hidden;
		box-shadow: rgba(0, 0, 0, 0.03) 0px 2px 4px;
	}

	.secret-text {
		margin: 0;
		padding: 1.25rem;
		padding-right: 5rem;
		color: #0d0d0d;
		font-family: 'Geist Mono', monospace;
		font-size: 14px;
		white-space: pre-wrap;
		word-break: break-all;
		line-height: 1.6;
		max-height: 300px;
		overflow-y: auto;
	}

	.btn-copy {
		position: absolute;
		top: 0.75rem;
		right: 0.75rem;
		background: #0d0d0d;
		border: none;
		color: #ffffff;
		font-family: 'Inter', sans-serif;
		font-size: 12px;
		font-weight: 500;
		padding: 0.35rem 0.85rem;
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

	.warning-box {
		margin-top: 1rem;
		padding: 0.75rem 1rem;
		border-radius: 8px;
		font-size: 13px;
		line-height: 1.5;
		display: flex;
		align-items: flex-start;
		gap: 0.5rem;
	}

	.warning-box p {
		margin: 0;
	}

	.warning-box.burn {
		background: #fffbf0;
		border: 1px solid rgba(195, 125, 13, 0.25);
		color: #c37d0d;
	}

	.warning-box:not(.burn) {
		background: #f0faf5;
		border: 1px solid rgba(24, 226, 153, 0.2);
		color: #666666;
	}

	/* --- State: Error --- */

	.error-card {
		text-align: center;
		background: #fafafa;
		border: 1px solid rgba(0, 0, 0, 0.05);
		border-radius: 16px;
		padding: 2.5rem 2rem;
		box-shadow: rgba(0, 0, 0, 0.03) 0px 2px 4px;
		animation: fadeIn 0.35s ease;
	}

	.error-icon-wrap {
		margin-bottom: 1rem;
	}

	.error-title {
		margin: 0 0 0.5rem;
		font-size: 18px;
		font-weight: 600;
		color: #d45656;
	}

	.error-detail {
		color: #666666;
		font-size: 14px;
		margin: 0 0 1.5rem;
		line-height: 1.5;
	}

	/* --- Shared --- */

	.link-home {
		display: inline-block;
		margin-top: 1.5rem;
		color: #18E299;
		font-size: 13px;
		font-weight: 500;
		text-decoration: none;
	}

	.link-home:hover {
		color: #0fa76e;
	}

	.link-home:focus-visible {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}

	@keyframes fadeIn {
		from { opacity: 0; transform: translateY(8px); }
		to { opacity: 1; transform: translateY(0); }
	}
</style>
