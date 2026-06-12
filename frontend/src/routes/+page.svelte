<script lang="ts">
	import { onMount } from 'svelte';

	// ── Live vault demo ──────────────────────────────────────────
	// Self-playing encryption pipeline in the hero. Runs entirely
	// client-side; the typed text never leaves the page.
	const DEMO_SECRET = 'sk_live_4f8aK2mQ9x';
	const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	const STATIC_CIPHER = '9hT2kLpXw4RnB7vZqJ3m';
	const STATIC_KEY = 'kG7xR2mN8pQv';

	type Stage = 'typing' | 'encrypting' | 'split' | 'burn';

	// Prerendered snapshot = the most legible stage.
	let stage: Stage = $state('split');
	let typed = $state(DEMO_SECRET);
	let cipher = $state(STATIC_CIPHER);
	let live = $state(false); // true once the loop owns the demo
	let userInput = $state('');

	let timers: ReturnType<typeof setTimeout>[] = [];
	let cycleId = 0;

	const later = (ms: number) =>
		new Promise<void>((res) => {
			timers.push(setTimeout(res, ms));
		});

	const randChar = () => B64[Math.floor(Math.random() * B64.length)];
	const randCipher = (n: number) => Array.from({ length: n }, randChar).join('');

	async function runCycle(secret: string) {
		const id = ++cycleId;
		const mine = () => id === cycleId;
		const target = randCipher(Math.max(14, Math.min(secret.length + 6, 26)));

		// 1 — type the secret
		stage = 'typing';
		typed = '';
		cipher = '';
		for (let i = 0; i < secret.length; i++) {
			if (!mine()) return;
			typed = secret.slice(0, i + 1);
			await later(55);
		}
		await later(500);
		if (!mine()) return;

		// 2 — encrypt: ciphertext resolves out of static
		stage = 'encrypting';
		const steps = 16;
		for (let s = 0; s <= steps; s++) {
			if (!mine()) return;
			const settled = Math.floor((s / steps) * target.length);
			cipher = target.slice(0, settled) + randCipher(target.length - settled);
			await later(46);
		}
		cipher = target;
		await later(420);
		if (!mine()) return;

		// 3 — split: server keeps noise, key stays with you
		stage = 'split';
		await later(2300);
		if (!mine()) return;

		// 4 — burn after read
		stage = 'burn';
		await later(1500);
		if (!mine()) return;

		runCycle(userInput.trim() ? userInput.trim().slice(0, 26) : DEMO_SECRET);
	}

	function onUserInput() {
		const v = userInput.trim().slice(0, 26);
		if (!live) return;
		runCycle(v || DEMO_SECRET);
	}

	// ── Atmosphere + scroll choreography ─────────────────────────
	let rainCanvas: HTMLCanvasElement;
	let landingEl: HTMLElement;

	onMount(() => {
		const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

		// Scroll-reveal choreography (no-JS users see everything; the
		// `js` class arms the hidden state only when we can reveal it).
		landingEl.classList.add('js');
		const io = new IntersectionObserver(
			(entries) => {
				for (const e of entries) {
					if (e.isIntersecting) {
						e.target.classList.add('sr-in');
						io.unobserve(e.target);
					}
				}
			},
			{ threshold: 0.12, rootMargin: '0px 0px -8% 0px' }
		);
		landingEl.querySelectorAll('.sr').forEach((el) => io.observe(el));

		// Live vault loop
		if (!reduced) {
			live = true;
			runCycle(DEMO_SECRET);
		}

		// Cipher rain
		let raf = 0;
		let cleanupRain = () => {};
		if (!reduced && rainCanvas) {
			const ctx = rainCanvas.getContext('2d')!;
			const GLYPHS = 'abcdef0123456789+/=';
			const FONT = 13;
			const STEP = 96; // ms per fall step
			let cols = 0;
			let drops: number[] = [];
			let speeds: number[] = [];
			let dpr = 1;

			const resize = () => {
				dpr = Math.min(window.devicePixelRatio || 1, 2);
				rainCanvas.width = window.innerWidth * dpr;
				rainCanvas.height = window.innerHeight * dpr;
				ctx.scale(dpr, dpr);
				cols = Math.floor(window.innerWidth / 30);
				drops = Array.from({ length: cols }, () => Math.random() * -60);
				speeds = Array.from({ length: cols }, () => 0.6 + Math.random() * 0.8);
				ctx.font = `${FONT}px 'Geist Mono', monospace`;
			};
			resize();

			let last = 0;
			const draw = (t: number) => {
				raf = requestAnimationFrame(draw);
				if (t - last < STEP) return;
				last = t;
				ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
				ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
				const rowH = FONT * 1.5;
				for (let i = 0; i < cols; i++) {
					const x = i * 30 + 8;
					const head = drops[i];
					for (let k = 0; k < 12; k++) {
						const y = (head - k) * rowH;
						if (y < -rowH || y > window.innerHeight + rowH) continue;
						const a = (1 - k / 12) * (k === 0 ? 0.30 : 0.13);
						ctx.fillStyle =
							k === 0 ? `rgba(120, 255, 200, ${a})` : `rgba(60, 200, 150, ${a})`;
						ctx.fillText(GLYPHS[Math.floor(Math.random() * GLYPHS.length)], x, y);
					}
					drops[i] += speeds[i];
					if ((drops[i] - 12) * rowH > window.innerHeight && Math.random() > 0.95) {
						drops[i] = Math.random() * -30;
						speeds[i] = 0.6 + Math.random() * 0.8;
					}
				}
			};
			raf = requestAnimationFrame(draw);

			const onVis = () => {
				if (document.hidden) cancelAnimationFrame(raf);
				else raf = requestAnimationFrame(draw);
			};
			window.addEventListener('resize', resize);
			document.addEventListener('visibilitychange', onVis);
			cleanupRain = () => {
				cancelAnimationFrame(raf);
				window.removeEventListener('resize', resize);
				document.removeEventListener('visibilitychange', onVis);
			};
		}

		return () => {
			cycleId++;
			timers.forEach(clearTimeout);
			io.disconnect();
			cleanupRain();
		};
	});
</script>

<svelte:head>
	<title>passwd.page — Secure secret sharing for humans and agents</title>
	<meta name="description" content="Zero-knowledge secret sharing. Send a password, API key, .env file, or any secret as an encrypted, self-destructing one-time link. End-to-end encrypted, no signup, open source. CLI, API, and MCP tool server for AI agents." />
	{@html `<script type="application/ld+json">${JSON.stringify({
		'@context': 'https://schema.org',
		'@graph': [
			{
				'@type': 'SoftwareApplication',
				name: 'passwd.page',
				description:
					'Zero-knowledge secret sharing. Send a password, API key, .env file, or any secret as an encrypted, self-destructing one-time link. End-to-end encrypted, open source, with CLI, REST API, and MCP tool server for AI agents.',
				url: 'https://passwd.page/',
				applicationCategory: 'SecurityApplication',
				operatingSystem: 'Web, Linux, macOS, Windows',
				offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
				license: 'https://opensource.org/licenses/MIT'
			},
			{
				'@type': 'FAQPage',
				mainEntity: [
					{
						'@type': 'Question',
						name: 'How do I share a password securely?',
						acceptedAnswer: {
							'@type': 'Answer',
							text: 'passwd.page encrypts your secret in your browser with AES-256-GCM and gives you a one-time link. The decryption key lives only in the URL fragment, which is never sent to the server. The recipient opens the link once and the secret is destroyed.'
						}
					},
					{
						'@type': 'Question',
						name: 'What is a one-time secret link?',
						acceptedAnswer: {
							'@type': 'Answer',
							text: 'A one-time secret link is a URL that reveals a shared secret a single time and then self-destructs (burn after reading), so the credential cannot be read again or recovered from chat history.'
						}
					},
					{
						'@type': 'Question',
						name: 'Is passwd.page really zero-knowledge?',
						acceptedAnswer: {
							'@type': 'Answer',
							text: 'Yes. Encryption happens on your device and the decryption key never reaches the server — it stays in the URL fragment after the # per the HTTP spec. The server only ever stores opaque ciphertext, so it is mathematically unable to read your secrets. The code is open source so you can verify it.'
						}
					},
					{
						'@type': 'Question',
						name: 'Can AI agents share secrets with passwd.page?',
						acceptedAnswer: {
							'@type': 'Answer',
							text: 'Yes. passwd.page ships an MCP tool server (share_secret, share_file, retrieve_secret) plus a CLI and REST API, so agents can hand off short-lived credentials without ever pasting them into a prompt.'
						}
					}
				]
			}
		]
	})}</script>`}
</svelte:head>

<div class="landing" bind:this={landingEl}>
	<canvas class="rain" bind:this={rainCanvas} aria-hidden="true"></canvas>

	<div class="page">

	<!-- Hero -->
	<section class="hero">
		<div class="contain hero-grid">
			<div class="hero-copy">
				<div class="brand-pill reveal" style="--d: 0">
					<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
						<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
					</svg>
					<span class="brand-name">passwd.page</span>
				</div>
				<h1 class="reveal" style="--d: 1">The secure<br/>secret handoff<br/>for <em>humans</em><br/>and <em>agents</em></h1>
				<p class="hero-sub reveal" style="--d: 2">
					Your agents need secrets. Pasting them into prompts gets them logged.
					Hardcoding them is worse. passwd.page is the zero-knowledge handoff &mdash;
					encrypted on your device, self-destructing, open source.
				</p>
				<div class="hero-actions reveal" style="--d: 3">
					<a href="/share" class="btn-mint">Share a Secret</a>
					<a href="#getting-started" class="btn-glass">Get Started</a>
				</div>
				<p class="hero-note reveal" style="--d: 4">No signup &middot; No app &middot; No subscription &middot; Free &amp; open source</p>
			</div>

			<!-- The live vault: a self-playing encryption pipeline -->
			<div class="vault reveal" style="--d: 2" data-stage={stage}>
				<div class="vault-bar" aria-hidden="true">
					<span class="vault-dot"></span><span class="vault-dot"></span><span class="vault-dot"></span>
					<span class="vault-title">live &mdash; runs in this tab, nothing is sent</span>
				</div>

				<div class="vault-row">
					<span class="vault-label">your secret</span>
					<div class="vault-line">
						<input
							class="vault-input"
							type="text"
							maxlength="26"
							placeholder={typed || DEMO_SECRET}
							bind:value={userInput}
							oninput={onUserInput}
							aria-label="Type anything to watch it encrypt — runs locally, nothing is sent"
						/>
						<span class="vault-typed" aria-hidden="true">{typed}<span class="caret"></span></span>
					</div>
				</div>

				<div class="vault-pipe" aria-hidden="true">
					<span class="pipe-glyph">&darr;</span> AES-256-GCM <span class="pipe-note">in your browser</span>
				</div>

				<div class="vault-row">
					<span class="vault-label">ciphertext</span>
					<div class="vault-line vault-cipher"><span class="cipher-text">{cipher}</span></div>
				</div>

				<div class="vault-split">
					<div class="split-card split-server">
						<span class="split-tag">server stores</span>
						<span class="split-noise" aria-hidden="true">&#9619;&#9618;&#9617;&#9619;&#9617;&#9618;&#9619;&#9618;&#9617;&#9619;</span>
						<span class="split-sub">opaque noise</span>
					</div>
					<div class="split-card split-key">
						<span class="split-tag">you keep</span>
						<span class="split-keytext">#{STATIC_KEY}</span>
						<span class="split-sub">key never leaves your device</span>
					</div>
				</div>

				<div class="vault-burn" aria-hidden="true">
					<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
					burned after first read
				</div>
			</div>
		</div>
	</section>

	<!-- What's new (v3) -->
	<section class="section" id="whats-new">
		<div class="contain">
			<p class="section-label sr">New in v3</p>
			<h2 class="sr">Six reasons to try it again.</h2>
			<div class="grid-2">
				<div class="card sr">
					<h3>📱 QR code on every link</h3>
					<p class="card-body">Shared from laptop, opening on your phone? Scan. Done. No 64-character URL typing.</p>
				</div>
				<div class="card sr">
					<h3>📎 Files, not just passwords</h3>
					<p class="card-body">Drag &amp; drop any file up to 1 MB. SSH keys, <code>.env</code> files, certs. Encrypted in your browser before it leaves.</p>
				</div>
				<div class="card sr">
					<h3>🔐 Optional passphrase</h3>
					<p class="card-body">Second factor for the paranoid. PBKDF2-hardened, never sent to the server. Even if the link leaks, the secret doesn't.</p>
				</div>
				<div class="card sr">
					<h3>🏷️ Typed secrets</h3>
					<p class="card-body">Tell the receiving agent it's an <code>api_key</code> vs a <code>postgres_url</code>. Eight types. Schema hints for the agent era.</p>
				</div>
				<div class="card sr">
					<h3>⏱️ Five-minute TTLs</h3>
					<p class="card-body">For when your agent needs a token <em>right now</em> and never again. Also 15m, 1h, 24h, 7d, 30d.</p>
				</div>
				<div class="card sr">
					<h3>🐳 Self-host in 60 seconds</h3>
					<p class="card-body"><code>docker compose up -d</code>. Or drop the systemd unit. See <a href="https://github.com/davidfeldi/passwd-page/blob/main/SELF_HOSTING.md">SELF_HOSTING.md</a>.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- Problem -->
	<section class="section" id="problem">
		<div class="contain">
			<p class="section-label sr">The problem</p>
			<h2 class="sr">Secrets are everywhere.<br/>Secure handoff is nowhere.</h2>
			<div class="grid-2">
				<div class="card card-problem sr">
					<p class="card-bad">Pasting API keys into an LLM session</p>
					<p class="card-body">Logged, stored, potentially trained on. Your secret is now someone else's data.</p>
				</div>
				<div class="card card-problem sr">
					<p class="card-bad">Slacking a .env file to a teammate</p>
					<p class="card-body">Plaintext, forever searchable, accessible to every admin and compliance tool.</p>
				</div>
				<div class="card card-problem sr">
					<p class="card-bad">Hardcoding secrets in agent configs</p>
					<p class="card-body">Plaintext on disk. One <code>git add .</code> away from being public.</p>
				</div>
				<div class="card card-problem sr">
					<p class="card-bad">Giving agents full vault access</p>
					<p class="card-body">Over-privileged. Your agent can read every secret, not just the one it needs.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- How it works -->
	<section class="section" id="how-it-works">
		<div class="contain">
			<p class="section-label sr">How it works</p>
			<h2 class="sr">Three steps. Zero knowledge.</h2>
			<div class="steps">
				<div class="step sr">
					<div class="step-num">1</div>
					<div>
						<h3>Encrypted on your device</h3>
						<p>AES-256-GCM encryption runs in your browser, your CLI, or your agent. The encryption key never touches our servers.</p>
					</div>
				</div>
				<div class="step sr">
					<div class="step-num">2</div>
					<div>
						<h3>We only store noise</h3>
						<p>Our server stores encrypted gibberish. The decryption key lives in the URL fragment &mdash; never sent to us per the HTTP spec. Even if we get breached, your secrets are safe.</p>
					</div>
				</div>
				<div class="step sr">
					<div class="step-num">3</div>
					<div>
						<h3>Read once, gone forever</h3>
						<p>The moment the recipient retrieves the secret, it's destroyed on the server. No copies, no backups, no traces.</p>
					</div>
				</div>
			</div>
			<div class="url-diagram glass sr">
				<code class="mono-label">URL structure</code>
				<pre>passwd.page/s/&#123;id&#125;#&#123;key&#125;
              <span class="dim">^^^^^^</span>    <span class="dim">^^^^^</span>
          <span class="dim">server sees</span>  <span class="accent-text">server NEVER sees</span></pre>
			</div>
		</div>
	</section>

	<!-- Use cases -->
	<section class="section" id="use-cases">
		<div class="contain">
			<p class="section-label sr">Use cases</p>
			<h2 class="sr">Every direction. Every principal.</h2>
			<div class="grid-2">
				<div class="card sr">
					<span class="case-label">Human &rarr; Human</span>
					<p class="card-body">Share a database password with your teammate. They open the link, see it once, it's gone. No more "check Slack from 3 months ago."</p>
				</div>
				<div class="card sr">
					<span class="case-label">Human &rarr; Agent</span>
					<p class="card-body">Create a link via browser or CLI. Tell your agent "use the credentials at this URL." The agent retrieves and decrypts at runtime &mdash; the secret never enters the prompt.</p>
				</div>
				<div class="card sr">
					<span class="case-label">Agent &rarr; Human</span>
					<p class="card-body">Your agent runs <code>share_file</code> on a generated credential &mdash; encrypts it without ever reading it into context. You get a self-destructing link.</p>
				</div>
				<div class="card sr">
					<span class="case-label">Agent &rarr; Agent</span>
					<p class="card-body">One service hands a short-lived token to another. Encrypted, ephemeral, zero trust. The way machine-to-machine should work.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- Getting started -->
	<section class="section" id="getting-started">
		<div class="contain">
			<p class="section-label sr">Getting started</p>
			<h2 class="sr">Three ways to share a secret.</h2>
			<div class="grid-3">
				<div class="card gs-card sr">
					<h3>Browser</h3>
					<p class="gs-desc">The simplest way. No install.</p>
					<div class="gs-steps">
						<p>1. Go to <a href="/share">passwd.page/share</a></p>
						<p>2. Paste a secret <em>or</em> drop a file</p>
						<p>3. Pick TTL, optional passphrase</p>
						<p>4. Copy link or scan the QR</p>
					</div>
				</div>
				<div class="card gs-card sr">
					<h3>CLI</h3>
					<p class="gs-desc">For your terminal and scripts.</p>
					<pre class="code-block"><span class="c-dim"># Install</span>
brew install davidfeldi/tap/passwd-page

<span class="c-dim"># Share a typed secret, 5 min TTL</span>
passwd-page create "sk_live_..." --type api_key --ttl 5m
<span class="c-green"># https://passwd.page/s/a3f8#kG7...</span>

<span class="c-dim"># Retrieve it</span>
passwd-page get "https://passwd.page/s/a3f8#kG7..."
<span class="c-green"># sk_live_...</span>

<span class="c-dim"># From a file (1 MB max)</span>
passwd-page create --file .env --type env_file</pre>
				</div>
				<div class="card gs-card sr">
					<h3>AI Agent</h3>
					<p class="gs-desc">MCP tool server. The agent never sees the secret.</p>
					<pre class="code-block"><span class="c-dim">// claude code settings.json</span>
&#123;
  "mcpServers": &#123;
    "passwd": &#123;
      "command": "passwd-mcp"
    &#125;
  &#125;
&#125;</pre>
					<p class="gs-hint"><strong>share_secret</strong> &mdash; hand the agent a plaintext value, get back a link.<br/>
					<strong>share_file</strong> &mdash; "Encrypt my .env" &rarr; agent reads the path, never the contents.<br/>
					<strong>retrieve_secret</strong> &mdash; agent fetches + decrypts at runtime. Returns the <code>type</code> so it knows the schema.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- Features -->
	<section class="section" id="features">
		<div class="contain">
			<p class="section-label sr">Why passwd.page</p>
			<h2 class="sr">Built different.</h2>
			<div class="grid-2">
				<div class="card sr">
					<h3>Truly zero knowledge</h3>
					<p class="card-body">Not "trust us" zero knowledge. Mathematically impossible for us to read your secrets. Open source &mdash; verify it yourself.</p>
				</div>
				<div class="card sr">
					<h3>Single binary. Self-hostable.</h3>
					<p class="card-body">One Go binary, embeds the entire frontend. <code>docker run passwd-page</code> and you own your infrastructure. No external dependencies.</p>
				</div>
				<div class="card sr">
					<h3>Built for automation</h3>
					<p class="card-body">CLI pipes, MCP tools, REST API. Every interface your workflow needs. <code>echo $SECRET | passwd create</code></p>
				</div>
				<div class="card sr">
					<h3>Nothing to remember</h3>
					<p class="card-body">No accounts. No master passwords. No subscription. Share a secret, get a link, done. The way it should be.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- FAQ -->
	<section class="section" id="faq">
		<div class="contain">
			<p class="section-label sr">FAQ</p>
			<h2 class="sr">One-time secret links, explained.</h2>
			<div class="faq-list">
				<div class="faq-item sr">
					<h3>How do I share a password securely?</h3>
					<p>Paste it, get a link, send the link. passwd.page encrypts the password in your browser with AES-256-GCM and hands you a <strong>one-time secret link</strong>. The decryption key lives only in the URL fragment and is never sent to the server. The recipient opens it once and the secret self-destructs.</p>
				</div>
				<div class="faq-item sr">
					<h3>What is a one-time secret link?</h3>
					<p>A URL that reveals a shared secret a single time, then burns after reading. No copies in Slack, no plaintext in email, nothing left to leak from chat history. Perfect for ephemeral secret sharing &mdash; temporary passwords, API keys, database URLs.</p>
				</div>
				<div class="faq-item sr">
					<h3>Is it really zero-knowledge?</h3>
					<p>Yes. Encryption runs on your device and the key never reaches our servers. We only store opaque ciphertext, so we are mathematically unable to read your secrets &mdash; even under subpoena or breach. It's open source, so you can verify it yourself.</p>
				</div>
				<div class="faq-item sr">
					<h3>Can AI agents share secrets with it?</h3>
					<p>Yes. An MCP tool server (<code>share_secret</code>, <code>share_file</code>, <code>retrieve_secret</code>), a CLI, and a REST API let agents hand off short-lived credentials without ever pasting them into a prompt.</p>
				</div>
				<div class="faq-item sr">
					<h3>How is this different from emailing a password?</h3>
					<p>Email and chat keep secrets in plaintext forever, searchable and accessible to admins and compliance tools. passwd.page secrets are end-to-end encrypted, expire on a timer (5 minutes to 30 days), and can self-destruct on first read.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- CTA -->
	<section class="section-cta">
		<div class="contain cta-content sr">
			<h2>Stop pasting secrets<br/>into chat windows.</h2>
			<p>Your agents deserve better. Your teammates deserve better.</p>
			<div class="hero-actions">
				<a href="/share" class="btn-mint">Share a Secret</a>
				<a href="https://github.com/davidfeldi/passwd-page" class="btn-glass">View on GitHub</a>
			</div>
		</div>
	</section>

	<!-- Footer -->
	<footer class="site-footer">
		<div class="contain footer-inner">
			<div class="footer-brand">
				<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
					<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
					<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
				</svg>
				<span>passwd.page</span>
			</div>
			<p class="footer-tagline">Open source &middot; End-to-end encrypted &middot; Built for the age of agents</p>
			<nav class="footer-links">
				<a href="https://github.com/davidfeldi/passwd-page">GitHub</a>
				<a href="https://github.com/davidfeldi/passwd-page#api">API</a>
				<a href="https://github.com/davidfeldi/passwd-page#cli-usage">CLI</a>
				<a href="https://github.com/davidfeldi/passwd-page#mcp-tool-server">MCP</a>
				<a href="https://github.com/davidfeldi/passwd-page#self-hosting">Self-host</a>
			</nav>
		</div>
	</footer>

	</div>
</div>

<style>
	/* ── Base ── */
	.landing {
		color: var(--ink-dim);
		line-height: 1.6;
		position: relative;
	}

	.rain {
		position: fixed;
		inset: 0;
		z-index: 0;
		pointer-events: none;
		mask-image: radial-gradient(ellipse 80% 70% at 50% 30%, black 30%, transparent 90%);
		-webkit-mask-image: radial-gradient(ellipse 80% 70% at 50% 30%, black 30%, transparent 90%);
	}

	.page {
		position: relative;
		z-index: 1;
	}

	.contain {
		max-width: 1080px;
		margin: 0 auto;
		padding: 0 24px;
	}

	/* ── Load reveal (hero) ── */
	.reveal {
		animation: rise 0.8s cubic-bezier(0.2, 0.7, 0.2, 1) both;
		animation-delay: calc(var(--d) * 120ms);
	}

	@keyframes rise {
		from { opacity: 0; transform: translateY(22px); filter: blur(5px); }
		to { opacity: 1; transform: translateY(0); filter: blur(0); }
	}

	/* Scroll choreography (.sr / .sr-in) lives in app.css — the classes
	   are toggled at runtime, so component-scoped rules get pruned by
	   Svelte's unused-CSS elimination. */

	/* ── Section rhythm ── */
	.section {
		padding: 104px 0;
		border-top: 1px solid rgba(255, 255, 255, 0.04);
	}

	.section-label {
		font-family: var(--font-mono);
		font-size: 12px;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.16em;
		color: var(--mint);
		margin-bottom: 14px;
	}

	.section h2 {
		font-family: var(--font-display);
		font-size: clamp(30px, 4.6vw, 46px);
		font-weight: 600;
		color: var(--ink);
		letter-spacing: -0.02em;
		line-height: 1.06;
		margin: 0 0 48px 0;
	}

	/* ── Hero ── */
	.hero {
		position: relative;
		min-height: 94vh;
		display: flex;
		align-items: center;
		padding: 96px 0 72px;
		overflow: hidden;
	}

	.hero-grid {
		display: grid;
		grid-template-columns: minmax(0, 1.05fr) minmax(0, 1fr);
		gap: 56px;
		align-items: center;
		width: 100%;
	}

	.hero-copy {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
	}

	h1 {
		font-family: var(--font-display);
		font-size: clamp(42px, 5.4vw, 64px);
		font-weight: 600;
		color: var(--ink);
		line-height: 1.02;
		letter-spacing: -0.028em;
		margin: 28px 0 22px;
	}

	h1 em {
		font-style: normal;
		color: var(--mint);
		text-shadow: 0 0 36px var(--mint-glow);
	}

	.hero-sub {
		font-size: 17px;
		color: var(--ink-dim);
		max-width: 460px;
		margin: 0 0 36px;
		line-height: 1.65;
	}

	.hero-actions {
		display: flex;
		gap: 14px;
		margin: 0 0 18px;
	}

	.hero-note {
		font-size: 13px;
		color: var(--ink-faint);
	}

	/* ── The vault ── */
	.vault {
		position: relative;
		font-family: var(--font-mono);
		background: linear-gradient(165deg, rgba(255, 255, 255, 0.07), rgba(255, 255, 255, 0.02));
		border: 1px solid var(--line-strong);
		border-radius: 22px;
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.09),
			0 40px 80px -36px rgba(0, 0, 0, 0.85),
			0 0 70px -36px var(--mint-glow);
		backdrop-filter: blur(28px);
		-webkit-backdrop-filter: blur(28px);
		padding: 0 0 18px;
		overflow: hidden;
	}

	.vault-bar {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 13px 16px;
		border-bottom: 1px solid rgba(255, 255, 255, 0.06);
		margin-bottom: 18px;
	}

	.vault-dot {
		width: 9px;
		height: 9px;
		border-radius: 50%;
		background: rgba(255, 255, 255, 0.14);
	}

	.vault-title {
		margin-left: 10px;
		font-size: 10px;
		letter-spacing: 0.1em;
		text-transform: uppercase;
		color: var(--ink-faint);
	}

	.vault-row {
		padding: 4px 20px;
	}

	.vault-label {
		display: block;
		font-size: 10px;
		letter-spacing: 0.12em;
		text-transform: uppercase;
		color: var(--ink-faint);
		margin-bottom: 5px;
	}

	.vault-line {
		position: relative;
		min-height: 38px;
		display: flex;
		align-items: center;
		background: rgba(0, 0, 0, 0.34);
		border: 1px solid rgba(255, 255, 255, 0.07);
		border-radius: 10px;
		padding: 0 13px;
		font-size: 14px;
	}

	.vault-input {
		position: absolute;
		inset: 0;
		width: 100%;
		background: transparent;
		border: none;
		outline: none;
		color: transparent;
		caret-color: var(--mint);
		font-family: var(--font-mono);
		font-size: 14px;
		padding: 0 13px;
	}

	.vault-input::placeholder { color: transparent; }

	.vault-input:focus { color: var(--ink); }
	.vault-input:focus + .vault-typed { opacity: 0; }

	.vault-typed {
		color: var(--ink);
		pointer-events: none;
		white-space: nowrap;
		overflow: hidden;
	}

	.caret {
		display: inline-block;
		width: 8px;
		height: 16px;
		margin-left: 2px;
		background: var(--mint);
		vertical-align: text-bottom;
		animation: blink 1s steps(2) infinite;
		opacity: 0;
	}

	.vault[data-stage='typing'] .caret { opacity: 1; }

	@keyframes blink { 50% { opacity: 0; } }

	.vault-pipe {
		padding: 10px 20px 6px;
		font-size: 11px;
		letter-spacing: 0.06em;
		color: var(--ink-faint);
		transition: color 0.3s, text-shadow 0.3s;
	}

	.pipe-glyph { color: var(--mint); margin-right: 6px; }

	.pipe-note { opacity: 0.7; margin-left: 6px; }

	.vault[data-stage='encrypting'] .vault-pipe {
		color: var(--mint);
		text-shadow: 0 0 18px var(--mint-glow);
	}

	.vault-cipher .cipher-text {
		color: var(--mint-dark);
		letter-spacing: 0.04em;
		white-space: nowrap;
		overflow: hidden;
		transition: opacity 0.4s, filter 0.4s;
	}

	.vault[data-stage='encrypting'] .cipher-text {
		color: var(--mint);
		text-shadow: 0 0 14px var(--mint-glow);
	}

	.vault[data-stage='burn'] .cipher-text {
		opacity: 0;
		filter: blur(6px);
	}

	/* split: server noise vs your key */
	.vault-split {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 10px;
		padding: 16px 20px 4px;
	}

	.split-card {
		border-radius: 12px;
		padding: 12px 14px;
		display: flex;
		flex-direction: column;
		gap: 4px;
		transition: opacity 0.5s, transform 0.5s, box-shadow 0.5s, border-color 0.5s;
		opacity: 0.45;
		transform: translateY(4px);
	}

	.vault[data-stage='split'] .split-card,
	.vault[data-stage='burn'] .split-card {
		opacity: 1;
		transform: translateY(0);
	}

	.split-server {
		background: rgba(0, 0, 0, 0.3);
		border: 1px solid rgba(255, 255, 255, 0.07);
	}

	.split-key {
		background: linear-gradient(160deg, rgba(60, 242, 176, 0.13), rgba(60, 242, 176, 0.04));
		border: 1px solid rgba(60, 242, 176, 0.3);
	}

	.vault[data-stage='split'] .split-key {
		box-shadow: 0 0 34px -8px var(--mint-glow), inset 0 1px 0 rgba(255, 255, 255, 0.12);
	}

	.split-tag {
		font-size: 9px;
		letter-spacing: 0.14em;
		text-transform: uppercase;
		color: var(--ink-faint);
	}

	.split-key .split-tag { color: var(--mint-dark); }

	.split-noise {
		font-size: 14px;
		color: var(--ink-faint);
		letter-spacing: 2px;
	}

	.split-keytext {
		font-size: 14px;
		color: var(--mint);
		font-weight: 500;
		text-shadow: 0 0 16px var(--mint-glow);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.split-sub {
		font-size: 10px;
		color: var(--ink-faint);
	}

	.split-key .split-sub { color: rgba(60, 242, 176, 0.75); }

	.vault-burn {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		margin: 14px 20px 0;
		padding: 8px;
		border-radius: 10px;
		font-size: 11px;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--warning);
		background: rgba(255, 197, 107, 0.05);
		border: 1px solid rgba(255, 197, 107, 0.14);
		opacity: 0.35;
		transition: opacity 0.4s, box-shadow 0.4s;
	}

	.vault[data-stage='burn'] .vault-burn {
		opacity: 1;
		box-shadow: 0 0 30px -10px rgba(255, 197, 107, 0.5);
		animation: burnPulse 1.4s ease both;
	}

	@keyframes burnPulse {
		0% { transform: scale(1); }
		12% { transform: scale(1.03); }
		100% { transform: scale(1); }
	}

	/* ── Buttons ── */
	.btn-mint {
		display: inline-block;
		padding: 12px 30px;
		background: linear-gradient(180deg, var(--mint), var(--mint-deep));
		color: #04140d;
		font-family: var(--font-body);
		font-weight: 600;
		font-size: 15px;
		border-radius: var(--r-pill);
		text-decoration: none;
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.4),
			0 12px 28px -10px var(--mint-glow);
		transition: transform 0.15s, box-shadow 0.2s, filter 0.2s;
	}

	.btn-mint:hover {
		color: #04140d;
		filter: brightness(1.06);
		transform: translateY(-1px);
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.4),
			0 16px 36px -10px var(--mint-glow);
	}

	.btn-mint:active { transform: translateY(0) scale(0.99); }

	.btn-glass {
		display: inline-block;
		padding: 12px 30px;
		background: var(--glass-bg);
		color: var(--ink);
		font-family: var(--font-body);
		font-weight: 500;
		font-size: 15px;
		border-radius: var(--r-pill);
		border: 1px solid var(--line);
		backdrop-filter: blur(16px);
		-webkit-backdrop-filter: blur(16px);
		text-decoration: none;
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06);
		transition: border-color 0.2s, background 0.2s, transform 0.15s;
	}

	.btn-glass:hover {
		color: var(--ink);
		border-color: var(--line-strong);
		background: var(--glass-bg-strong);
		transform: translateY(-1px);
	}

	/* ── Cards: glass + conic glow border on hover ── */
	.grid-2 {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 16px;
	}

	.grid-3 {
		display: grid;
		grid-template-columns: 1fr 1fr 1fr;
		gap: 16px;
	}

	@property --spin {
		syntax: '<angle>';
		initial-value: 0deg;
		inherits: false;
	}

	.card {
		position: relative;
		background: var(--glass-bg);
		border: 1px solid transparent;
		background-clip: padding-box;
		border-radius: var(--r-card);
		padding: 28px;
		box-shadow: var(--glass-shadow);
		backdrop-filter: blur(24px);
		-webkit-backdrop-filter: blur(24px);
		transition: transform 0.25s, box-shadow 0.25s;
	}

	.card::before {
		content: '';
		position: absolute;
		inset: -1px;
		z-index: -1;
		border-radius: inherit;
		background: rgba(255, 255, 255, 0.08);
		transition: background 0.3s;
	}

	.card:hover {
		transform: translateY(-3px);
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.07),
			0 32px 60px -26px rgba(0, 0, 0, 0.75),
			0 0 44px -20px var(--mint-glow);
	}

	.card:hover::before {
		background: conic-gradient(
			from var(--spin),
			rgba(60, 242, 176, 0.5),
			rgba(255, 255, 255, 0.07) 25%,
			rgba(123, 224, 255, 0.3) 50%,
			rgba(255, 255, 255, 0.07) 75%,
			rgba(60, 242, 176, 0.5)
		);
		animation: spinBorder 3.2s linear infinite;
	}

	@keyframes spinBorder {
		to { --spin: 360deg; }
	}

	.card h3 {
		font-family: var(--font-display);
		font-size: 18px;
		font-weight: 600;
		color: var(--ink);
		letter-spacing: -0.01em;
		margin: 0 0 8px 0;
		line-height: 1.3;
	}

	.card-body {
		font-size: 15px;
		color: var(--ink-dim);
		line-height: 1.6;
		margin: 0;
	}

	.card-problem::before { background: rgba(255, 115, 115, 0.16); }

	.card-problem:hover::before {
		background: conic-gradient(
			from var(--spin),
			rgba(255, 115, 115, 0.5),
			rgba(255, 255, 255, 0.07) 35%,
			rgba(255, 115, 115, 0.2) 70%,
			rgba(255, 115, 115, 0.5)
		);
		animation: spinBorder 3.2s linear infinite;
	}

	.card-problem:hover {
		box-shadow:
			inset 0 1px 0 rgba(255, 255, 255, 0.07),
			0 32px 60px -26px rgba(0, 0, 0, 0.75),
			0 0 44px -20px rgba(255, 115, 115, 0.3);
	}

	.card-bad {
		font-weight: 600;
		color: var(--danger);
		font-size: 15px;
		margin: 0 0 6px 0;
	}

	.card code, .faq-item code {
		font-family: var(--font-mono);
		font-size: 13px;
		background: rgba(255, 255, 255, 0.06);
		border: 1px solid rgba(255, 255, 255, 0.06);
		padding: 2px 7px;
		border-radius: 6px;
		color: var(--ink);
	}

	.case-label {
		display: inline-block;
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--mint);
		background: rgba(60, 242, 176, 0.1);
		border: 1px solid rgba(60, 242, 176, 0.22);
		padding: 5px 13px;
		border-radius: var(--r-pill);
		margin-bottom: 14px;
	}

	/* ── Steps ── */
	.steps {
		display: flex;
		flex-direction: column;
		gap: 22px;
		margin-bottom: 48px;
	}

	.step {
		display: flex;
		gap: 20px;
		align-items: flex-start;
	}

	.step-num {
		flex-shrink: 0;
		width: 40px;
		height: 40px;
		display: flex;
		align-items: center;
		justify-content: center;
		background: linear-gradient(160deg, rgba(60, 242, 176, 0.16), rgba(60, 242, 176, 0.05));
		border: 1px solid rgba(60, 242, 176, 0.3);
		color: var(--mint);
		font-family: var(--font-mono);
		font-weight: 600;
		font-size: 15px;
		border-radius: var(--r-pill);
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.1), 0 0 22px -8px var(--mint-glow);
	}

	.step h3 {
		font-family: var(--font-display);
		font-size: 19px;
		font-weight: 600;
		color: var(--ink);
		letter-spacing: -0.01em;
		margin: 6px 0 4px;
	}

	.step p {
		font-size: 15px;
		color: var(--ink-dim);
		line-height: 1.6;
		margin: 0;
	}

	/* ── URL diagram ── */
	.url-diagram {
		padding: 26px 28px;
		text-align: center;
	}

	.mono-label {
		font-family: var(--font-mono);
		font-size: 10px;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.14em;
		color: var(--ink-faint);
		display: block;
		margin-bottom: 14px;
	}

	.url-diagram pre {
		font-family: var(--font-mono);
		font-size: 14px;
		line-height: 1.6;
		color: var(--ink);
		margin: 0;
		white-space: pre;
		overflow-x: auto;
	}

	.dim { color: var(--ink-faint); }
	.accent-text { color: var(--mint); font-weight: 600; text-shadow: 0 0 16px var(--mint-glow); }

	/* ── Getting started ── */
	.gs-card h3 {
		font-family: var(--font-display);
		font-size: 18px;
		font-weight: 600;
		color: var(--ink);
		margin: 0 0 4px 0;
	}

	.gs-desc {
		font-size: 14px;
		color: var(--ink-faint);
		margin: 0 0 16px 0;
	}

	.gs-steps p {
		font-size: 14px;
		color: var(--ink-dim);
		margin: 0 0 5px 0;
		line-height: 1.6;
	}

	.gs-hint {
		font-size: 13px;
		color: var(--ink-dim);
		margin: 12px 0 0 0;
		line-height: 1.55;
	}

	.gs-hint strong { color: var(--ink); }

	.code-block {
		background: rgba(0, 0, 0, 0.35);
		border: 1px solid rgba(255, 255, 255, 0.06);
		border-radius: 12px;
		padding: 16px;
		overflow-x: auto;
		font-family: var(--font-mono);
		font-size: 12px;
		line-height: 1.7;
		color: var(--ink);
		white-space: pre;
		margin: 0;
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
	}

	.c-dim { color: var(--ink-faint); }
	.c-green { color: var(--mint-dark); }

	/* ── FAQ ── */
	.faq-list {
		display: flex;
		flex-direction: column;
		gap: 26px;
		max-width: 760px;
	}

	.faq-item h3 {
		font-family: var(--font-display);
		font-size: 18px;
		font-weight: 600;
		color: var(--ink);
		letter-spacing: -0.01em;
		margin: 0 0 6px 0;
	}

	.faq-item p {
		font-size: 15px;
		color: var(--ink-dim);
		line-height: 1.65;
		margin: 0;
	}

	.faq-item strong { color: var(--ink); }

	/* ── CTA ── */
	.section-cta {
		padding: 130px 0;
		text-align: center;
		border-top: 1px solid rgba(255, 255, 255, 0.04);
		background: radial-gradient(ellipse 60% 80% at 50% 115%, rgba(24, 226, 153, 0.1), transparent 70%);
	}

	.section-cta h2 {
		font-family: var(--font-display);
		font-size: clamp(34px, 5.4vw, 56px);
		font-weight: 600;
		color: var(--ink);
		letter-spacing: -0.025em;
		line-height: 1.05;
		margin: 0 0 14px 0;
	}

	.section-cta p {
		font-size: 18px;
		color: var(--ink-dim);
		margin: 0 0 12px 0;
	}

	.section-cta .hero-actions { justify-content: center; margin-top: 24px; }

	/* ── Footer ── */
	.site-footer {
		padding: 36px 0;
		border-top: 1px solid rgba(255, 255, 255, 0.05);
	}

	.footer-inner { text-align: center; }

	.footer-brand {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-family: var(--font-mono);
		font-weight: 600;
		font-size: 13px;
		color: var(--ink);
		margin-bottom: 6px;
	}

	.footer-brand svg { color: var(--mint); }

	.footer-tagline {
		font-size: 13px;
		color: var(--ink-faint);
		margin: 0 0 16px 0;
	}

	.footer-links {
		display: flex;
		gap: 24px;
		justify-content: center;
	}

	.footer-links a {
		font-size: 13px;
		font-weight: 500;
		color: var(--ink-faint);
	}

	.footer-links a:hover { color: var(--mint); }

	/* ── Responsive ── */
	@media (max-width: 920px) {
		.hero-grid {
			grid-template-columns: 1fr;
			gap: 44px;
		}

		.hero-copy { align-items: center; text-align: center; }

		.hero-sub { margin-inline: auto; }

		h1 br { display: none; }

		.hero { min-height: auto; padding: 88px 0 56px; }
	}

	@media (max-width: 768px) {
		.section { padding: 64px 0; }

		.grid-2, .grid-3 { grid-template-columns: 1fr; }

		.hero-actions { flex-direction: column; align-items: center; }

		.vault-split { grid-template-columns: 1fr; }

		.section-cta { padding: 80px 0; }
	}
</style>
