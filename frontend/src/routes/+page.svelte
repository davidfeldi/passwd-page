<svelte:head>
	<title>passwd.page — Secure secret sharing for humans and agents</title>
	<meta name="description" content="Zero-knowledge secret sharing. End-to-end encrypted, self-destructing, open source. CLI, API, and MCP tool server for AI agents." />
	<link rel="preconnect" href="https://fonts.googleapis.com" />
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
	<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Geist+Mono:wght@500;600&display=swap" rel="stylesheet" />
</svelte:head>

<div class="landing">

	<!-- Hero -->
	<section class="hero">
		<div class="hero-glow"></div>
		<div class="contain hero-content">
			<div class="hero-badge">
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
					<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
					<path d="M7 11V7a5 5 0 0 1 10 0v4"/>
				</svg>
				<span>passwd.page</span>
			</div>
			<h1>The secure secret handoff<br/>for <em>humans</em> and <em>agents</em></h1>
			<p class="hero-sub">
				Your agents need secrets. Pasting them into prompts gets them logged.
				Hardcoding them is worse. passwd.page is the zero-knowledge handoff &mdash;
				encrypted on your device, self-destructing, open source.
			</p>
			<div class="hero-actions">
				<a href="/share" class="btn-dark">Share a Secret</a>
				<a href="#getting-started" class="btn-ghost">Get Started</a>
			</div>
			<p class="hero-note">No signup &middot; No app &middot; No subscription &middot; Free &amp; open source</p>
		</div>
	</section>

	<!-- What's new (v3) -->
	<section class="section" id="whats-new">
		<div class="contain">
			<p class="section-label">New in v3</p>
			<h2>Six reasons to try it again.</h2>
			<div class="grid-2">
				<div class="card">
					<h3>📱 QR code on every link</h3>
					<p class="card-body">Shared from laptop, opening on your phone? Scan. Done. No 64-character URL typing.</p>
				</div>
				<div class="card">
					<h3>📎 Files, not just passwords</h3>
					<p class="card-body">Drag &amp; drop any file up to 1 MB. SSH keys, <code>.env</code> files, certs. Encrypted in your browser before it leaves.</p>
				</div>
				<div class="card">
					<h3>🔐 Optional passphrase</h3>
					<p class="card-body">Second factor for the paranoid. PBKDF2-hardened, never sent to the server. Even if the link leaks, the secret doesn't.</p>
				</div>
				<div class="card">
					<h3>🏷️ Typed secrets</h3>
					<p class="card-body">Tell the receiving agent it's an <code>api_key</code> vs a <code>postgres_url</code>. Eight types. Schema hints for the agent era.</p>
				</div>
				<div class="card">
					<h3>⏱️ Five-minute TTLs</h3>
					<p class="card-body">For when your agent needs a token <em>right now</em> and never again. Also 15m, 1h, 24h, 7d, 30d.</p>
				</div>
				<div class="card">
					<h3>🐳 Self-host in 60 seconds</h3>
					<p class="card-body"><code>docker compose up -d</code>. Or drop the systemd unit. See <a href="https://github.com/davidfeldi/passwd-page/blob/main/SELF_HOSTING.md">SELF_HOSTING.md</a>.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- Problem -->
	<section class="section" id="problem">
		<div class="contain">
			<p class="section-label">The problem</p>
			<h2>Secrets are everywhere.<br/>Secure handoff is nowhere.</h2>
			<div class="grid-2">
				<div class="card">
					<p class="card-bad">Pasting API keys into an LLM session</p>
					<p class="card-body">Logged, stored, potentially trained on. Your secret is now someone else's data.</p>
				</div>
				<div class="card">
					<p class="card-bad">Slacking a .env file to a teammate</p>
					<p class="card-body">Plaintext, forever searchable, accessible to every admin and compliance tool.</p>
				</div>
				<div class="card">
					<p class="card-bad">Hardcoding secrets in agent configs</p>
					<p class="card-body">Plaintext on disk. One <code>git add .</code> away from being public.</p>
				</div>
				<div class="card">
					<p class="card-bad">Giving agents full vault access</p>
					<p class="card-body">Over-privileged. Your agent can read every secret, not just the one it needs.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- How it works -->
	<section class="section" id="how-it-works">
		<div class="contain">
			<p class="section-label">How it works</p>
			<h2>Three steps. Zero knowledge.</h2>
			<div class="steps">
				<div class="step">
					<div class="step-num">1</div>
					<div>
						<h3>Encrypted on your device</h3>
						<p>AES-256-GCM encryption runs in your browser, your CLI, or your agent. The encryption key never touches our servers.</p>
					</div>
				</div>
				<div class="step">
					<div class="step-num">2</div>
					<div>
						<h3>We only store noise</h3>
						<p>Our server stores encrypted gibberish. The decryption key lives in the URL fragment &mdash; never sent to us per the HTTP spec. Even if we get breached, your secrets are safe.</p>
					</div>
				</div>
				<div class="step">
					<div class="step-num">3</div>
					<div>
						<h3>Read once, gone forever</h3>
						<p>The moment the recipient retrieves the secret, it's destroyed on the server. No copies, no backups, no traces.</p>
					</div>
				</div>
			</div>
			<div class="url-diagram">
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
			<p class="section-label">Use cases</p>
			<h2>Every direction. Every principal.</h2>
			<div class="grid-2">
				<div class="card">
					<span class="case-label">Human &rarr; Human</span>
					<p class="card-body">Share a database password with your teammate. They open the link, see it once, it's gone. No more "check Slack from 3 months ago."</p>
				</div>
				<div class="card">
					<span class="case-label">Human &rarr; Agent</span>
					<p class="card-body">Create a link via browser or CLI. Tell your agent "use the credentials at this URL." The agent retrieves and decrypts at runtime &mdash; the secret never enters the prompt.</p>
				</div>
				<div class="card">
					<span class="case-label">Agent &rarr; Human</span>
					<p class="card-body">Your agent runs <code>share_file</code> on a generated credential &mdash; encrypts it without ever reading it into context. You get a self-destructing link.</p>
				</div>
				<div class="card">
					<span class="case-label">Agent &rarr; Agent</span>
					<p class="card-body">One service hands a short-lived token to another. Encrypted, ephemeral, zero trust. The way machine-to-machine should work.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- Getting started -->
	<section class="section" id="getting-started">
		<div class="contain">
			<p class="section-label">Getting started</p>
			<h2>Three ways to share a secret.</h2>
			<div class="grid-3">
				<div class="card gs-card">
					<h3>Browser</h3>
					<p class="gs-desc">The simplest way. No install.</p>
					<div class="gs-steps">
						<p>1. Go to <a href="/share">passwd.page/share</a></p>
						<p>2. Paste a secret <em>or</em> drop a file</p>
						<p>3. Pick TTL, optional passphrase</p>
						<p>4. Copy link or scan the QR</p>
					</div>
				</div>
				<div class="card gs-card">
					<h3>CLI</h3>
					<p class="gs-desc">For your terminal and scripts.</p>
					<pre class="code-block"><span class="c-dim"># Share a typed secret, 5 min TTL</span>
passwd create "sk_live_..." --type api_key --ttl 5m
<span class="c-green"># https://passwd.page/s/a3f8#kG7...</span>

<span class="c-dim"># Retrieve it</span>
passwd get "https://passwd.page/s/a3f8#kG7..."
<span class="c-green"># sk_live_...</span>

<span class="c-dim"># From a file (1 MB max)</span>
passwd create --file .env --type env_file</pre>
				</div>
				<div class="card gs-card">
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
			<p class="section-label">Why passwd.page</p>
			<h2>Built different.</h2>
			<div class="grid-2">
				<div class="card">
					<h3>Truly zero knowledge</h3>
					<p class="card-body">Not "trust us" zero knowledge. Mathematically impossible for us to read your secrets. Open source &mdash; verify it yourself.</p>
				</div>
				<div class="card">
					<h3>Single binary. Self-hostable.</h3>
					<p class="card-body">One Go binary, embeds the entire frontend. <code>docker run passwd-page</code> and you own your infrastructure. No external dependencies.</p>
				</div>
				<div class="card">
					<h3>Built for automation</h3>
					<p class="card-body">CLI pipes, MCP tools, REST API. Every interface your workflow needs. <code>echo $SECRET | passwd create</code></p>
				</div>
				<div class="card">
					<h3>Nothing to remember</h3>
					<p class="card-body">No accounts. No master passwords. No subscription. Share a secret, get a link, done. The way it should be.</p>
				</div>
			</div>
		</div>
	</section>

	<!-- CTA -->
	<section class="section-cta">
		<div class="contain cta-content">
			<h2>Stop pasting secrets into chat windows.</h2>
			<p>Your agents deserve better. Your teammates deserve better.</p>
			<div class="hero-actions">
				<a href="/share" class="btn-dark">Share a Secret</a>
				<a href="https://github.com/davidfeldi/passwd-page" class="btn-ghost">View on GitHub</a>
			</div>
		</div>
	</section>

	<!-- Footer -->
	<footer class="site-footer">
		<div class="contain footer-inner">
			<div class="footer-brand">
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
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

<style>
	/* ── Base ── */
	.landing {
		font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
		color: #333333;
		line-height: 1.5;
		background: #ffffff;
		-webkit-font-smoothing: antialiased;
	}

	.contain {
		max-width: 960px;
		margin: 0 auto;
		padding: 0 24px;
	}

	/* ── Section rhythm ── */
	.section {
		padding: 80px 0;
	}

	.section-label {
		font-family: 'Geist Mono', ui-monospace, monospace;
		font-size: 12px;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.6px;
		color: #18E299;
		margin-bottom: 12px;
	}

	.section h2 {
		font-size: 40px;
		font-weight: 600;
		color: #0d0d0d;
		letter-spacing: -0.8px;
		line-height: 1.1;
		margin: 0 0 48px 0;
	}

	/* ── Hero ── */
	.hero {
		position: relative;
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		text-align: center;
		padding: 96px 24px;
		overflow: hidden;
	}

	.hero-glow {
		position: absolute;
		top: -20%;
		left: 50%;
		transform: translateX(-50%);
		width: 140%;
		height: 80%;
		background: radial-gradient(ellipse at 50% 40%, rgba(24, 226, 153, 0.08) 0%, rgba(24, 226, 153, 0.02) 40%, transparent 70%);
		pointer-events: none;
	}

	.hero-content {
		position: relative;
		z-index: 1;
	}

	.hero-badge {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 6px 16px;
		border: 1px solid rgba(0, 0, 0, 0.08);
		border-radius: 9999px;
		font-size: 14px;
		font-weight: 600;
		color: #0d0d0d;
		margin-bottom: 32px;
	}

	.hero-badge svg {
		color: #18E299;
	}

	h1 {
		font-size: 56px;
		font-weight: 600;
		color: #0d0d0d;
		line-height: 1.1;
		letter-spacing: -1.12px;
		margin: 0 0 24px 0;
	}

	h1 em {
		font-style: normal;
		color: #18E299;
	}

	.hero-sub {
		font-size: 18px;
		color: #666666;
		max-width: 540px;
		margin: 0 auto 40px;
		line-height: 1.6;
	}

	.hero-actions {
		display: flex;
		gap: 12px;
		justify-content: center;
		margin-bottom: 16px;
	}

	.btn-dark {
		display: inline-block;
		padding: 10px 28px;
		background: #0d0d0d;
		color: #ffffff;
		font-family: 'Inter', sans-serif;
		font-weight: 500;
		font-size: 15px;
		border-radius: 9999px;
		text-decoration: none;
		box-shadow: rgba(0, 0, 0, 0.06) 0px 1px 2px;
		transition: opacity 0.2s;
	}

	.btn-dark:hover {
		opacity: 0.88;
	}

	.btn-ghost {
		display: inline-block;
		padding: 10px 28px;
		background: #ffffff;
		color: #0d0d0d;
		font-family: 'Inter', sans-serif;
		font-weight: 500;
		font-size: 15px;
		border-radius: 9999px;
		border: 1px solid rgba(0, 0, 0, 0.08);
		text-decoration: none;
		transition: border-color 0.2s;
	}

	.btn-ghost:hover {
		border-color: rgba(0, 0, 0, 0.2);
	}

	.hero-note {
		font-size: 13px;
		color: #888888;
		letter-spacing: -0.26px;
	}

	/* ── Cards ── */
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

	.card {
		background: #ffffff;
		border: 1px solid rgba(0, 0, 0, 0.05);
		border-radius: 16px;
		padding: 28px;
		box-shadow: rgba(0, 0, 0, 0.03) 0px 2px 4px;
	}

	.card h3 {
		font-size: 18px;
		font-weight: 600;
		color: #0d0d0d;
		letter-spacing: -0.2px;
		margin: 0 0 8px 0;
		line-height: 1.3;
	}

	.card-body {
		font-size: 15px;
		color: #555555;
		line-height: 1.6;
		margin: 0;
	}

	.card-bad {
		font-weight: 600;
		color: #d45656;
		font-size: 15px;
		margin: 0 0 6px 0;
	}

	.card code {
		font-family: 'Geist Mono', ui-monospace, monospace;
		font-size: 13px;
		background: #f5f5f5;
		padding: 2px 6px;
		border-radius: 4px;
		color: #0d0d0d;
	}

	.case-label {
		display: inline-block;
		font-family: 'Geist Mono', ui-monospace, monospace;
		font-size: 12px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.6px;
		color: #0fa76e;
		background: #d4fae8;
		padding: 4px 12px;
		border-radius: 9999px;
		margin-bottom: 12px;
	}

	/* ── Steps ── */
	.steps {
		display: flex;
		flex-direction: column;
		gap: 20px;
		margin-bottom: 48px;
	}

	.step {
		display: flex;
		gap: 20px;
		align-items: flex-start;
	}

	.step-num {
		flex-shrink: 0;
		width: 36px;
		height: 36px;
		display: flex;
		align-items: center;
		justify-content: center;
		background: #0d0d0d;
		color: #ffffff;
		font-weight: 600;
		font-size: 14px;
		border-radius: 9999px;
	}

	.step h3 {
		font-size: 18px;
		font-weight: 600;
		color: #0d0d0d;
		letter-spacing: -0.2px;
		margin: 0 0 4px 0;
	}

	.step p {
		font-size: 15px;
		color: #555555;
		line-height: 1.6;
		margin: 0;
	}

	/* ── URL diagram ── */
	.url-diagram {
		background: #fafafa;
		border: 1px solid rgba(0, 0, 0, 0.05);
		border-radius: 16px;
		padding: 24px 28px;
		text-align: center;
	}

	.mono-label {
		font-family: 'Geist Mono', ui-monospace, monospace;
		font-size: 10px;
		font-weight: 500;
		text-transform: uppercase;
		letter-spacing: 0.6px;
		color: #888888;
		display: block;
		margin-bottom: 12px;
	}

	.url-diagram pre {
		font-family: 'Geist Mono', ui-monospace, monospace;
		font-size: 14px;
		line-height: 1.6;
		color: #0d0d0d;
		margin: 0;
		white-space: pre;
	}

	.dim { color: #888888; }
	.accent-text { color: #18E299; font-weight: 600; }

	/* ── Getting started ── */
	.gs-card h3 {
		font-size: 18px;
		font-weight: 600;
		color: #0d0d0d;
		margin: 0 0 4px 0;
	}

	.gs-desc {
		font-size: 14px;
		color: #888888;
		margin: 0 0 16px 0;
	}

	.gs-steps p {
		font-size: 14px;
		color: #333333;
		margin: 0 0 4px 0;
		line-height: 1.6;
	}

	.gs-steps a {
		color: #18E299;
		text-decoration: none;
		font-weight: 500;
	}

	.gs-steps a:hover {
		text-decoration: underline;
	}

	.gs-hint {
		font-size: 13px;
		color: #666666;
		margin: 12px 0 0 0;
		line-height: 1.5;
	}

	.code-block {
		background: #fafafa;
		border: 1px solid rgba(0, 0, 0, 0.05);
		border-radius: 8px;
		padding: 16px;
		overflow-x: auto;
		font-family: 'Geist Mono', ui-monospace, monospace;
		font-size: 12px;
		line-height: 1.7;
		color: #0d0d0d;
		white-space: pre;
		margin: 0;
	}

	.c-dim { color: #888888; }
	.c-green { color: #0fa76e; }

	/* ── CTA ── */
	.section-cta {
		padding: 96px 0;
		text-align: center;
	}

	.section-cta h2 {
		font-size: 40px;
		font-weight: 600;
		color: #0d0d0d;
		letter-spacing: -0.8px;
		line-height: 1.1;
		margin: 0 0 12px 0;
	}

	.section-cta p {
		font-size: 18px;
		color: #666666;
		margin: 0 0 32px 0;
	}

	/* ── Footer ── */
	.site-footer {
		padding: 32px 0;
		border-top: 1px solid rgba(0, 0, 0, 0.05);
	}

	.footer-inner {
		text-align: center;
	}

	.footer-brand {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-weight: 600;
		font-size: 14px;
		color: #0d0d0d;
		margin-bottom: 6px;
	}

	.footer-brand svg {
		color: #18E299;
	}

	.footer-tagline {
		font-size: 13px;
		color: #888888;
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
		color: #888888;
		text-decoration: none;
		transition: color 0.2s;
	}

	.footer-links a:hover {
		color: #0d0d0d;
	}

	/* ── Responsive ── */
	@media (max-width: 768px) {
		h1 {
			font-size: 36px;
			letter-spacing: -0.72px;
		}

		.section h2, .section-cta h2 {
			font-size: 28px;
			letter-spacing: -0.56px;
		}

		.section {
			padding: 56px 0;
		}

		.grid-2, .grid-3 {
			grid-template-columns: 1fr;
		}

		.hero {
			padding: 64px 24px;
			min-height: auto;
		}

		.hero-actions {
			flex-direction: column;
			align-items: center;
		}

		.section-cta {
			padding: 64px 0;
		}
	}
</style>
