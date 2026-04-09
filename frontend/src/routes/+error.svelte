<script>
	import { page } from '$app/stores';
</script>

<svelte:head>
	<title>passwd.page — {$page.status}</title>
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

		<div class="error-card">
			<div class="error-icon-wrap">
				<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#d45656" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
					<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
					<line x1="12" y1="9" x2="12" y2="13"/>
					<line x1="12" y1="17" x2="12.01" y2="17"/>
				</svg>
			</div>
			<h2 class="error-title">
				{#if $page.status === 404}
					Page not found
				{:else}
					Something went wrong
				{/if}
			</h2>
			<p class="error-detail">
				{#if $page.status === 404}
					The page you're looking for doesn't exist.
				{:else}
					An unexpected error occurred. Please try again.
				{/if}
			</p>
			<a href="/share" class="link-pill">Share a secret</a>
		</div>
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
		text-align: center;
	}

	header {
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

	.error-card {
		background: #fafafa;
		border: 1px solid rgba(0, 0, 0, 0.05);
		border-radius: 16px;
		padding: 3rem 2rem;
		box-shadow: rgba(0, 0, 0, 0.03) 0px 2px 4px;
	}

	.error-icon-wrap {
		margin-bottom: 1.25rem;
	}

	.error-title {
		font-size: 24px;
		font-weight: 600;
		color: #0d0d0d;
		margin: 0 0 0.5rem;
	}

	.error-detail {
		color: #666666;
		font-size: 14px;
		margin: 0 0 2rem;
		line-height: 1.5;
	}

	.link-pill {
		display: inline-block;
		padding: 0.6rem 1.5rem;
		background: #0d0d0d;
		color: #ffffff;
		font-family: 'Inter', sans-serif;
		font-size: 14px;
		font-weight: 500;
		border-radius: 9999px;
		text-decoration: none;
		transition: opacity 0.2s;
	}

	.link-pill:hover {
		opacity: 0.85;
	}

	.link-pill:focus-visible {
		outline: 2px solid #18E299;
		outline-offset: 2px;
	}
</style>
