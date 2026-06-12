import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	kit: {
		adapter: adapter({
			// 200.html (not index.html) is the SPA fallback for the dynamic
			// /s/[id] route. This keeps the prerendered index.html (the real
			// landing-page HTML) from being overwritten by the empty shell, so
			// crawlers and social scrapers see content. The Go server serves
			// 200.html for unmatched routes — see internal/server/server.go.
			fallback: '200.html'
		})
	}
};

export default config;
