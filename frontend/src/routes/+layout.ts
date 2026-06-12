// Prerender static marketing/app pages to real HTML at build time so crawlers
// and social scrapers see content (adapter-static). The dynamic secret route
// /s/[id] opts out below (ssr=false, prerender=false) and is served via the
// index.html SPA fallback — its content must stay client-only anyway.
export const prerender = true;
export const ssr = true;
