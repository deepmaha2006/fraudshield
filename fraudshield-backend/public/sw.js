// sw.js — offline fallback only.
//
// Caches nothing but the public status pages and their own assets. API
// responses and console pages are NEVER cached (they contain private data).
// When a page navigation fails (no network, server down) or the reverse proxy
// answers 502/503/504, the visitor gets the cached "Connection Lost" page,
// which retries automatically once the connection is back.

const CACHE = 'fraudshield-status-v1';
const ASSETS = ['/offline.html', '/404.html', '/500.html', '/css/not-found.css', '/js/not-found.js'];

self.addEventListener('install', event => {
    event.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys()
            .then(keys => Promise.all(keys.filter(k => k.startsWith('fraudshield-') && k !== CACHE).map(k => caches.delete(k))))
            .then(() => self.clients.claim()),
    );
});

self.addEventListener('fetch', event => {
    const req = event.request;
    if (req.method !== 'GET') return;
    const url = new URL(req.url);
    if (url.origin !== self.location.origin) return;   // never touch third-party requests
    if (url.pathname.startsWith('/api/')) return;       // never touch API traffic

    // Page loads: always go to the network; fall back only when it is unreachable.
    if (req.mode === 'navigate') {
        event.respondWith((async () => {
            try {
                const res = await fetch(req);
                if ([502, 503, 504].includes(res.status)) return (await caches.match('/offline.html')) || res;
                return res;
            } catch {
                return (await caches.match('/offline.html')) || Response.error();
            }
        })());
        return;
    }

    // The status page's own assets: network first (stay current), cache when offline.
    if (ASSETS.includes(url.pathname)) {
        event.respondWith(fetch(req).then(res => {
            if (res.ok) {
                const copy = res.clone();
                caches.open(CACHE).then(c => c.put(req, copy));
            }
            return res;
        }).catch(() => caches.match(req)));
    }
});
