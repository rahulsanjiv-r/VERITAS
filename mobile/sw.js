const CACHE = 'veritas-v1';
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/mobile/', '/mobile/manifest.json']))));
self.addEventListener('fetch', e => {
  if (e.request.url.includes('/api') || e.request.url.includes(':8000')) return; // let API calls through
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
