/* Password Vault PWA — Service Worker
   Cache-first per uso offline su iPhone */

const CACHE_NAME = 'pv-vault-local-v4';
const ASSETS = [
  './index.html',
  './app.js?v=local4',
  './styles.css?v=local4',
  './apple-touch-icon.png',
  './manifest.json',
  './icon-192.svg',
  './icon-512.svg',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k.startsWith('pv-vault-') && k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Le richieste esterne non entrano nella cache del vault. Gli eventuali favicon
  // vengono richiesti direttamente al sito salvato e senza passare da servizi terzi.
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(event.request.mode === 'navigate' ? './index.html' : event.request).then(cached => {
      return cached || fetch(event.request).then(response => {
        const clone = response.clone();
        caches.open(CACHE_NAME).then(c => c.put(event.request, clone));
        return response;
      });
    })
  );
});
