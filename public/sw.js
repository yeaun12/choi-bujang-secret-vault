// Stage 11 PWA: only cache the public offline message and icons.
// NEVER cache protected API responses, login tokens, note bodies, or index.html.
const CACHE_NAME = 'byteback-public-offline-v1';
const PUBLIC_OFFLINE_ASSETS = ['/offline.html', '/app-icon.svg', '/manifest.webmanifest'];
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(PUBLIC_OFFLINE_ASSETS)));
  self.skipWaiting();
});
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((name) => name !== CACHE_NAME).map((name) => caches.delete(name)));
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  // All APIs, authentication and non-navigation requests always go to the server.
  if (url.origin !== self.location.origin || request.method !== 'GET' ||
      request.mode !== 'navigate' || url.pathname.startsWith('/api/')) return;
  event.respondWith(
    fetch(request).catch(async () => {
      const cache = await caches.open(CACHE_NAME);
      return await cache.match('/offline.html') ||
        new Response('오프라인 상태입니다.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    })
  );
});
