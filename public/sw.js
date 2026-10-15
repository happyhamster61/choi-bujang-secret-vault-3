// Stage 11: cache only a static offline notice, NEVER API, token or note contents.
const OFFLINE_CACHE = 'byteback-offline-v11';
const OFFLINE_PAGE = '/offline.html';
self.addEventListener('install', event => {
  event.waitUntil(caches.open(OFFLINE_CACHE).then(cache => cache.add(OFFLINE_PAGE)));
  self.skipWaiting();
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(names => Promise.all(
    names.filter(name => name !== OFFLINE_CACHE).map(name => caches.delete(name))
  )));
  self.clients.claim();
});
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.mode !== 'navigate' || request.method !== 'GET'
      || url.origin !== self.location.origin) return;
  event.respondWith(fetch(request).catch(async () => {
    const cache = await caches.open(OFFLINE_CACHE);
    return cache.match(OFFLINE_PAGE);
  }));
});
