/* Service worker: makes the app installable and keeps its static shell available offline.
 *
 * What it caches: only files under /static/ and the public /offline page, in a cache named
 * after the app version so every release starts clean. What it never caches: pages, forms,
 * /ips.txt or anything else behind the login. Navigations always go to the network; when that
 * fails the cached /offline page is shown instead. */
'use strict';

const VERSION = '__VERSION__';
const CACHE = 'whitelister-static-' + VERSION;
const OFFLINE = '/offline';
const PRECACHE = [
  OFFLINE,
  '/static/app.css?v=' + VERSION,
  '/static/app.js?v=' + VERSION,
  '/static/icon.svg',
  '/static/manifest.webmanifest',
  '/static/fonts/ibm-plex-mono-400.woff2',
  '/static/fonts/ibm-plex-mono-500.woff2',
  '/static/fonts/ibm-plex-mono-600.woff2',
  '/static/fonts/instrument-sans-var.woff2',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

const cacheable = (url) => url.origin === self.location.origin && url.pathname.startsWith('/static/');

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);

  if (request.mode === 'navigate') {
    // pages are never cached: network, or the offline page
    event.respondWith(fetch(request).catch(() => caches.match(OFFLINE, { cacheName: CACHE })));
    return;
  }
  if (!cacheable(url)) return; // /ips.txt, /healthz, cross-origin: untouched

  event.respondWith(
    caches.open(CACHE).then((cache) =>
      cache.match(request).then((hit) => {
        if (hit) return hit;
        return fetch(request).then((response) => {
          if (response.ok && response.type === 'basic') cache.put(request, response.clone());
          return response;
        });
      })
    )
  );
});
