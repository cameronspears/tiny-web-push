// The demo's service worker: show each push, and tell the page it arrived.

// Take over straight away, so an edited demo never runs an old copy of this file.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  const data = event.data ? event.data.json() : {};
  event.waitUntil(
    (async () => {
      await self.registration.showNotification(data.title ?? 'New message', {
        body: data.body,
        tag: 'tiny-web-push-demo',
      });
      for (const client of await self.clients.matchAll({ type: 'window' })) {
        client.postMessage({ type: 'push-received', title: data.title, body: data.body });
      }
    })()
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then((clients) => {
      if (clients[0]) return clients[0].focus();
      return self.clients.openWindow('/');
    })
  );
});
