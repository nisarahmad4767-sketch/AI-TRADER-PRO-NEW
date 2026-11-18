// Cache only public app metadata. Never persist the dashboard HTML offline.
const CACHE='aitrader-shell-v2';
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.add('/manifest.webmanifest'))));
self.addEventListener('activate',e=>e.waitUntil(Promise.all([caches.keys().then(keys=>Promise.all(keys.filter(k=>k.startsWith('aitrader-shell-')&&k!==CACHE).map(k=>caches.delete(k)))),self.clients.claim()])));
self.addEventListener('fetch',e=>{
  const url=new URL(e.request.url);
  if(e.request.method!=='GET'||url.origin!==self.location.origin)return;
  // Authenticated dashboard and API are always network-only.
  if(url.pathname==='/'||url.pathname.startsWith('/api/'))return;
  if(url.pathname==='/manifest.webmanifest')e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));
});
