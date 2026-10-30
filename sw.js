self.addEventListener('install',function(e){self.skipWaiting();}); /* v3 */
self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim());});
self.addEventListener('push',function(e){
  var d={}; try{ d=e.data.json(); }catch(x){ d={title:'📋 Задачи',body:e.data?e.data.text():''}; }
  e.waitUntil(self.registration.showNotification(d.title||'📋 Задачи',{body:d.body||'',tag:d.tag||undefined,data:{url:d.url||'./'}}));
});
self.addEventListener('notificationclick',function(e){
  e.notification.close();
  var url=(e.notification.data&&e.notification.data.url)||'./', m=/[?&]t=([^&]+)/.exec(url), id=m?decodeURIComponent(m[1]):null;
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(function(l){
    for(var i=0;i<l.length;i++){ if('focus' in l[i]){ l[i].postMessage({openTask:id}); return l[i].focus(); } }
    return self.clients.openWindow(url);
  }));
});
self.addEventListener('fetch',function(e){
  var r=e.request;
  if(r.method!=='GET'||new URL(r.url).origin!==location.origin) return;
  if(r.mode==='navigate'||/\.(html|js|webmanifest)$/.test(new URL(r.url).pathname)){
    e.respondWith(fetch(r,{cache:'no-store'}).catch(function(){ return caches.match(r); }));
  }
});
