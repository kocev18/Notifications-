self.addEventListener('install',function(e){self.skipWaiting();});
self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim());});
self.addEventListener('push',function(e){
  var d={}; try{ d=e.data.json(); }catch(x){ d={title:'📋 Задачи',body:e.data?e.data.text():''}; }
  e.waitUntil(self.registration.showNotification(d.title||'📋 Задачи',{body:d.body||'',tag:d.tag||undefined,data:{url:d.url||'./'}}));
});
self.addEventListener('notificationclick',function(e){
  e.notification.close();
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(function(l){
    for(var i=0;i<l.length;i++){ if('focus' in l[i]) return l[i].focus(); }
    return self.clients.openWindow('./');
  }));
});
