const encoder = new TextEncoder();
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digest = /^[0-9a-f]{64}$/;
const security = {"Cache-Control":"no-store", "Content-Type":"application/json; charset=utf-8", "X-Content-Type-Options":"nosniff", "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'", "Referrer-Policy":"no-referrer", "Strict-Transport-Security":"max-age=31536000"};
class ApiError extends Error { constructor(status, message) { super(message); this.status=status; } }
const fail=(status,message)=>{throw new ApiError(status,message);};
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:security});
const now=()=>Math.floor(Date.now()/1000);
const base64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unbase64=value=>Uint8Array.from(atob(value),char=>char.charCodeAt(0));
export async function sha(value) { const bytes=typeof value==='string'?encoder.encode(value):value; return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),byte=>byte.toString(16).padStart(2,'0')).join(''); }
export function sanitize(stack) {
 return stack.split('\n').slice(0,256).map(line=>line.trim()).filter(line=>/^(?:Caused by: |Suppressed: )?[A-Za-z0-9_.$]+(?:Exception|Error|Throwable)$/.test(line)||/^at [A-Za-z0-9_.$<>]+\([A-Za-z0-9_.$ :?-]+\)$/.test(line)).join('\n') || 'Crash report (details redacted)';
}
async function body(request, allowed) {
 if(request.headers.get('Content-Type')?.split(';')[0]!=='application/json') fail(415,'JSON required');
 const size=Number(request.headers.get('Content-Length') || 0);
 if(!Number.isSafeInteger(size)||size<0||size>65536) fail(413,'body too large');
 const reader=request.body?.getReader(); let total=0; const chunks=[];
 if(reader) while(true) {
  const {value,done}=await reader.read(); if(done) break;
  total+=value.byteLength; if(total>65536) {await reader.cancel();fail(413,'body too large');}
  chunks.push(value);
 }
 const bytes=new Uint8Array(total); let offset=0; for(const chunk of chunks) {bytes.set(chunk,offset);offset+=chunk.length;}
 if(new URL(request.url).pathname.startsWith('/admin/')&&await sha(bytes)!==request.headers.get('X-Aide-Body-SHA256'))fail(401,'body signature mismatch');
 let value; try {value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));} catch {fail(400,'invalid JSON');}
 if(value===null||Array.isArray(value)||typeof value!=='object'||Object.keys(value).some(key=>!allowed.includes(key))) fail(422,'invalid fields');
 return value;
}
const text=(value,max)=>{if(typeof value!=='string'||!value.length||value.length>max)fail(422,'invalid text');return value;};
async function quota(env,key,maximum,seconds) {
 const bucket=Math.floor(now()/seconds);
 const row=await env.DB.prepare(`INSERT INTO quotas(key,bucket,count,expires) VALUES(?,?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN bucket=excluded.bucket THEN count+1 ELSE 1 END,bucket=excluded.bucket,expires=excluded.expires RETURNING count`).bind(key,bucket,(bucket+1)*seconds).first();
 if(row.count>maximum) fail(429,'rate limit');
}
async function authenticated(request,env) {
 const value=request.headers.get('Authorization')||'';
 if(!/^Bearer [A-Za-z0-9_-]{43}$/.test(value)) fail(401,'invalid installation token');
 const row=await env.DB.prepare('SELECT id,version FROM installations WHERE token_hash=?').bind(await sha(value.slice(7))).first();
 if(!row) fail(401,'invalid installation token');
 return row;
}
async function admin(request,env) {
 // Only the origin has the private key; Cloudflare stores a public verification key.
 const timestamp=Number(request.headers.get('X-Aide-Timestamp'));
 const nonce=request.headers.get('X-Aide-Nonce')||'';
 const bodyHash=request.headers.get('X-Aide-Body-SHA256')||'';
 const signature=request.headers.get('X-Aide-Signature')||'';
 if(!env.SERVER_PUBLIC_KEY||!Number.isSafeInteger(timestamp)||Math.abs(now()-timestamp)>120||!uuid.test(nonce)||!digest.test(bodyHash)||signature.length>700)fail(401,'unauthorized');
 const peer=request.headers.get('CF-Connecting-IP')||'unknown';
 await quota(env,'admin-ip:'+await sha(peer),120,60);
 const url=new URL(request.url);
 const message=encoder.encode(`AIDE-API-v1\n${request.method}\n${url.pathname}${url.search}\n${timestamp}\n${nonce}\n${bodyHash}`);
 let verified=false;
 try {
  const key=await crypto.subtle.importKey('spki',unbase64(env.SERVER_PUBLIC_KEY),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  verified=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unbase64(signature),message);
 }catch {}
 if(!verified)fail(401,'unauthorized');
 if(request.method==='GET'&&bodyHash!==await sha(new Uint8Array()))fail(401,'body signature mismatch');
 const result=await env.DB.prepare('INSERT OR IGNORE INTO nonces(id,expires) VALUES(?,?)').bind(nonce,now()+600).run();
 if(result.meta.changes!==1)fail(401,'request replay blocked');
}
async function signedRelease(env,origin) {
 const object=await env.RELEASES.get('release.json'); if(!object)return json({available:false});
 return json(JSON.parse(await object.text()));
}
async function verifyRelease(env,envelope,origin) {
 text(envelope.payload,22000);text(envelope.signature,700);
 const payload=unbase64(envelope.payload);
 const key=await crypto.subtle.importKey('spki',unbase64(env.SERVER_PUBLIC_KEY),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unbase64(envelope.signature),payload))fail(422,'invalid update signature');
 const release=JSON.parse(new TextDecoder().decode(payload));
 if(!digest.test(release.sha256)||!Number.isSafeInteger(release.versionCode)||!Number.isSafeInteger(release.size)||release.size<=0||release.size>150000000) fail(503,'invalid release');
 if(release.url!==origin+'/api/apk/'+release.sha256+'.apk'||release.issued>now()+300||release.expires<=now()||release.expires-release.issued>86400)fail(422,'invalid release validity');
 return release;
}
export async function handle(request,env,ctx) {
 const url=new URL(request.url),path=url.pathname;
 if(url.protocol!=='https:') fail(400,'HTTPS required');
 if(!['GET','HEAD','POST'].includes(request.method)) fail(405,'method not allowed');
 if(path.startsWith('/admin/')) {
  await admin(request,env);
  if(path==='/admin/prune'&&request.method==='POST') {
   await body(request,[]);
   await env.DB.batch([
    env.DB.prepare('DELETE FROM quotas WHERE expires<?').bind(now()),
    env.DB.prepare('DELETE FROM nonces WHERE expires<?').bind(now()),
    env.DB.prepare('DELETE FROM crashes WHERE acknowledged=1 AND created<?').bind(now()-30*86400)
   ]);
   return json({ok:true});
  }
  const upload=/^\/admin\/apk\/([a-f0-9]{64})$/.exec(path);
  if(upload&&request.method==='POST') {
   if(upload[1]!==request.headers.get('X-Aide-Body-SHA256'))fail(401,'body signature mismatch');
   const length=Number(request.headers.get('Content-Length'));
   if(!Number.isSafeInteger(length)||length<=0||length>99000000)fail(413,'invalid APK size');
   if(!request.body)fail(400,'APK body required');
   // Keep the native request stream's length; R2 verifies integrity while storing.
   const checksum=Uint8Array.from(upload[1].match(/../g),byte=>parseInt(byte,16));
   const stored=await env.RELEASES.put(upload[1]+'.apk',request.body,{sha256:checksum.buffer,httpMetadata:{contentType:'application/vnd.android.package-archive'}});
   if(!stored||stored.size!==length) {await env.RELEASES.delete(upload[1]+'.apk');fail(400,'APK length mismatch');}
   return json({ok:true,size:stored.size});
  }
  if(path==='/admin/release'&&request.method==='POST') {
   const envelope=await body(request,['payload','signature']);
   const value=await verifyRelease(env,envelope,url.origin);
   if(!digest.test(value.sha256)||!Number.isSafeInteger(value.size)||value.size<=0||value.size>99000000||!Number.isSafeInteger(value.versionCode)||value.versionCode<=0||value.versionCode>2147483647)fail(422,'invalid release');
   text(value.versionName,80);if(value.notes!==undefined)text(value.notes,3000);
   const apk=await env.RELEASES.head(value.sha256+'.apk');if(!apk||apk.size!==value.size)fail(409,'upload APK first');
   const previous=await env.RELEASES.get('release.json');
   if(previous&&JSON.parse(new TextDecoder().decode(unbase64(JSON.parse(await previous.text()).payload))).versionCode>value.versionCode)fail(409,'release downgrade blocked');
   await env.RELEASES.put('release.json',JSON.stringify(envelope),{httpMetadata:{contentType:'application/json'}});
   return json({ok:true});
  }
  if(path==='/admin/events'&&request.method==='GET') {
   const rows=await env.DB.prepare('SELECT id,installation,version,stack,created FROM crashes WHERE acknowledged=0 ORDER BY created,id LIMIT 50').all();
   return json({items:rows.results});
  }
  if(path==='/admin/ack'&&request.method==='POST') {
   const value=await body(request,['ids']);
   if(!Array.isArray(value.ids)||value.ids.length>50||value.ids.some(id=>typeof id!=='string'||!uuid.test(id)))fail(422,'invalid IDs');
   if(value.ids.length) await env.DB.batch(value.ids.map(id=>env.DB.prepare('UPDATE crashes SET acknowledged=1 WHERE id=?').bind(id)));
   return json({ok:true});
  }
  if(path==='/admin/devices'&&request.method==='GET') {
   const since=Number(url.searchParams.get('since')||'0');const cursor=url.searchParams.get('after')||'';
   if(!Number.isSafeInteger(since)||since<0||cursor.length>36)fail(422,'invalid cursor');
   const rows=await env.DB.prepare('SELECT id AS device_id,version AS app_version,created AS first_seen,seen AS last_seen FROM installations WHERE seen>? OR (seen=? AND id>?) ORDER BY seen,id LIMIT 100').bind(since,since,cursor).all();
   return json({items:rows.results});
  }
  if(path==='/admin/registrations'&&request.method==='GET') {
   const since=Number(url.searchParams.get('since')||'0'); const cursor=url.searchParams.get('after')||'';
   if(!Number.isSafeInteger(since)||since<0||cursor.length>36)fail(422,'invalid cursor');
   const rows=await env.DB.prepare('SELECT id AS device_id,version AS app_version,created AS first_seen FROM installations WHERE created>? OR (created=? AND id>?) ORDER BY created,id LIMIT 100').bind(since,since,cursor).all();
   return json({items:rows.results});
  }
  fail(404,'not found');
 }
 if((path==='/health'||path==='/')&&request.method==='GET')return json({ok:true,service:'AIDE mobile API',configured:!!(env.DB&&env.SERVER_PUBLIC_KEY&&env.RELEASES)});
 const peer=request.headers.get('CF-Connecting-IP')||'unknown';
 // Native Cloudflare rate limiting reduces database amplification under floods.
 if(env.API_LIMIT) {if(!(await env.API_LIMIT.limit({key:peer})).success)fail(429,'rate limit');}
 else await quota(env,'ip-minute:'+await sha(peer),120,60);
 if(path==='/api/register'&&request.method==='POST') {
  if(env.REGISTER_LIMIT&&!(await env.REGISTER_LIMIT.limit({key:peer})).success)fail(429,'rate limit');
  await quota(env,'register:'+await sha(peer),20,3600);
  const value=await body(request,['installation','version']);
  if(typeof value.installation!=='string'||!uuid.test(value.installation))fail(422,'invalid installation');
  text(value.version,80);
  const token=base64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const result=await env.DB.prepare('INSERT OR IGNORE INTO installations(id,token_hash,version,created,seen) VALUES(?,?,?,?,?)').bind(value.installation,await sha(token),value.version,now(),now()).run();
  if(result.meta.changes!==1)fail(409,'installation already exists');
  return json({token});
 }
 if(path==='/api/crash/status'&&request.method==='GET') {
  const installation=await authenticated(request,env);
  await quota(env,'crash-status:'+installation.id,60,60);
  const id=url.searchParams.get('id')||'';if(!uuid.test(id))fail(422,'invalid report ID');
  const row=await env.DB.prepare('SELECT acknowledged FROM crashes WHERE id=? AND installation=?').bind(id,installation.id).first();
  return json({received:!!row,delivered:!!row&&row.acknowledged===1});
 }
 if(path==='/api/crash'&&request.method==='POST') {
  const installation=await authenticated(request,env);
  await quota(env,'crash:'+installation.id,60,3600);
  const value=await body(request,['id','version','stack']);
  if(typeof value.id!=='string'||!uuid.test(value.id))fail(422,'invalid report ID');
  text(value.version,80);text(value.stack,32000);
  const existing=await env.DB.prepare('SELECT installation FROM crashes WHERE id=?').bind(value.id).first();
  if(existing&&existing.installation!==installation.id)fail(409,'report ID collision');
  await env.DB.prepare('INSERT OR IGNORE INTO crashes(id,installation,version,stack,created) VALUES(?,?,?,?,?)').bind(value.id,installation.id,value.version,sanitize(value.stack),now()).run();
  return json({ok:true});
 }
 if(path==='/api/heartbeat'&&request.method==='POST') {
  const installation=await authenticated(request,env);
  await quota(env,'heartbeat:'+installation.id,24,3600);
  const value=await body(request,['version']);text(value.version,80);
  await env.DB.prepare('UPDATE installations SET seen=?,version=? WHERE id=?').bind(now(),value.version,installation.id).run();
  return json({ok:true});
 }
 if(path==='/api/update'&&request.method==='GET')return signedRelease(env,url.origin);
 const match=/^\/api\/apk\/([a-f0-9]{64})\.apk$/.exec(path);
 if(match&&['GET','HEAD'].includes(request.method)) {
  const key=match[1]+'.apk',metadata=await env.RELEASES.head(key);
  if(!metadata)fail(404,'not found');
  const etag=metadata.httpEtag||'"'+match[1]+'"';
  const headers={...security,'Cache-Control':'private, no-transform','Content-Type':'application/vnd.android.package-archive','Content-Disposition':'attachment; filename="AIDE-Sora.apk"','Accept-Ranges':'bytes','ETag':etag,'X-Aide-Download-Version':'2'};
  let offset=0,length=metadata.size,status=200;
  const range=request.headers.get('Range');
  if(request.method==='GET'&&range&&(!request.headers.get('If-Range')||request.headers.get('If-Range')===etag)) {
   const parts=/^bytes=(\d*)-(\d*)$/.exec(range);
   const invalid=()=>new Response(null,{status:416,headers:{...headers,'Content-Range':'bytes */'+metadata.size,'Content-Length':'0'}});
   if(!parts||(!parts[1]&&!parts[2]))return invalid();
   if(!parts[1]) {
    const suffix=Number(parts[2]);if(!Number.isSafeInteger(suffix)||suffix<=0)return invalid();
    offset=Math.max(0,metadata.size-suffix);
   }else offset=Number(parts[1]);
   let end=parts[1]&&parts[2]?Number(parts[2]):metadata.size-1;
   if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(end)||offset<0||offset>=metadata.size||end<offset)return invalid();
   end=Math.min(end,metadata.size-1);length=end-offset+1;status=206;
   headers['Content-Range']=`bytes ${offset}-${end}/${metadata.size}`;
  }
  headers['Content-Length']=String(length);
  if(request.method==='HEAD')return new Response(null,{headers});
  const object=await env.RELEASES.get(key,status===206?{range:{offset,length}}:undefined);
  if(!object||!object.body)fail(503,'download unavailable');
  // Explicit fixed length gives the download a finite body and detects truncated storage reads.
  const stream=typeof FixedLengthStream==='function'?new FixedLengthStream(length):new TransformStream({
   start(){this.count=0;},transform(chunk,controller){this.count+=chunk.byteLength;if(this.count>length)throw new Error('download overflow');controller.enqueue(chunk);},flush(){if(this.count!==length)throw new Error('download truncated');}
  });
  const transfer=object.body.pipeTo(stream.writable);
  if(ctx)ctx.waitUntil(transfer);else transfer.catch(()=>{});
  return new Response(stream.readable,{status,headers});
 }
 fail(404,'not found');
}
export default {
 async fetch(request,env,ctx) {try {return await handle(request,env,ctx);}catch(error) {return json({detail:error instanceof ApiError?error.message:'service unavailable'},error instanceof ApiError?error.status:503);}},
 async scheduled(event,env,ctx) {
  ctx.waitUntil(env.DB.batch([
   env.DB.prepare('DELETE FROM quotas WHERE expires<?').bind(now()),
   env.DB.prepare('DELETE FROM nonces WHERE expires<?').bind(now()),
   env.DB.prepare('DELETE FROM crashes WHERE acknowledged=1 AND created<?').bind(now()-30*86400)
  ]));
 }
};
