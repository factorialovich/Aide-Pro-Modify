const encoder = new TextEncoder();
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digest = /^[0-9a-f]{64}$/;
const security = {"Cache-Control":"no-store", "Content-Type":"application/json; charset=utf-8", "X-Content-Type-Options":"nosniff", "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'", "Referrer-Policy":"no-referrer", "X-Frame-Options":"DENY", "Cross-Origin-Resource-Policy":"same-origin", "Permissions-Policy":"camera=(), microphone=(), geolocation=(), payment=()", "Strict-Transport-Security":"max-age=31536000"};
class ApiError extends Error { constructor(status, message) { super(message); this.status=status; } }
const fail=(status,message)=>{throw new ApiError(status,message);};
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:security});
const now=()=>Math.floor(Date.now()/1000);
const uploadChunkSize=5*1024*1024;
// Best-effort burst gate before storage. D1 quotas below remain authoritative.
const burstState=new WeakMap();
function burst(request,env) {
 const peer=request.headers.get('CF-Connecting-IP')||'unknown';
 if(peer.length>64)fail(400,'invalid peer');
 let state=burstState.get(env);if(!state){state={bucket:-1,peers:new Map()};burstState.set(env,state);}
 const bucket=Math.floor(now()/60);if(state.bucket!==bucket){state.bucket=bucket;state.peers.clear();}
 if(!state.peers.has(peer)&&state.peers.size>=2000)fail(429,'rate limit');
 const count=(state.peers.get(peer)||0)+1;state.peers.set(peer,count);
 if(count>240)fail(429,'rate limit');
}
const maintenanceState=new WeakMap();
async function pruneDownloads(env) {
 if(!env.RELEASES?.list)return;
 const page=await env.RELEASES.list({prefix:'private-downloads/',limit:100,include:['customMetadata']});
 const expired=page.objects.filter(item=>Number(item.customMetadata?.expires)<=now());
 if(expired.length)await env.RELEASES.delete(expired.map(item=>item.key));
}
const stagingCursors=new WeakMap();
async function pruneStaging(env) {
 if(!env.RELEASES?.list)return;
 const page=await env.RELEASES.list({prefix:'staging/',limit:100,include:['customMetadata'],cursor:stagingCursors.get(env)});
 stagingCursors.set(env,page.truncated?page.cursor:undefined);
 const expired=page.objects.filter(item=>Number(item.customMetadata?.expires)<=now());
 if(expired.length)await env.RELEASES.delete(expired.map(item=>item.key));
}
function maintenance(env,ctx) {
 if(!ctx||!env.DB||now()-(maintenanceState.get(env)||0)<600)return;
 maintenanceState.set(env,now());
 // Pages has no cron trigger: bounded request-driven expiry cleanup is required.
 ctx.waitUntil(env.DB.batch([
  env.DB.prepare('DELETE FROM quotas WHERE key IN (SELECT key FROM quotas WHERE expires<? LIMIT 500)').bind(now()),
  env.DB.prepare('DELETE FROM nonces WHERE id IN (SELECT id FROM nonces WHERE expires<? LIMIT 500)').bind(now()),
  env.DB.prepare('DELETE FROM crashes WHERE id IN (SELECT id FROM crashes WHERE acknowledged=1 AND created<? LIMIT 100)').bind(now()-30*86400)
 ]).catch(()=>{}));
 ctx.waitUntil(pruneDownloads(env).catch(()=>{}));
 ctx.waitUntil(pruneStaging(env).catch(()=>{}));
}
const base64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unbase64=value=>Uint8Array.from(atob(value),char=>char.charCodeAt(0));
export async function sha(value) { const bytes=typeof value==='string'?encoder.encode(value):value; return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),byte=>byte.toString(16).padStart(2,'0')).join(''); }
export function sanitize(stack) {
 const message=value=>value.slice(0,2000)
  .replace(/(authorization|password|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi,'$1=[redacted]')
  .replace(/(https?:\/\/[^?#\s]+)[?#][^\s]+/g,'$1?[redacted]')
  .replace(/Bearer\s+[A-Za-z0-9_.-]+/gi,'Bearer [redacted]');
 return stack.split('\n').slice(0,256).map(line=>line.trim()).flatMap(line=>{
  if(line==='Diagnostic report')return [line];
  if(/^at [A-Za-z0-9_.$<>]+\([A-Za-z0-9_.$ :?-]+\)$/.test(line))return [line];
  const heading=/^((?:Caused by: |Suppressed: )?[A-Za-z0-9_.$]+(?:Exception|Error|Throwable|ToastMessage))(?:: (.*))?$/.exec(line);
  return heading?[heading[1]+(heading[2]?': '+message(heading[2]):'')]:[];
 }).join('\n') || 'Crash report (details redacted)';
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

async function verifiedMessage(env,envelope) {
 text(envelope.payload,22000);text(envelope.signature,700);
 const key=await crypto.subtle.importKey('spki',unbase64(env.SERVER_PUBLIC_KEY),{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 const payload=unbase64(envelope.payload);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,unbase64(envelope.signature),payload))fail(422,'invalid message signature');
 const value=JSON.parse(new TextDecoder().decode(payload));
 if(!uuid.test(value.id)||!['notification','dialog','both'].includes(value.kind))fail(422,'invalid message');
 text(value.title,80);text(value.text,2000);
 if(!Number.isSafeInteger(value.created)||!Number.isSafeInteger(value.expires)||value.created>now()+300||value.expires<=now()||value.expires-value.created>30*86400)fail(422,'invalid message validity');
 if(!Array.isArray(value.versions)||value.versions.length>20||value.versions.some(v=>typeof v!=='string'||!v.length||v.length>80))fail(422,'invalid audience');
 return value;
}
async function messageIndex(env) {
 const object=await env.RELEASES.get('messages/index.json');
 return object?JSON.parse(await object.text()):[];
}
async function changeMessages(env,mutate) {
 for(let attempt=0;attempt<3;attempt++) {
  const object=await env.RELEASES.get('messages/index.json');
  const index=mutate(object?JSON.parse(await object.text()):[]);
  const raw=JSON.stringify(index);if(encoder.encode(raw).byteLength>60000)fail(409,'message storage full; remove old announcements');
  const condition=new Headers(object?{'If-Match':object.httpEtag}:{'If-None-Match':'*'});
  const stored=await env.RELEASES.put('messages/index.json',raw,{onlyIf:condition});
  if(stored)return;
 }
 fail(409,'concurrent message update; retry');
}
function finiteObject(object,length,ctx) {
 const stream=typeof FixedLengthStream==='function'?new FixedLengthStream(length):new TransformStream({start(){this.count=0;},transform(chunk,c){this.count+=chunk.byteLength;if(this.count>length)throw Error('overflow');c.enqueue(chunk);},flush(){if(this.count!==length)throw Error('truncated');}});
 const transfer=object.body.pipeTo(stream.writable);if(ctx)ctx.waitUntil(transfer);else transfer.catch(()=>{});
 return new Response(stream.readable,{headers:{...security,'Content-Type':'application/vnd.android.package-archive','Content-Length':String(length)}});
}

function uploadProgress(ticket) {
 return {status:ticket.status,offset:ticket.status==='uploaded'?ticket.size:(ticket.parts||[]).reduce((sum,part)=>sum+part.size,0),
  size:ticket.size||0,sha256:ticket.sha256||'',chunkSize:uploadChunkSize,expires:ticket.expires};
}
async function loadUpload(request,env,url) {
 const origin=request.headers.get('Origin');if(origin&&origin!==url.origin)fail(403,'cross-origin upload blocked');
 const authorization=request.headers.get('Authorization')||'';
 if(!/^Bearer [A-Za-z0-9_-]{43}$/.test(authorization))fail(401,'invalid upload ticket');
 const hash=await sha(authorization.slice(7));
 const object=await env.RELEASES.get('staging/tickets/'+hash+'.json');if(!object)fail(401,'invalid upload ticket');
 const issued=JSON.parse(await object.text());if(issued.expires<=now())fail(401,'upload ticket expired');
 const latest=await env.RELEASES.get('staging/status/'+issued.id+'.json');if(!latest)fail(401,'invalid upload ticket');
 const ticket=JSON.parse(await latest.text());
 if(ticket.token_hash!==hash)fail(401,'superseded upload ticket');
 return {ticket,latest,hash};
}
async function saveUpload(env,ticket,latest) {
 return env.RELEASES.put('staging/status/'+ticket.id+'.json',JSON.stringify(ticket),
  {onlyIf:new Headers({'If-Match':latest.httpEtag}),customMetadata:{expires:String(ticket.expires)}});
}
async function deleteUploadFiles(env,ticket,receipt=false) {
 const keys=(ticket.parts||[]).map(part=>part.key);
 if(ticket.object_key)keys.push(ticket.object_key);
 keys.push('staging/apk/'+ticket.id+'.apk');
 if(!receipt)keys.push('staging/tickets/'+ticket.token_hash+'.json','staging/status/'+ticket.id+'.json');
 await env.RELEASES.delete(keys);
}
async function assembleUpload(env,ticket,latest) {
 const parts=ticket.parts||[];
 if(uploadProgress(ticket).offset!==ticket.size)fail(409,'upload is incomplete');
 ticket.object_key='staging/resumable/'+ticket.id+'/'+ticket.token_hash+'/'+crypto.randomUUID()+'.apk';
 let index=0;
 const source=new ReadableStream({async pull(controller) {
  if(index===parts.length){controller.close();return;}
  const part=parts[index++],object=await env.RELEASES.get(part.key);
  if(!object||object.size!==part.size)throw Error('missing upload part');
  const bytes=await new Response(object.body).arrayBuffer();
  if(bytes.byteLength!==part.size)throw Error('truncated upload part');
  controller.enqueue(new Uint8Array(bytes));
 }});
 const stream=typeof FixedLengthStream==='function'?new FixedLengthStream(ticket.size):new TransformStream();
 const abort=new AbortController(),transfer=source.pipeTo(stream.writable,{signal:abort.signal});
 transfer.catch(()=>{});
 try {
  const stored=await env.RELEASES.put(ticket.object_key,stream.readable,{
   sha256:Uint8Array.from(ticket.sha256.match(/../g),byte=>parseInt(byte,16)).buffer,
   httpMetadata:{contentType:'application/vnd.android.package-archive'},customMetadata:{expires:String(ticket.expires)}});
  await transfer;
  if(!stored||stored.size!==ticket.size)throw Error('APK length mismatch');
 }catch(error) {
  abort.abort();await transfer.catch(()=>{});
  await env.RELEASES.delete(ticket.object_key);
  if(/checksum/i.test(error.message||''))fail(422,'APK checksum mismatch');
  throw error;
 }
 ticket.status='uploaded';
 if(!await saveUpload(env,ticket,latest)) {
  const current=await env.RELEASES.get('staging/status/'+ticket.id+'.json');
  const state=current?JSON.parse(await current.text()):null;
  // A concurrent completion or the bot's receipt may already acknowledge these bytes.
  if(state?.token_hash===ticket.token_hash&&state.status==='uploaded'&&state.sha256===ticket.sha256) {
   await env.RELEASES.delete(ticket.object_key);return json(uploadProgress(state));
  }
  await env.RELEASES.delete(ticket.object_key);fail(409,'upload ticket superseded');
 }
 return json(uploadProgress(ticket));
}
async function resumableUpload(request,env,url) {
 const {ticket,latest,hash}=await loadUpload(request,env,url);
 if(ticket.kind!=='apk')fail(401,'wrong ticket scope');
 const path=url.pathname;
 if(path==='/api/upload/status'&&request.method==='GET')return json(uploadProgress(ticket));
 if(request.method!=='POST')fail(405,'method not allowed');
 if(path==='/api/upload/start') {
  const value=await body(request,['size','sha256']);
  if(!Number.isSafeInteger(value.size)||value.size<=0||value.size>99000000)fail(413,'invalid APK size');
  if(!digest.test(value.sha256||''))fail(422,'checksum required');
  if(ticket.protocol===2||ticket.status==='uploaded') {
   if(ticket.size!==value.size||ticket.sha256!==value.sha256)fail(409,'ticket belongs to another file');
   return json(uploadProgress(ticket));
  }
  ticket.protocol=2;ticket.status='receiving';ticket.size=value.size;ticket.sha256=value.sha256;ticket.parts=[];
  delete ticket.object_key;
  if(!await saveUpload(env,ticket,latest))fail(409,'concurrent upload; retry');
  return json(uploadProgress(ticket));
 }
 if(ticket.protocol!==2)fail(409,'start the upload first');
 if(path==='/api/upload/complete') {
  await body(request,[]);
  if(ticket.status==='uploaded')return json(uploadProgress(ticket));
  return assembleUpload(env,ticket,latest);
 }
 if(path!=='/api/upload/chunk')fail(404,'not found');
 const range=/^bytes (\d+)-(\d+)\/(\d+)$/.exec(request.headers.get('Content-Range')||'');
 const length=Number(request.headers.get('Content-Length')),checksum=request.headers.get('X-Aide-SHA256')||'';
 if(!range||!digest.test(checksum))fail(422,'chunk range and checksum required');
 const [start,end,total]=range.slice(1).map(Number);
 if(![start,end,total,length].every(Number.isSafeInteger)||total!==ticket.size||start<0||start>=total||
  start%uploadChunkSize!==0||end!==Math.min(total,start+uploadChunkSize)-1||length!==end-start+1||!request.body)fail(422,'invalid chunk range');
 const offset=uploadProgress(ticket).offset,index=start/uploadChunkSize;
 if(start<offset) {
  const part=ticket.parts?.[index];
  if(ticket.status!=='uploaded'&&part?.sha256!==checksum)fail(409,'chunk differs from saved file');
  await request.body.cancel();return json(uploadProgress(ticket));
 }
 if(start!==offset||ticket.status==='uploaded')fail(409,'chunk offset mismatch');
 const key='staging/parts/'+ticket.id+'/'+hash+'/'+crypto.randomUUID();
 let acknowledging=false;
 try {
  const stored=await env.RELEASES.put(key,request.body,{sha256:Uint8Array.from(checksum.match(/../g),byte=>parseInt(byte,16)).buffer,customMetadata:{expires:String(ticket.expires)}});
  if(!stored||stored.size!==length)fail(422,'chunk length mismatch');
  ticket.parts.push({key,size:length,sha256:checksum});
  acknowledging=true;
  if(!await saveUpload(env,ticket,latest))fail(409,'chunk offset changed; retry');
 }catch(error) {
  if(acknowledging) {
   let current;
   try {const object=await env.RELEASES.get('staging/status/'+ticket.id+'.json');current=object?JSON.parse(await object.text()):null;}
   catch {throw error;}
   if(current?.token_hash===hash&&current.parts?.some(part=>part.key===key))return json(uploadProgress(current));
  }
  await env.RELEASES.delete(key);
  if(/checksum/i.test(error.message||''))fail(422,'chunk checksum mismatch');
  throw error;
 }
 return json(uploadProgress(ticket));
}

async function credentialPage(env) {
 if(!/^[A-Za-z0-9+/=]{100,1000}$/.test(env.SERVER_PUBLIC_KEY||''))fail(503,'verification key unavailable');
 const style='body{font:16px system-ui;background:#14141a;color:#eee;max-width:520px;margin:60px auto;padding:24px}input,button{font:inherit;width:100%;padding:16px;margin:16px 0;border-radius:16px;box-sizing:border-box}button{background:#bdb6ff;border:0}p{line-height:1.5}';
 const script=`const ticket=location.hash.slice(1);history.replaceState(null,'',location.pathname);document.querySelector('button').onclick=async()=>{const input=document.querySelector('input'),status=document.querySelector('#status'),value=input.value.trim();if(!/^(github_pat_|ghp_)[A-Za-z0-9_]{20,220}$/.test(value)){status.textContent='Введите fine-grained GitHub token для выбранного репозитория.';return;}try{const der=Uint8Array.from(atob('${env.SERVER_PUBLIC_KEY}'),c=>c.charCodeAt(0));const key=await crypto.subtle.importKey('spki',der,{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'RSA-OAEP'},key,new TextEncoder().encode(value)));input.value='';const ciphertext=btoa(String.fromCharCode(...encrypted));const result=await fetch('/api/credential',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+ticket},body:JSON.stringify({ciphertext})});if(!result.ok)throw Error('HTTP '+result.status);status.textContent='Зашифрованные данные переданы. Вернитесь в бот: он проверит доступ.';}catch(error){status.textContent='Подключение не завершено: '+error.message;}};`;
 const hash=async value=>base64(await crypto.subtle.digest('SHA-256',encoder.encode(value)));
 return new Response('<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Подключение GitHub</title><style>'+style+'</style><h1>Подключить GitHub</h1><p>Создайте fine-grained token только для factorialovich/Aide-Pro-Modify, с правом Contents: Read and write. Токен шифруется в браузере; расшифровать его сможет только сервер бота.</p><input type="password" autocomplete="off" aria-label="GitHub token"><button>Подключить</button><p id="status" role="status"></p><script>'+script+'</script></html>',{headers:{...security,'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; script-src 'sha256-"+await hash(script)+"'; style-src 'sha256-"+await hash(style)+"'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"}});
}

export function uploadClient() {
 let token=location.hash.slice(1),expires=0;
 try {
  if(token)sessionStorage.setItem('aide-upload-ticket',token);
  else token=sessionStorage.getItem('aide-upload-ticket')||'';
 }catch {}
 history.replaceState(null,'',location.pathname);
 window.addEventListener('hashchange',()=>{if(location.hash)location.reload();});
 const input=document.querySelector('input'),button=document.querySelector('button');
 const status=document.querySelector('#status'),progress=document.querySelector('progress');
 button.disabled=true;
 const hash=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
 function failure(code,message) {
  const error=new Error(message||({401:'Ссылка истекла или отменена. Получите новую в боте.',403:'Откройте ссылку непосредственно из бота.',
   409:'Эта ссылка уже связана с другим файлом. Выберите прежний APK или получите новую ссылку.',
   413:'Выберите APK размером до 99 МБ.',422:'Проверка файла не прошла. Выберите исходный APK повторно.'}[code])||'Не удалось выполнить запрос.');
  error.status=code;return error;
 }
 function state(value) {
  if(!value||!Number.isSafeInteger(value.offset)||!Number.isSafeInteger(value.size)||value.offset<0||value.offset>value.size||
   !Number.isSafeInteger(value.chunkSize)||value.chunkSize<=0||!Number.isSafeInteger(value.expires))throw failure(422,'Некорректный ответ сервера.');
  expires=value.expires;
  progress.value=value.size?Math.floor(value.offset/value.size*100):0;
  return value;
 }
 async function api(path,data,timeout=30000) {
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
  try {
   const response=await fetch('/api/upload/'+path,{method:data===undefined?'GET':'POST',cache:'no-store',signal:controller.signal,
    headers:{Authorization:'Bearer '+token,...(data===undefined?{}:{'Content-Type':'application/json'})},body:data===undefined?undefined:JSON.stringify(data)});
   if(!response.ok)throw failure(response.status);
   return state(await response.json());
  }finally {clearTimeout(timer);}
 }
 async function retry(operation) {
  let attempt=0;
  while(true) {
   if(expires&&Date.now()>=expires*1000)throw failure(401);
   try{return await operation();}
   catch(error) {
    if(error.status&&error.status!==408&&error.status!==425&&error.status!==429&&error.status<500)throw error;
    const delay=Math.min(30000,1000*2**Math.min(++attempt,5));
    status.textContent=error.status===429?'Сервер занят. Загрузка продолжится автоматически.':
     'Связь прервалась. Сохранённые части остаются на сервере; загрузка продолжится после восстановления сети.';
    await new Promise(resolve=>{
     const done=()=>{clearTimeout(timer);window.removeEventListener('online',done);resolve();};
     const timer=setTimeout(done,delay);window.addEventListener('online',done,{once:true});
    });
   }
  }
 }
 function sendChunk(file,start,end,checksum) {
  return new Promise((resolve,reject)=>{
   const xhr=new XMLHttpRequest();xhr.open('POST','/api/upload/chunk');
   let idleTimer,lastLoaded=-1;
   const stalled=()=>xhr.abort();
   const resetIdle=()=>{clearTimeout(idleTimer);idleTimer=setTimeout(stalled,45000);};
   const cleanup=()=>{clearTimeout(idleTimer);window.removeEventListener('offline',stalled);};
   xhr.setRequestHeader('Authorization','Bearer '+token);
   xhr.setRequestHeader('Content-Type','application/vnd.android.package-archive');
   xhr.setRequestHeader('Content-Range','bytes '+start+'-'+(end-1)+'/'+file.size);
   xhr.setRequestHeader('X-Aide-SHA256',checksum);
   xhr.upload.onprogress=event=>{
    if(event.loaded>lastLoaded){lastLoaded=event.loaded;resetIdle();}
    if(event.lengthComputable) {
     const sent=Math.min(file.size,start+event.loaded);
     progress.value=Math.floor(sent/file.size*100);
     status.textContent=progress.value+'% — '+(sent/1048576).toFixed(1)+' из '+(file.size/1048576).toFixed(1)+' МБ';
    }
   };
   xhr.onload=()=>{cleanup();try {
    if(xhr.status<200||xhr.status>=300)throw failure(xhr.status);
    resolve(state(JSON.parse(xhr.responseText)));
   }catch(error){reject(error);}};
   xhr.onerror=xhr.ontimeout=xhr.onabort=()=>{cleanup();reject(failure(0));};
   window.addEventListener('offline',stalled,{once:true});resetIdle();
   try {xhr.send(file.slice(start,end));}catch(error){cleanup();reject(error);}
  });
 }
 function completed() {
  progress.value=100;button.textContent='Загружено';button.disabled=true;input.disabled=true;
  status.textContent='Файл загружен и проверен на целостность. Вернитесь в бот: он проверит подпись и версию APK.';
 }
 button.onclick=async()=>{
  const file=input.files[0];
  if(!file||!file.name.toLowerCase().endsWith('.apk')||file.size<=0||file.size>99000000) {
   status.textContent='Выберите APK размером до 99 МБ.';return;
  }
  button.disabled=true;input.disabled=true;button.textContent='Загрузка…';
  try {
   status.textContent='Проверяем выбранный файл…';
   const checksum=await hash(await file.arrayBuffer());
   let current;
   try {current=await retry(()=>api('start',{size:file.size,sha256:checksum}));}
   catch(error) {
    if(error.status!==409)throw error;
    current=await retry(()=>api('status'));
    if(current.size!==file.size||current.sha256!==checksum)throw error;
   }
   if(current.status==='uploaded'){completed();return;}
   while(current.offset<file.size) {
    const start=current.offset,end=Math.min(file.size,start+current.chunkSize);
    const partHash=await hash(await file.slice(start,end).arrayBuffer());
    try {current=await retry(()=>sendChunk(file,start,end,partHash));}
    catch(error) {
     if(error.status!==409)throw error;
     current=await retry(()=>api('status'));
     if(current.sha256!==checksum||current.offset<end)throw error;
    }
    if(current.offset<end)throw failure(422,'Сервер не подтвердил сохранение части файла.');
   }
   status.textContent='Все части получены. Проверяем целостность APK…';
   await retry(()=>api('complete',{},180000));completed();
  }catch(error) {
   status.textContent=error.message;button.textContent='Продолжить';button.disabled=false;input.disabled=false;
  }
 };
 if(!/^[A-Za-z0-9_-]{43}$/.test(token)) {
  status.textContent='Откройте ссылку загрузки из бота.';return;
 }
 retry(()=>api('status')).then(current=>{
  if(current.status==='uploaded'){completed();return;}
  button.disabled=false;
  button.textContent=current.size?'Продолжить':'Загрузить';
  status.textContent=current.size?'Сохранено '+(current.offset/1048576).toFixed(1)+' из '+(current.size/1048576).toFixed(1)+' МБ. Выберите тот же APK, чтобы продолжить.':'Выберите APK. При обрыве сети загрузка продолжится автоматически.';
 }).catch(error=>{status.textContent=error.message;});
}

async function uploadPage() {
 const css='body{font:16px system-ui;background:#14141a;color:#eee;max-width:520px;margin:60px auto;padding:24px}h1{font-size:28px}input,button{font:inherit;padding:16px;margin:16px 0;border-radius:16px;max-width:100%;box-sizing:border-box}button{background:#bdb6ff;color:#16121e;border:0;width:100%}progress{width:100%;height:18px;accent-color:#bdb6ff}#status{line-height:1.5;overflow-wrap:anywhere}';
 const js='('+uploadClient.toString()+')();';
 const hash=async value=>base64(await crypto.subtle.digest('SHA-256',encoder.encode(value)));
 return new Response('<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Загрузка AIDE APK</title><style>'+css+'</style><h1>Загрузить APK</h1><p>Ссылка действует сутки. При обрыве сети загрузка продолжится автоматически. После обновления страницы выберите тот же APK — сохранённые части отправлять заново не нужно.</p><input type="file" accept=".apk" aria-label="APK для загрузки"><button>Загрузить</button><progress value="0" max="100" aria-label="Ход загрузки"></progress><p id="status" role="status">Выберите файл.</p><script>'+js+'</script></html>',{headers:{...security,'X-Aide-Upload-Version':'2','Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; script-src 'sha256-"+await hash(js)+"'; style-src 'sha256-"+await hash(css)+"'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"}});
}

export async function handle(request,env,ctx) {
 const url=new URL(request.url),path=url.pathname;
 if(url.origin!==(env.PUBLIC_ORIGIN||'https://aide-pro-modify.pages.dev'))fail(421,'origin not allowed');
 if(url.protocol!=='https:') fail(400,'HTTPS required');
 burst(request,env);
 if(!['GET','HEAD','POST'].includes(request.method)) fail(405,'method not allowed');
 if(path.startsWith('/admin/')) {
  await admin(request,env);

  if(path==='/admin/download'&&request.method==='POST') {
   const value=await body(request,['files']);
   if(!Array.isArray(value.files)||!value.files.length||value.files.length>3)fail(422,'invalid files');
   const names=new Set();let total=0;
   for(const file of value.files) {
    if(!file||typeof file.name!=='string'||! /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(file.name)||names.has(file.name))fail(422,'invalid filename');
    names.add(file.name);text(file.data,44000);
    let bytes;try{bytes=unbase64(file.data);}catch{fail(422,'invalid file encoding');}
    if(base64(bytes)!==file.data||!bytes.length)fail(422,'invalid file encoding');
    total+=bytes.length;if(total>32000)fail(413,'files too large');
   }
   const token=base64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
   const expires=now()+86400;
   await env.RELEASES.put('private-downloads/'+await sha(token)+'.json',JSON.stringify({expires,files:value.files.map(file=>({name:file.name,data:file.data}))}),{customMetadata:{expires:String(expires)}});
   return json({expires,files:value.files.map(file=>({name:file.name,url:url.origin+'/api/download/'+token+'/'+file.name}))});
  }
  if(path==='/admin/download/delete'&&request.method==='POST') {
   const value=await body(request,['token']);if(!/^[A-Za-z0-9_-]{43}$/.test(value.token||''))fail(422,'invalid token');
   await env.RELEASES.delete('private-downloads/'+await sha(value.token)+'.json');return json({ok:true});
  }

  if(path==='/admin/messages'&&request.method==='POST') {
   const envelope=await body(request,['payload','signature']);const value=await verifiedMessage(env,envelope);
   await changeMessages(env,current=>{
    const index=current.filter(item=>item.id!==value.id&&item.expires>now());
    if(index.length>=20)fail(409,'20 active messages; remove one first');
    index.push({id:value.id,expires:value.expires,created:value.created,envelope});return index;
   });return json({ok:true,id:value.id});
  }
  if(path==='/admin/messages'&&request.method==='GET') {
   const items=[];for(const item of await messageIndex(env))if(item.expires>now())items.push(await verifiedMessage(env,item.envelope));
   return json({items});
  }
  if(path==='/admin/messages/delete'&&request.method==='POST') {
   const value=await body(request,['id']);if(!uuid.test(value.id))fail(422,'invalid ID');
   await changeMessages(env,index=>index.filter(item=>item.id!==value.id&&item.expires>now()));return json({ok:true});
  }
  if((path==='/admin/upload-ticket'||path==='/admin/credential-ticket')&&request.method==='POST') {
   await quota(env,'admin-upload-tickets',30,3600);
   const value=await body(request,['id']);if(!uuid.test(value.id))fail(422,'invalid ID');
   const token=base64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
   const kind=path==='/admin/credential-ticket'?'github':'apk';
   const ticket={id:value.id,expires:now()+(kind==='apk'?86400:1200),status:'waiting',kind,token_hash:await sha(token)};
   const previous=await env.RELEASES.get('staging/status/'+value.id+'.json');
   if(previous)await deleteUploadFiles(env,JSON.parse(await previous.text()));
   const options={customMetadata:{expires:String(ticket.expires)}};
   await env.RELEASES.put('staging/status/'+value.id+'.json',JSON.stringify(ticket),options);
   await env.RELEASES.put('staging/tickets/'+ticket.token_hash+'.json',JSON.stringify(ticket),options);
   return json({url:url.origin+(ticket.kind==='github'?'/api/github-connect#':'/api/upload/page#')+token,expires:ticket.expires});
  }

  if(path==='/admin/credential'&&request.method==='GET') {
   const id=url.searchParams.get('id')||'';if(!uuid.test(id))fail(422,'invalid ID');
   const object=await env.RELEASES.get('staging/status/'+id+'.json');if(!object)fail(404,'not found');
   const value=JSON.parse(await object.text());if(value.kind!=='github'||value.status!=='uploaded')fail(404,'not uploaded');
   return json({ciphertext:value.ciphertext});
  }

  const staged=/^\/admin\/staged\/([0-9a-f-]{36})\.apk$/.exec(path);
  if(staged&&request.method==='GET') {
   const status=await env.RELEASES.get('staging/status/'+staged[1]+'.json');if(!status)fail(404,'not found');
   const value=JSON.parse(await status.text());if(value.status!=='uploaded'||!value.object_key)fail(404,'not uploaded');
   const object=await env.RELEASES.get(value.object_key);if(!object)fail(404,'not found');
   return finiteObject(object,object.size,ctx);
  }
  if(path==='/admin/upload-status'&&request.method==='GET') {
   const id=url.searchParams.get('id')||'';if(!uuid.test(id))fail(422,'invalid ID');
   const object=await env.RELEASES.get('staging/status/'+id+'.json');if(!object)fail(404,'not found');
   const value=JSON.parse(await object.text());delete value.token_hash;delete value.object_key;delete value.ciphertext;delete value.parts;return json(value);
  }
  if(path==='/admin/upload-delete'&&request.method==='POST') {
   const value=await body(request,['id','keep_receipt']);if(!uuid.test(value.id))fail(422,'invalid ID');
   if(value.keep_receipt!==undefined&&typeof value.keep_receipt!=='boolean')fail(422,'invalid receipt flag');
   const object=await env.RELEASES.get('staging/status/'+value.id+'.json');
   if(object) {
    const ticket=JSON.parse(await object.text());
    const receipt=value.keep_receipt===true&&ticket.protocol===2&&ticket.status==='uploaded';
    if(receipt) {
     const retained={...ticket,parts:[],consumed:true};delete retained.object_key;
     if(!await saveUpload(env,retained,object))fail(409,'upload changed; retry');
    }
    await deleteUploadFiles(env,ticket,receipt);
   }
   return json({ok:true});
  }

  if(path==='/admin/prune'&&request.method==='POST') {
   await body(request,[]);
   await env.DB.batch([
    env.DB.prepare('DELETE FROM quotas WHERE expires<?').bind(now()),
    env.DB.prepare('DELETE FROM nonces WHERE expires<?').bind(now()),
    env.DB.prepare('DELETE FROM crashes WHERE acknowledged=1 AND created<?').bind(now()-30*86400)
   ]);
   await pruneDownloads(env);
   await pruneStaging(env);
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
   if(previous) {
    const old=JSON.parse(new TextDecoder().decode(unbase64(JSON.parse(await previous.text()).payload)));
    if(old.versionCode>value.versionCode)fail(409,'release downgrade blocked');
    if(old.versionCode===value.versionCode&&(old.sha256!==value.sha256||old.versionName!==value.versionName))fail(409,'version code already belongs to another APK');
   }
   const stored=await env.RELEASES.put('release.json',JSON.stringify(envelope),{httpMetadata:{contentType:'application/json'},onlyIf:new Headers(previous?{'If-Match':previous.httpEtag}:{'If-None-Match':'*'})});
   if(!stored)fail(409,'concurrent release update; retry');
   const archive=await env.RELEASES.get('release-history.json');
   let history=archive?JSON.parse(await archive.text()):[];
   history=history.filter(item=>JSON.parse(new TextDecoder().decode(unbase64(item.payload))).versionCode!==value.versionCode);
   history.push(envelope);history.sort((a,b)=>JSON.parse(new TextDecoder().decode(unbase64(a.payload))).versionCode-JSON.parse(new TextDecoder().decode(unbase64(b.payload))).versionCode);
   await env.RELEASES.put('release-history.json',JSON.stringify(history.slice(-20)));
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

 const download=/^\/api\/download\/([A-Za-z0-9_-]{43})\/([A-Za-z0-9][A-Za-z0-9._-]{0,79})$/.exec(path);
 if(download&&['GET','HEAD'].includes(request.method)) {
  const key='private-downloads/'+await sha(download[1])+'.json';
  const object=await env.RELEASES.get(key);if(!object)fail(404,'download not found');
  const record=JSON.parse(await object.text());
  if(!Number.isSafeInteger(record.expires)||record.expires<=now()){await env.RELEASES.delete(key);fail(404,'download expired');}
  const file=record.files.find(item=>item.name===download[2]);if(!file)fail(404,'file not found');
  const bytes=unbase64(file.data);
  const headers={...security,'Content-Type':'application/octet-stream','Content-Disposition':'attachment; filename="'+file.name+'"','Content-Length':String(bytes.length),'X-Robots-Tag':'noindex, nofollow, noarchive'};
  return new Response(request.method==='HEAD'?null:bytes,{headers});
 }

 if(path==='/api/github-connect'&&request.method==='GET')return credentialPage(env);
 if(path==='/api/upload/page'&&request.method==='GET')return uploadPage();
 if(['/api/upload/status','/api/upload/start','/api/upload/chunk','/api/upload/complete'].includes(path))return resumableUpload(request,env,url);
 if((path==='/api/upload'||path==='/api/credential')&&request.method==='POST') {
  const {ticket,latest,hash}=await loadUpload(request,env,url);

  if(path==='/api/credential') {
   if(ticket.kind!=='github')fail(401,'wrong ticket scope');
   const value=await body(request,['ciphertext']);text(value.ciphertext,700);
   const encrypted=unbase64(value.ciphertext);if(encrypted.byteLength<256||encrypted.byteLength>512)fail(422,'invalid encrypted credential');
   const used=await env.DB.prepare('INSERT OR IGNORE INTO nonces(id,expires) VALUES(?,?)').bind('upload:'+hash,ticket.expires).run();if(used.meta.changes!==1)fail(409,'ticket already used');
   ticket.status='uploaded';ticket.ciphertext=value.ciphertext;
   const updated=await env.RELEASES.put('staging/status/'+ticket.id+'.json',JSON.stringify(ticket),{onlyIf:new Headers({'If-Match':latest.httpEtag})});if(!updated)fail(409,'ticket superseded');
   return json({ok:true});
  }
  if(ticket.kind!=='apk')fail(401,'wrong ticket scope');
  if(ticket.protocol===2)fail(409,'continue using resumable upload');

  const length=Number(request.headers.get('Content-Length')),checksum=request.headers.get('X-Aide-SHA256')||'';
  if(!Number.isSafeInteger(length)||length<=0||length>99000000||!request.body)fail(413,'invalid APK size');if(!digest.test(checksum))fail(422,'checksum required');
  const used=await env.DB.prepare('INSERT OR IGNORE INTO nonces(id,expires) VALUES(?,?)').bind('upload:'+hash,ticket.expires).run();if(used.meta.changes!==1)fail(409,'ticket already used');
  ticket.object_key='staging/apk/'+ticket.id+'/'+hash+'.apk';
  try {
   const stored=await env.RELEASES.put(ticket.object_key,request.body,{sha256:Uint8Array.from(checksum.match(/../g),byte=>parseInt(byte,16)).buffer});
   if(!stored||stored.size!==length){await env.RELEASES.delete(ticket.object_key);fail(400,'APK length mismatch');}
   ticket.status='uploaded';ticket.sha256=checksum;ticket.size=length;
   const updated=await env.RELEASES.put('staging/status/'+ticket.id+'.json',JSON.stringify(ticket),{onlyIf:new Headers({'If-Match':latest.httpEtag})});
   if(!updated){await env.RELEASES.delete(ticket.object_key);fail(409,'upload ticket superseded');}return json({ok:true});
  }catch(error){ticket.status='failed';await env.RELEASES.put('staging/status/'+ticket.id+'.json',JSON.stringify(ticket),{onlyIf:new Headers({'If-Match':latest.httpEtag})});throw error;}
 }
 if(path==='/api/messages'&&request.method==='GET') {
  const installation=await authenticated(request,env);await quota(env,'messages:'+installation.id,120,3600);
  const items=[];for(const item of await messageIndex(env))if(item.expires>now()){
   const value=await verifiedMessage(env,item.envelope);
   if(!value.versions.length||value.versions.includes(installation.version))items.push(item.envelope);
  }
  return json({items});
 }

 if(path==='/api/register'&&request.method==='POST') {
  if(env.REGISTER_LIMIT&&!(await env.REGISTER_LIMIT.limit({key:peer})).success)fail(429,'rate limit');
  await quota(env,'register:'+await sha(peer),20,3600);
  await quota(env,'register-global',1000,3600);
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
 if(path==='/api/releases'&&request.method==='GET') {
  const archive=await env.RELEASES.get('release-history.json');
  const current=archive?null:await env.RELEASES.get('release.json');
  return json({items:archive?JSON.parse(await archive.text()):(current?[JSON.parse(await current.text())]:[])});
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
 async fetch(request,env,ctx) {try {const response=await handle(request,env,ctx);maintenance(env,ctx);return response;}catch(error) {return json({detail:error instanceof ApiError?error.message:'service unavailable'},error instanceof ApiError?error.status:503);}},
 async scheduled(event,env,ctx) {
  ctx.waitUntil(env.DB.batch([
   env.DB.prepare('DELETE FROM quotas WHERE expires<?').bind(now()),
   env.DB.prepare('DELETE FROM nonces WHERE expires<?').bind(now()),
   env.DB.prepare('DELETE FROM crashes WHERE acknowledged=1 AND created<?').bind(now()-30*86400)
  ]));
 }
};
