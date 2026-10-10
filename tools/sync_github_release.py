"""GitHub Actions mirror: only server-signed, checksum-verified Cloudflare APKs are released."""
import base64,hashlib,json,os,re,subprocess,tempfile,time,urllib.request,urllib.error
from pathlib import Path
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
ORIGIN='https://aide-pro-modify.pages.dev'
REPOSITORY='factorialovich/Aide-Pro-Modify'
KEY=os.environ['AIDE_UPDATE_PUBLIC_KEY']
public=serialization.load_der_public_key(base64.b64decode(KEY))
def get(path):
 request=urllib.request.Request(path,headers={'User-Agent':'AIDE-GitHub-Sync/1.0','Accept':'application/json'})
 with urllib.request.urlopen(request,timeout=60) as response:
  raw=response.read(512001)
  if len(raw)>512000:raise ValueError('manifest too large')
  return json.loads(raw)
def gh(*args,input=None,check=True):return subprocess.run(['gh',*args],input=input,capture_output=True,text=True,check=check)
def verify(envelope):
 raw=base64.b64decode(envelope['payload'],validate=True);signature=base64.b64decode(envelope['signature'],validate=True)
 if len(raw)>16000:raise ValueError('payload too large')
 public.verify(signature,raw,padding.PKCS1v15(),hashes.SHA256());value=json.loads(raw)
 if not isinstance(value['versionCode'],int) or not 0<value['versionCode']<2147483648:raise ValueError('version code')
 if not re.fullmatch(r'\d{1,4}(?:\.\d{1,4}){2,3}(?:-(?:alpha|beta|rc)\d{0,3})?',value['versionName']):raise ValueError('version name')
 if not re.fullmatch('[a-f0-9]{64}',value['sha256']) or value['url']!=ORIGIN+'/api/apk/'+value['sha256']+'.apk':raise ValueError('origin or hash')
 if not 0<value['size']<=99000000 or value['issued']>time.time()+300 or not 0<value['expires']-value['issued']<=86400:raise ValueError('validity')
 return value
def main():
 with tempfile.TemporaryDirectory() as directory:
  root=Path(directory)
  result=get(ORIGIN+'/api/releases')
  for envelope in result.get('items',[]):
   release=verify(envelope);tag='v'+release['versionName']+'-'+str(release['versionCode']);name='AIDE-'+release['versionName']+'.apk'
   existing=gh('api','repos/'+REPOSITORY+'/releases/tags/'+tag,check=False)
   if existing.returncode==0:
    assets=json.loads(existing.stdout).get('assets',[])
    asset=next((asset for asset in assets if asset['name']==name),None)
    if asset:
     if asset.get('digest')!='sha256:'+release['sha256'] or asset.get('size')!=release['size']:raise ValueError('Existing release asset differs; manual review required')
     continue
   elif '404' not in existing.stderr:raise RuntimeError('Could not inspect GitHub release')
   path=root/name;digest=hashlib.sha256();total=0
   request=urllib.request.Request(release['url'],headers={'User-Agent':'AIDE-GitHub-Sync/1.0'})
   with urllib.request.urlopen(request,timeout=90) as remote,path.open('wb') as output:
    while total<release['size']:
     data=remote.read(min(1048576,release['size']-total))
     if not data:raise ValueError('truncated APK')
     digest.update(data);output.write(data);total+=len(data)
   if total!=release['size'] or digest.hexdigest()!=release['sha256']:raise ValueError('APK checksum mismatch')
   notes=root/'notes.md';notes.write_text(release.get('notes','')+'\n\nSHA-256: `'+release['sha256']+'`\n',encoding='utf8')
   if existing.returncode:gh('release','create',tag,'--repo',REPOSITORY,'--title','AIDE '+release['versionName'],'--notes-file',str(notes))
   gh('release','upload',tag,str(path),'--repo',REPOSITORY)
   confirmed=json.loads(gh('api','repos/'+REPOSITORY+'/releases/tags/'+tag).stdout)
   asset=next((item for item in confirmed.get('assets',[]) if item['name']==name),None)
   if not asset or asset.get('digest')!='sha256:'+release['sha256'] or asset.get('size')!=release['size']:raise ValueError('GitHub did not confirm the complete file')
   print('Published '+tag+' after signature and file checksum validation',flush=True)

if __name__=="__main__":main()
