"""Rebuild mt-plugins/catalog.json from ready-to-install MTP packages, keeping version history."""
from datetime import datetime, timezone
import subprocess
import hashlib
import io
import json
import lzma
from pathlib import Path
import re
import time
import zipfile

try:
    import json5
except ImportError:
    json5 = json

BASE = 'https://raw.githubusercontent.com/factorialovich/Aide-Pro-Modify/main/mt-plugins/'
ID = r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+'
decompressor = zipfile._get_decompressor
zipfile._get_decompressor = lambda kind: lzma.LZMADecompressor() if kind == 95 else decompressor(kind)


def parse_mtl(text):
    entries={};line=''
    for part in text.replace('\r\n','\n').replace('\r','\n').split('\n'):
        line+=part
        trailing=len(line)-len(line.rstrip('\\'))
        if trailing%2:
            line=line[:-1]
            continue
        match=re.fullmatch(r'\s*([\w.-]+)\s*:[ \t]*(.*)',line)
        if match:
            escapes={'n':'\n','r':'\r','t':'\t','\\':'\\','"':'"',"'":"'"}
            entries[match[1]]=re.sub(r'\\([nrt\\"\'])',lambda m:escapes[m[1]],match[2].strip())
        line=''
    if line:raise ValueError('Unterminated MTL continuation')
    return entries


def resolve_label(archive,value,tables):
    if not isinstance(value,str):raise ValueError('Plugin labels must be strings')
    match=re.fullmatch(r'\{([\w.]+)(?::([\w.]+))?\}',value)
    if not match:return value
    resources=[match[1]] if match[2] else ['String','strings']
    label=match[2] or match[1]
    names=set(archive.namelist())
    for resource in resources:
        base='assets/'+resource
        paths=[base+'.mtl']+sorted((n for n in names if n.startswith(base+'-') and n.endswith('.mtl')),
            key=lambda n:(not n.startswith(base+'-en.'),not n.startswith(base+'-en-'),n))
        for path in paths:
            if path not in names:continue
            if path not in tables:
                if archive.getinfo(path).file_size>2*1024*1024:raise ValueError('MTL resource exceeds 2 MiB')
                tables[path]=parse_mtl(archive.read(path).decode('utf-8-sig'))
            if label in tables[path]:return tables[path][label]
    raise ValueError('Missing plugin text resource: '+value)


def inspect(data):
    if len(data) > 64 * 1024 * 1024:
        raise ValueError('MTP exceeds 64 MiB')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) > 10000 or sum(i.file_size for i in archive.infolist()) > 64 * 1024 * 1024:
            raise ValueError('Invalid MTP entries/size')
        for name in names:
            if name.startswith('/') or '\\' in name or '..' in name.split('/') or '\0' in name:
                raise ValueError('Unsafe MTP path')
        entry = archive.getinfo('manifest.json')
        if entry.file_size > 65536:
            raise ValueError('Manifest exceeds 64 KiB')
        manifest = json5.loads(archive.read(entry).decode('utf-8-sig'))
        if not isinstance(manifest.get('developer',''),str) or len(manifest.get('developer',''))>128:
            raise ValueError('Invalid plugin developer')
        if not re.fullmatch(ID, manifest['pluginID']) or type(manifest['versionCode']) is not int or manifest['versionCode'] < 1:
            raise ValueError('Invalid plugin identity/version')
        if manifest.get('pluginSdkVersion') not in (1,2,3) or not (manifest.get('interfaces') or manifest.get('mainPreference')):
            raise ValueError('Unsupported plugin SDK/entry point')
        if 'classes.dex' not in names and 'code.jar' not in names:
            raise ValueError('Build this source package in the local Developer Center first, then upload the resulting MTP')
        for name in names:
            if re.fullmatch(r'classes(?:[2-9][0-9]*)?\.dex', name):
                if archive.read(name)[:4] != b'dex\n':
                    raise ValueError('Invalid plugin DEX')
        icon = next((n for n in names if re.fullmatch(r'icon\.(png|webp|jpe?g)', n)), '')
        icon_data = archive.read(icon) if icon else b''
        tables = {}
        labels = {key:resolve_label(archive,manifest.get(key,manifest['pluginID'] if key=='name' else ''),tables)
                  for key in ['name','description']}
        return manifest, labels, icon, icon_data


def updated_at(version):
    stamp=version.get('updatedAt',0)
    if type(stamp) is int and stamp>0:return stamp
    published=version.get('published')
    if not isinstance(published,str) or not published:return 0
    try:
        value=datetime.fromisoformat(published.replace('Z','+00:00'))
        if value.tzinfo is None:value=value.replace(tzinfo=timezone.utc)
        return max(0,int(value.timestamp()*1000))
    except (ValueError,OverflowError,OSError):return 0


def order_key(item):
    versions=item.get('versions',[])
    stamp=updated_at(versions[0]) if versions else 0
    return -stamp,item.get('name','').casefold(),item['id']


def package_date(root,filename):
    # Checkout mtimes change on every CI run; use the immutable package's commit date.
    result=subprocess.run(['git','-C',str(root),'log','-1','--format=%ct','--',filename],
        capture_output=True,text=True,timeout=10)
    stamp=result.stdout.strip()
    return int(stamp)*1000 if result.returncode==0 and stamp.isdigit() else int(time.time()*1000)


def update(root):
    path = root / 'catalog.json'
    previous = json.loads(path.read_text()) if path.exists() else {'schema':91, 'revision':0, 'items':[]}
    old = {item['id']:item for item in previous['items']}
    files = root / 'files'
    files.mkdir(exist_ok=True)
    incoming = root / 'incoming'
    incoming.mkdir(exist_ok=True)
    for package in sorted(incoming.glob('*.mtp')):
        original = package.read_bytes()
        manifest, _, _, _ = inspect(original)
        normalized = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(original)) as src, zipfile.ZipFile(normalized, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as dst:
            for entry in src.infolist():
                value = (json.dumps(manifest, ensure_ascii=False, indent=2).encode() if entry.filename == 'manifest.json'
                         else b'' if entry.is_dir() else src.read(entry))
                dst.writestr(entry.filename, value)
        target = files / (manifest['pluginID'] + '-' + str(manifest['versionCode']) + '.mtp')
        data = normalized.getvalue()
        if target.exists() and target.read_bytes() != data:
            raise ValueError('Version already exists: increase versionCode instead of replacing ' + target.name)
        target.write_bytes(data)
        package.unlink()
    items = {}
    for package in sorted(files.glob('*.mtp')):
        data = package.read_bytes()
        manifest, labels, icon, icon_data = inspect(data)
        id, code = manifest['pluginID'], manifest['versionCode']
        filename = id + '-' + str(code) + '.mtp'
        if package.name != filename:
            raise ValueError('Rename package to ' + filename)
        digest = hashlib.sha256(data).hexdigest()
        item = items.setdefault(id, {'id':id, 'name':labels['name'], 'description':labels['description'], 'icon':'', 'versions':[]})
        item['developer'] = manifest.get('developer', old.get(id, {}).get('developer', ''))
        item['versions'].append({'version':manifest.get('versionName',str(code)), 'versionCode':code,
            'sha256':digest, 'size':len(data), 'file':'files/'+filename, 'source':'factorialovich', 'url':BASE+'files/'+filename,
            'minAndroid':manifest.get('minAndroidVersion',21), 'minHost':manifest.get('minHostVersion',0),
            'notes':labels['description'], 'published':'', 'sdk':manifest.get('pluginSdkVersion',3)})
        # The highest version supplies the card's name, description and icon.
        if code == max(v['versionCode'] for v in item['versions']):
            item.update(name=labels['name'], description=labels['description'])
            if icon:
                iconpath = 'icons/' + digest + '.' + icon.rsplit('.',1)[1]
                (root/'icons').mkdir(exist_ok=True)
                (root/iconpath).write_bytes(icon_data)
                item['icon'] = iconpath
    for item in items.values():
        item['versions'].sort(key=lambda v:v['versionCode'], reverse=True)
        if item['id'] in old:
            for version in item['versions']:
                past = next((v for v in old[item['id']]['versions'] if v['versionCode']==version['versionCode']), None)
                if past and past['sha256'] != version['sha256']:
                    raise ValueError('Published version changed: ' + version['file'])
                if past:
                    notes=past.get('notes',version['notes'])
                    # Earlier indexes used the unresolved package ID or truncated description as generated notes.
                    if notes==old[item['id']].get('description') or notes==item['id']:notes=version['notes']
                    version.update(notes=notes, published=past.get('published',''))
                    for field in ['interfaces','updatedAt']:
                        if field in past:version[field]=past[field]
    for item in items.values():
        for version in item['versions']:
            stamp=updated_at(version)
            if not stamp:stamp=package_date(root,version['file'])
            version['updatedAt']=stamp
    result = {'schema':91, 'revision':previous['revision'], 'items':sorted(items.values(),key=order_key),
        'providers':[{'name':'factorialovich/Aide-Pro-Modify','url':BASE}]}
    if result != previous:
        result['revision'] = max(previous['revision']+1, int(time.time()))
        path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(str(len(items)) + ' plugins indexed')


if __name__ == '__main__':
    update(Path(__file__).resolve().parents[1])
