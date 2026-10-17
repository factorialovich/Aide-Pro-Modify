"""Rebuild mt-plugins/catalog.json from ready-to-install MTP packages, keeping version history."""
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
        labels = {}
        for key in ['name', 'description']:
            value = manifest.get(key, manifest['pluginID'] if key == 'name' else '')
            match = re.fullmatch(r'\{([\w.]+)(?::([\w.]+))?\}', value)
            if match:
                resource, label = (match[1], match[2]) if match[2] else ('strings', match[1])
                path = 'assets/' + resource + '.mtl'
                if path not in names:
                    path = next((n for n in names if n.startswith('assets/' + resource + '-') and n.endswith('.mtl')), '')
                found = re.search(r'^\s*' + re.escape(label) + r'\s*:\s*(.*)$', archive.read(path).decode('utf-8-sig'), re.M) if path else None
                value = found[1].strip() if found else manifest['pluginID']
            labels[key] = value
        return manifest, labels, icon, icon_data


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
        item['versions'].append({'version':manifest.get('versionName',str(code)), 'versionCode':code,
            'sha256':digest, 'size':len(data), 'file':'files/'+filename, 'source':'factorialovich', 'url':BASE+'files/'+filename,
            'minAndroid':manifest.get('minAndroidVersion',21), 'minHost':manifest.get('minHostVersion',0),
            'notes':labels['description'], 'published':''})
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
                    version.update(notes=past.get('notes',version['notes']), published=past.get('published',''))
    result = {'schema':91, 'revision':previous['revision'], 'items':sorted(items.values(),key=lambda i:i['name'].casefold()),
        'providers':[{'name':'factorialovich/Aide-Pro-Modify','url':BASE}]}
    if result != previous:
        result['revision'] = max(previous['revision']+1, int(time.time()))
        path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(str(len(items)) + ' plugins indexed')


if __name__ == '__main__':
    update(Path(__file__).resolve().parents[1])
