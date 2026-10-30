"""Temporary CI probe for the hosts asiaon.top links to: which are alive, and which can be fetched direct.

Read-only and capped: nothing is stored beyond a few megabytes per host, thrown away with the runner.
"""
import base64, json, os, random, re, shutil, struct, subprocess, sys, time
from collections import Counter, defaultdict
from urllib.parse import urlsplit

import cloudscraper
import requests

sys.path.insert(0, os.getcwd())
from inf.asiaon.client import AOClient, get_asiaon_session  # noqa: E402
from inf.utils.session import get_random_ua  # noqa: E402

CAP = int(os.environ.get('DL_CAP_MB', '24')) * 1024 ** 2
R = {'checks': [], 'env': {}}
SIG = {b'Rar!': 'rar', b'PK\x03\x04': 'zip', b'7z\xbc\xaf': '7z'}


def S():
    s = cloudscraper.session(); s.headers['User-Agent'] = get_random_ua()
    s.request = (lambda f: lambda *a, **k: f(*a, **{'timeout': 40, **k}))(s.request)
    return s


def rec(group, host, ident, status, **kw):
    R['checks'].append({'group': group, 'host': host, 'id': ident, 'status': status, **kw})
    print(f'{status:8s} {group:7s} {host:12s} {ident[:34]:34s} {json.dumps(kw, ensure_ascii=False)[:230]}', flush=True)


def title(text):
    m = re.search(r'<title>(.*?)</title>', text, re.S | re.I)
    return re.sub(r'\s+', ' ', m.group(1)).strip()[:70] if m else None


def timed(sess, url, cap=CAP, **kw):
    t0 = time.time(); r = sess.get(url, stream=True, **kw)
    out = {'http': r.status_code, 'length': int(r.headers.get('Content-Length') or 0), 'ctype': r.headers.get('Content-Type', '')[:30]}
    if r.status_code not in (200, 206):
        r.close(); return out
    n, first = 0, b''
    for c in r.iter_content(1 << 18):
        first = first or c[:8]; n += len(c)
        if n >= cap or time.time() - t0 > 90: break
    r.close(); dt = max(time.time() - t0, 1e-6)
    out.update(bytes=n, mbps=round(n / dt / 1024 ** 2, 1), kind=next((v for k, v in SIG.items() if first.startswith(k)), first[:6].hex()))
    return out


# ---------------------------------------------------------------- per-host liveness (+ partial download)
def chk_mediafire(url, dl):
    s = S(); r = s.get(url); t = r.text
    if 'downloadButton' not in t:
        return ('dead' if r.status_code == 404 or re.search(r'Invalid or Deleted|dangerous file|violat', t, re.I) else 'unknown'), {'http': r.status_code, 'title': title(t)}
    if not dl: return 'alive', {}
    btn = re.search(r'id="downloadButton"[^>]*?href="([^"]+)"', t) or re.search(r'href="([^"]+)"[^>]*?id="downloadButton"', t)
    scr = re.search(r'data-scrambled-url="([^"]+)"', t)
    direct = base64.b64decode(scr.group(1)).decode() if scr else (btn.group(1) if btn else None)
    return 'alive', {'dl': timed(s, direct) if direct else 'no direct link'}


def chk_pixeldrain(url, dl):
    m = re.search(r'pixeldrain\.com/(u|l)/([\w-]+)', url)
    if not m: return 'unknown', {'why': 'url shape'}
    kind, ident = m.groups(); s = S()
    r = s.get(f'https://pixeldrain.com/api/{"file" if kind == "u" else "list"}/{ident}' + ('/info' if kind == 'u' else ''))
    if r.status_code == 404: return 'dead', {}
    if r.status_code != 200: return 'unknown', {'http': r.status_code, 'body': r.text[:80]}
    j = r.json(); info = {'size': j.get('size') or sum(f.get('size', 0) for f in j.get('files', [])), 'avail': j.get('availability')}
    if not dl: return 'alive', info
    fid = ident if kind == 'u' else j['files'][0]['id']
    return 'alive', {**info, 'dl': timed(s, f'https://pixeldrain.com/api/file/{fid}?download')}


def chk_buzzheavier(url, dl):
    ident = urlsplit(url).path.strip('/').split('/')[0]; s = S(); r = s.get(f'https://buzzheavier.com/{ident}')
    if r.status_code == 404 or re.search(r'not found|does not exist|removed|deleted', r.text[:6000], re.I) and r.status_code != 200: return 'dead', {'http': r.status_code}
    if r.status_code != 200: return 'unknown', {'http': r.status_code}
    if not dl: return 'alive', {'title': title(r.text)}
    h = s.get(f'https://buzzheavier.com/{ident}/download', headers={'HX-Request': 'true', 'Referer': f'https://buzzheavier.com/{ident}'}, allow_redirects=False)
    loc = h.headers.get('hx-redirect') or h.headers.get('Location')
    return 'alive', {'title': title(r.text), 'redirect': (loc or '')[:60], 'dl': timed(s, loc if loc.startswith('http') else f'https://buzzheavier.com{loc}') if loc else {'http': h.status_code}}


def chk_vikingfile(url, dl):
    s = S(); r = s.get(url); t = r.text
    scripts = re.findall(r'src="([^"]+\.js[^"]*)"', t)[:3]; apis = sorted(set(re.findall(r'["\'](/api/[\w/\-]+)', t)))[:5]
    st = 'dead' if re.search(r'not found|doesn.t exist|deleted|removed', t[:8000], re.I) and r.status_code != 200 else ('alive' if r.status_code == 200 else 'unknown')
    return st, {'http': r.status_code, 'title': title(t), 'len': len(t), 'scripts': scripts, 'apis': apis, 'snippet': re.sub(r'\s+', ' ', re.sub(r'<script.*?</script>|<style.*?</style>', '', t, flags=re.S))[:200]}


def chk_terabox(url, dl):
    m = re.search(r'/(?:s|a-sl)/([\w-]+)', url)
    if not m: return 'unknown', {'why': 'url shape'}
    s = S(); sid = m.group(1); s.get(url)
    j = s.get('https://www.terabox.com/api/shorturlinfo', params={'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'shorturl': sid if sid.startswith('1') else '1' + sid, 'root': '1'}).json()
    return ('alive' if j.get('errno') == 0 else 'dead'), {'errno': j.get('errno'), 'files': len(j.get('list', []) or [])}


def b64u(x): return base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))


def chk_mega(url, dl):
    m = re.search(r'mega\.nz/(?:file/|folder/|embed/)([\w-]{8})#([\w-]+)', url) or re.search(r'mega\.nz/#(F?)!([\w-]{8})!([\w-]+)', url)
    if not m: return 'unknown', {'why': 'url shape'}
    g = m.groups(); folder = '/folder/' in url or url.split('#')[1].startswith('F')
    handle, key = (g[0], g[1]) if len(g) == 2 else (g[1], g[2])
    for attempt in range(4):
        if folder:
            r = requests.post('https://g.api.mega.co.nz/cs', params={'id': random.randint(1, 10 ** 9), 'n': handle}, json=[{'a': 'f', 'c': 1, 'r': 1}], timeout=40)
        else:
            r = requests.post('https://g.api.mega.co.nz/cs', params={'id': random.randint(1, 10 ** 9)}, json=[{'a': 'g', 'g': 1, 'p': handle}], timeout=40)
        j = r.json()
        if j == -3 or j == [-3]: time.sleep(3); continue
        break
    j = j[0] if isinstance(j, list) else j
    if isinstance(j, int): return ('dead' if j in (-9, -16, -11, -8, -2) else 'unknown'), {'mega_err': j}
    if folder: return ('alive' if j.get('f') else 'dead'), {'nodes': len(j.get('f', []))}
    info = {'size': j.get('s'), 'has_url': bool(j.get('g'))}
    if not dl or not j.get('g'): return 'alive', info
    try:  # decrypt the first MiB with the key from the link, to prove the stream is usable
        k = struct.unpack('>8I', b64u(key)); aes = struct.pack('>4I', k[0] ^ k[4], k[1] ^ k[5], k[2] ^ k[6], k[3] ^ k[7])
        iv = struct.pack('>4I', k[4], k[5], 0, 0)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        t0 = time.time(); rr = requests.get(j['g'] + '/0-' + str(CAP - 1), stream=True, timeout=60); buf = b''
        for c in rr.iter_content(1 << 18):
            buf += c
            if len(buf) >= CAP or time.time() - t0 > 90: break
        plain = Cipher(algorithms.AES(aes), modes.CTR(iv)).decryptor().update(buf)
        info['dl'] = {'http': rr.status_code, 'bytes': len(buf), 'mbps': round(len(buf) / max(time.time() - t0, 1e-6) / 1024 ** 2, 1), 'kind': next((v for kk, v in SIG.items() if plain.startswith(kk)), plain[:6].hex())}
    except Exception as e:
        info['dl'] = {'err': repr(e)[:120]}
    return 'alive', info


def chk_googledrive(url, dl):
    m = re.search(r'/d/([\w-]+)', url) or re.search(r'[?&]id=([\w-]+)', url)
    if 'drive.google.com' not in url or not m: return 'unknown', {'why': 'not a drive link', 'host': urlsplit(url).hostname}
    s = requests.Session(); s.headers['User-Agent'] = get_random_ua()
    r = s.get('https://drive.google.com/uc', params={'export': 'download', 'id': m.group(1)}, stream=True, timeout=40, allow_redirects=True)
    cd = r.headers.get('Content-Disposition'); t = '' if cd else r.text[:6000]
    if cd: 
        out = {'http': r.status_code, 'direct': True}
        if dl:
            n, t0 = 0, time.time()
            for c in r.iter_content(1 << 18):
                n += len(c)
                if n >= CAP or time.time() - t0 > 90: break
            out['dl'] = {'bytes': n, 'mbps': round(n / max(time.time() - t0, 1e-6) / 1024 ** 2, 1)}
        r.close(); return 'alive', out
    r.close()
    if r.status_code == 404 or re.search(r'does not exist|Sorry, the file you have requested', t): return 'dead', {'http': r.status_code}
    if 'accounts.google.com' in r.url: return 'dead', {'why': 'private (login required)'}
    if re.search(r'Quota exceeded|too many users|download quota', t, re.I): return 'quota', {}
    if re.search(r'virus scan|confirm=|Download anyway', t, re.I): return 'alive', {'note': 'large file, confirm page'}
    return 'unknown', {'http': r.status_code, 'title': title(t)}


def chk_generic(url, dl):
    s = S()
    try:
        r = s.get(url, allow_redirects=True); t = r.text[:20000]
    except Exception as e:
        return 'error', {'err': type(e).__name__, 'msg': str(e)[:90]}
    gone = bool(re.search(r'not found|no longer|deleted|removed|does not exist|expired|invalid|suspended|unavailable|404', t[:6000], re.I))
    ttl = title(t)
    st = 'dead' if r.status_code in (404, 410) or (gone and r.status_code == 200 and not re.search(r'download', t[:3000], re.I)) else ('alive' if r.status_code == 200 else 'unknown')
    return st, {'http': r.status_code, 'final': urlsplit(r.url).hostname, 'title': ttl, 'len': len(t)}


GF = {'tok': None, 'wt': None, 'sess': None}


def chk_gofile(url, dl):
    ident = urlsplit(url).path.strip('/').split('/')[-1]
    if GF['tok'] is None:
        open('wt.obf.js', 'w').write(S().get('https://gofile.io/js/wt.obf.js').text)
        g = S(); a = g.post('https://api.gofile.io/accounts')
        if a.status_code != 200: return 'unknown', {'step': 'account', 'http': a.status_code}
        GF.update(tok=a.json()['data']['token'], sess=g)
        GF['wt'] = subprocess.run(['node', 'gf_wt.mjs', GF['tok'], g.headers['User-Agent']], capture_output=True, text=True, timeout=60).stdout.strip()
    g = GF['sess']
    c = g.get(f'https://api.gofile.io/contents/{ident}', headers={'Authorization': f'Bearer {GF["tok"]}', 'X-Website-Token': GF['wt'], 'X-BL': 'en-US'})
    if c.status_code == 404 or '"error-notFound"' in c.text: return 'dead', {'http': c.status_code}
    if c.status_code != 200: return 'unknown', {'http': c.status_code, 'body': c.text[:80]}
    kids = [k for k in c.json()['data'].get('children', {}).values() if k.get('type') == 'file']
    if not kids: return 'dead', {'why': 'empty'}
    info = {'files': len(kids), 'bytes_total': sum(k.get('size', 0) for k in kids)}
    if dl:
        g.cookies.set('accountToken', GF['tok'], domain='.gofile.io')
        info['dl'] = timed(g, kids[0]['link'], headers={'Authorization': f'Bearer {GF["tok"]}'})
    return 'alive', info


HANDLERS = {'mediafire': chk_mediafire, 'pixeldrain': chk_pixeldrain, 'buzzheavier': chk_buzzheavier, 'vikingfile': chk_vikingfile,
            'terabox': chk_terabox, 'mega': chk_mega, 'googledrive': chk_googledrive, 'gofile': chk_gofile}


def host_of(key):
    return {'bayfiles': 'bayfile', 'anonfile': 'anonfile', 'annofile': 'annon'}.get(key, key)


def run_one(group, host, ident, url, dl):
    try:
        st, info = HANDLERS.get(host, chk_generic)(url, dl)
        rec(group, host, ident, st, **info)
    except Exception as e:
        rec(group, host, ident, 'error', err=repr(e)[:160])



import threading
from concurrent.futures import ThreadPoolExecutor

_local = threading.local()


def tclient():
    if not hasattr(_local, 'c'):
        _local.c = AOClient(session=get_asiaon_session()); _local.c.init()
    return _local.c


def tlinks(id_):
    for attempt in range(3):
        try:
            info = tclient().get_info(id_); return info['download_urls'], info
        except Exception as e:
            time.sleep(2)
    return {}, None


def password_candidates(text):
    out = []
    for tok in re.findall(r'[A-Za-z0-9][\w.\-]*\.(?:top|com|net|org)', text or ''):
        if tok not in out: out.append(tok)
    if text and len(text) <= 24 and text not in out: out.append(text)
    return out or ['asiaon.top', 'asiaontop.com']


def mf_direct(url, tries=5):
    last = None
    for _ in range(tries):
        s = S(); r = s.get(url); t = r.text
        if 'downloadButton' in t:
            scr = re.search(r'data-scrambled-url="([^"]+)"', t)
            btn = re.search(r'id="downloadButton"[^>]*?href="([^"]+)"', t) or re.search(r'href="([^"]+)"[^>]*?id="downloadButton"', t)
            return (base64.b64decode(scr.group(1)).decode() if scr else (btn.group(1) if btn else None)), s, _ + 1
        last = (r.status_code, title(t))
        if r.status_code == 404: break
    return None, None, last


def get_direct(host, url):
    """-> (session, direct_url, extra_headers, note) for the hosts that can be fetched without a browser."""
    if host == 'mediafire':
        d, s, info = mf_direct(url); return (s, d, {}, f'attempts={info}') if d else (None, None, {}, f'no direct: {info}')
    if host == 'pixeldrain':
        m = re.search(r'pixeldrain\.com/(u|l)/([\w-]+)', url); s = S(); ident = m.group(2)
        if m.group(1) == 'l':
            ident = s.get(f'https://pixeldrain.com/api/list/{ident}').json()['files'][0]['id']
        return s, f'https://pixeldrain.com/api/file/{ident}?download', {}, ''
    return None, None, {}, 'unsupported'


def to_file(s, url, path, headers=None, limit=None):
    t0 = time.time(); r = s.get(url, stream=True, headers=headers or {}); n = 0
    if r.status_code != 200: return {'http': r.status_code}
    with open(path, 'wb') as f:
        for c in r.iter_content(1 << 20):
            f.write(c); n += len(c)
            if limit and n >= limit: break
    dt = max(time.time() - t0, 1e-6)
    return {'http': 200, 'bytes': n, 'length': int(r.headers.get('Content-Length') or 0), 'sec': round(dt, 1), 'mbps': round(n / dt / 1024 ** 2, 1)}


def stage_scale():
    sample = json.load(open('ao_sample2.json')); jobs = [(h, i) for h, ids in sample.items() for i in ids]
    random.Random(1).shuffle(jobs)
    def work(job):
        host, id_ = job; links, _ = tlinks(id_); url = links.get(host)
        if not url: return host, id_, 'nolink', {}
        try:
            st, info = HANDLERS.get(host, chk_generic)(url, False); return host, id_, st, info
        except Exception as e:
            return host, id_, 'error', {'err': repr(e)[:100]}
    done = 0
    with ThreadPoolExecutor(int(os.environ.get('THREADS', '8'))) as ex:
        for host, id_, st, info in ex.map(work, jobs):
            R['checks'].append({'group': 'scale', 'host': host, 'id': id_, 'status': st, **info}); done += 1
            if done % 200 == 0: print('scale progress', done, '/', len(jobs), flush=True)


def stage_stab():
    ids = json.load(open('ao_recent_ids.json'))
    hosts = ['mediafire', 'pixeldrain']
    got = defaultdict(int)
    def work(id_):
        links, info = tlinks(id_); out = []
        for host in hosts:
            if links.get(host) and got[host] < int(os.environ.get('STAB_N', '30')):
                got[host] += 1
                s, d, hdr, note = get_direct(host, links[host])
                if not d: out.append((host, id_, 'fail', {'note': note})); continue
                p = f'/tmp/stab_{threading.get_ident()}.bin'; res = to_file(s, d, p, hdr, limit=CAP)
                out.append((host, id_, 'ok' if res.get('bytes') else 'fail', {**res, 'note': note, 'size_rough': info.get('file_size_rough') if info else None}))
                try: os.remove(p)
                except OSError: pass
        return out
    with ThreadPoolExecutor(3) as ex:
        for out in ex.map(work, ids):
            for host, id_, st, kw in out: rec('stab', host, id_, st, **kw)


def stage_full():
    ids = json.load(open('ao_recent_ids.json'))
    want = os.environ.get('FULL_BAND', '100,400').split(','); lo, hi = int(want[0]) * 1e6, int(want[1]) * 1e6
    tried = 0
    for id_ in ids:
        links, info = tlinks(id_)
        for host in ('mediafire', 'pixeldrain'):
            if not links.get(host): continue
            s, d, hdr, note = get_direct(host, links[host])
            if not d: rec('full', host, id_, 'fail', note=note); continue
            probe = s.get(d, stream=True, headers=hdr); length = int(probe.headers.get('Content-Length') or 0); probe.close()
            if not (lo <= length <= hi): continue
            path = '/tmp/full.zip'; res = to_file(s, d, path, hdr)
            kind = open(path, 'rb').read(4) if os.path.exists(path) else b''
            pws = password_candidates((info or {}).get('unzip_password')); outcome = {}
            for pw in pws + [None]:
                p = subprocess.run(['7z', 't', '-y', f'-p{pw or ""}', path], capture_output=True, text=True, stdin=subprocess.DEVNULL)
                outcome[pw or '(none)'] = p.returncode
            lst = subprocess.run(['7z', 'l', '-slt', path], capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout
            names = re.findall(r'^Path = (.+)$', lst, re.M)[1:]
            rec('full', host, id_, 'ok' if res.get('bytes') and res.get('bytes') == res.get('length') else 'fail', **res,
                sig=kind.hex(), pw_in_page=(info or {}).get('unzip_password'), pw_candidates=pws, test_rc=outcome, members=len(names),
                images=sum(n.lower().endswith(('.jpg', '.jpeg', '.png', '.webp')) for n in names), disk_free_gb=round(shutil.disk_usage('/tmp').free / 1024 ** 3, 1))
            os.remove(path); tried += 1
            break
        if tried >= int(os.environ.get('FULL_N', '3')): break


def stage_cffi():
    from curl_cffi import requests as cr
    ids = json.load(open('ao_recent_ids.json'))[:12]
    for id_ in ids:
        links, _ = tlinks(id_)
        for host in ('buzzheavier', 'mediafire'):
            url = links.get(host)
            if not url: continue
            try:
                s = cr.Session(impersonate='chrome124'); r = s.get(url, timeout=40)
                info = {'http': r.status_code, 'title': title(r.text)}
                if host == 'buzzheavier' and r.status_code == 200:
                    ident = urlsplit(url).path.strip('/').split('/')[0]
                    h = s.get(f'https://buzzheavier.com/{ident}/download', headers={'HX-Request': 'true', 'Referer': url}, allow_redirects=False, timeout=40)
                    loc = h.headers.get('hx-redirect'); info['redirect'] = (loc or '')[:70]
                    if loc:
                        rr = s.get(loc if loc.startswith('http') else 'https://buzzheavier.com' + loc, stream=True, timeout=60); n = 0; t0 = time.time()
                        for c in rr.iter_content(1 << 18):
                            n += len(c)
                            if n >= CAP or time.time() - t0 > 60: break
                        info['dl'] = {'http': rr.status_code, 'bytes': n, 'mbps': round(n / max(time.time() - t0, 1e-6) / 1024 ** 2, 1)}
                rec('cffi', host, id_, 'alive' if r.status_code == 200 else 'blocked', **info)
            except Exception as e:
                rec('cffi', host, id_, 'error', err=repr(e)[:140])


GD_GONE_WORDS = ('request access', 'you need access', 'sign in', 'not found', 'permission', 'does not exist')
GD_QUOTA_WORDS = ('too many users', 'many accesses', 'quota exceeded', 'unusual traffic', 'download quota')


def gd_url(endpoint, fid):
    if endpoint == 'uc':  # the gdown-style path
        return f'https://drive.google.com/uc?export=download&id={fid}'
    return f'https://drive.usercontent.google.com/download?id={fid}&export=download&confirm=t'


def gd_one(sess, endpoint, fid, cap, save=None):
    t0 = time.time(); r = sess.get(gd_url(endpoint, fid), stream=True, timeout=(15, 60))
    ctype = r.headers.get('Content-Type', '')
    if r.status_code == 200 and not ctype.lower().startswith('text/html'):
        n = 0; f = open(save, 'wb') if save else None
        for c in r.iter_content(1 << 20):
            n += len(c)
            if f: f.write(c)
            if cap and n >= cap or time.time() - t0 > 120: break
        r.close()
        if f: f.close()
        dt = max(time.time() - t0, 1e-6)
        return 'ok', {'bytes': n, 'length': int(r.headers.get('Content-Length') or 0), 'mbps': round(n / dt / 1024 ** 2, 1),
                      'kind': 'zip' if ctype.startswith('application/zip') else ctype[:24], 'disp': bool(r.headers.get('Content-Disposition'))}
    text = next(r.iter_content(6000), b'').decode('utf-8', 'replace').lower(); r.close()
    if any(w in text for w in GD_QUOTA_WORDS): return 'quota', {'http': r.status_code}
    if r.status_code in (401, 403, 404) or any(w in text for w in GD_GONE_WORDS): return 'gone', {'http': r.status_code}
    return 'transient', {'http': r.status_code, 'ctype': ctype[:30], 'peek': text[:80]}


def stage_gdrive():
    endpoint = os.environ.get('GD_ENDPOINT', 'usercontent'); gap = float(os.environ.get('GD_GAP', '1.0'))
    ids = json.load(open('ao_gd_ids.json')); sess = requests.Session(); sess.headers['User-Agent'] = MODERN_UA
    fids = []
    for id_ in ids:
        url = tlinks(id_)[0].get('googledrive') or ''
        m = re.search(r'/d/([\w-]+)', url)
        if m and 'drive.google.com' in url: fids.append((id_, m.group(1)))
    print('endpoint', endpoint, '| usable drive links', len(fids), flush=True)
    order = fids + fids[:60]; seq = 0; full_done = False
    for id_, fid in order:
        seq += 1; time.sleep(gap)
        try:
            st, info = gd_one(sess, endpoint, fid, CAP)
        except Exception as e:
            st, info = 'error', {'err': repr(e)[:100]}
        rec('gdrive', endpoint, id_, st, seq=seq, **info)
        if st == 'quota': time.sleep(20)
        if endpoint == 'usercontent' and st == 'ok' and not full_done and 20e6 < info.get('length', 0) < 600e6:
            full_done = True; path = '/tmp/gd_full.zip'; time.sleep(gap)
            st2, info2 = gd_one(sess, endpoint, fid, None, save=path)
            pw = tlinks(id_)[1].get('unzip_password') if tlinks(id_)[1] else None
            t = subprocess.run(['7z', 't', '-y', f'-p{(pw or "asiaon.top")}', path], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            lst = subprocess.run(['7z', 'l', '-slt', path], capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout
            rec('gdfull', endpoint, id_, st2, **info2, pw=pw, test_rc=t.returncode, members=len(re.findall(r'^Path = ', lst, re.M)) - 1)
            os.remove(path)


MODERN_UA = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36')



if __name__ == '__main__':
    R['env']['ip'] = S().get('https://api.ipify.org').text; print('egress ip', R['env']['ip'], flush=True)
    client = AOClient(session=get_asiaon_session()); client.init()
    downloaded = set()
    stages = os.environ.get('STAGES', 'recent,old').split(',')
    if 'recent' not in stages and 'old' not in stages: pass

    def links(id_):
        try: return client.get_info(id_)['download_urls']
        except Exception as e:
            print('detail fail', id_[:30], repr(e)[:80]); return {}

    if 'recent' in stages:
        ids = []
        for page in (1, 2, 3, 40, 80):
            try: ids += [(page, i['id']) for i in client.get_lst_page(page)]
            except Exception as e: print('list fail', page, repr(e)[:80])
        for page, id_ in ids:
            for key, url in links(id_).items():
                host = host_of(key)
                if host in HANDLERS or host in ('rapidgator',):
                    run_one(f'new{page}', host, id_, url, dl=(host not in downloaded and host in HANDLERS and host != 'terabox'))
                    if host in HANDLERS: downloaded.add(host) if R['checks'][-1]['status'] == 'alive' else None
    if 'old' in stages:
        sample = json.load(open('ao_sample.json'))
        for host, id_list in sample.items():
            for id_ in id_list:
                url = links(id_).get(host) or links(id_).get({'bayfile': 'bayfile', 'annon': 'annon'}.get(host, host))
                if not url: rec('old', host, id_, 'nolink'); continue
                run_one('old', host, id_, url, dl=(host + ':old' not in downloaded and host in HANDLERS and host != 'terabox'))
                if R['checks'][-1]['status'] == 'alive' and host in HANDLERS: downloaded.add(host + ':old')
    for st in stages:
        if st in ('scale', 'stab', 'full', 'cffi', 'gdrive'):
            print('=== stage', st, flush=True); globals()['stage_' + st]()
    json.dump(R, open('ao_results.json', 'w'), indent=1, ensure_ascii=False)
    print('\n=== SUMMARY (group, host: statuses)')
    tab = defaultdict(Counter)
    for c in R['checks']: tab[(c['group'].rstrip('0123456789'), c['host'])][c['status']] += 1
    for k in sorted(tab): print(k, dict(tab[k]))
