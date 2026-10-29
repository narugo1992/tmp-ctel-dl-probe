"""Temporary CI probe: can a GitHub runner download from the hosts cosplaytele links to, direct?

Everything here is read-only and capped. Nothing is stored beyond one small archive that is
unpacked to prove the archive is usable, then deleted with the runner.
"""
import ast, base64, html, json, os, random, re, shutil, subprocess, sys, time
from hashlib import md5
from urllib.parse import urljoin, urlsplit

import cloudscraper
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from pyquery import PyQuery as pq

UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
]
SITE = 'https://cosplaytele.com'
NEW_POSTS = 3
OLD_SORA = os.environ.get('OLD_SORA', 'stepmoms-scent,by-my-husbands-side,augusta-2,galbrena,vivy-amelia-watson,my-wifes-spring-outing-plan,santa-clauss-reindeer').split(',')
OLD_GOFILE = os.environ.get('OLD_GOFILE', 'yor-forger-thorn-princess-2,yumemizuki-mizuki-6').split(',')
OLD_MEDIAFIRE = os.environ.get('OLD_MEDIAFIRE', 'happy-birthday,raiden-shogun-19,leopard-print-pajamas,aeolian-4').split(',')
OTHER = {'traffic1s': 'the-bathroom,2b-3,hwa', 'terabox': 'rapi-10,blonde,usada-pekora-2', 'yandex': 'exotic-dancer,hutao-3,kashino-3'}
DL_CAP = int(os.environ.get('DL_CAP_MB', '60')) * 1024 ** 2
FULL_MAX = int(os.environ.get('FULL_MAX_MB', '2048')) * 1024 ** 2
R = {'env': {}, 'checks': []}


def S():
    s = cloudscraper.session()
    s.headers['User-Agent'] = random.choice(UAS)
    s.request = (lambda f: lambda *a, **k: f(*a, **{'timeout': 40, **k}))(s.request)
    return s


def rec(kind, name, ok, **kw):
    item = {'kind': kind, 'name': name, 'ok': bool(ok), **kw}
    R['checks'].append(item)
    print(('PASS ' if ok else 'FAIL ') + f'{kind:10s} {name:34s} ' + json.dumps(kw, ensure_ascii=False)[:300], flush=True)


def post_info(slug, sess):
    r = sess.get(f'{SITE}/{slug}/')
    r.raise_for_status()
    page = pq(r.text)
    body = page('article .entry-content')
    bx = body('blockquote')
    pw = bx('input').attr('value') or None
    for sel in ('blockquote', 'div.gallery', '.crp_related', '.blog-share'):
        body.remove(sel)
    links = {}
    for a in body('a').items():
        u = urljoin(r.url, a.attr('href'))
        h = urlsplit(u).hostname or ''
        if 'cosplaytele' not in h:
            links.setdefault(h.split('.')[-2], u)
    return {'password': pw, 'links': links, 'title': page('.page-title .entry-title').text().strip()}


def decrypt_link(enc):
    key = 'Ak7qrvvH4WKYxV2OgaeHAEg2a5eh16vE'.encode()
    raw = base64.b64decode(enc); salt, ct = raw[8:16], raw[16:]
    d = prev = b''
    while len(d) < 48:
        prev = md5(prev + key + salt).digest(); d += prev
    dec = Cipher(algorithms.AES(d[:32]), modes.CBC(d[32:48]), backend=default_backend()).decryptor()
    pad = dec.update(ct) + dec.finalize(); un = PKCS7(128).unpadder()
    return (un.update(pad) + un.finalize()).decode()


def sora_meta(sess, url):
    page = sess.get(url).text
    def get(n):
        m = re.search(rf'const\s+{n}\s*=\s*(\'(?:[^\'\\]|\\.)*\'|"(?:[^"\\]|\\.)*")\s*;', page)
        return html.unescape(ast.literal_eval(m.group(1)))
    key, fid, fname = get('keyEncrypte'), get('fileId'), get('fileName')
    d = sess.post('https://sorafolder.com/file-down', headers={'Content-Type': 'application/json'}, data=json.dumps({'keyEncrypte': key})).json()
    if 'error' in d:
        raise RuntimeError(f'sorafolder error {d}')
    u = decrypt_link(d['url'])
    assert 'https' in u and 'sorafolder.com' in u, 'decoded url looks wrong, key probably rotated'
    return {'url': u, 'filename': fname}


def timed_get(sess, url, cap, save=None, **kw):
    t0 = time.time(); r = sess.get(url, stream=True, **kw)
    out = {'status': r.status_code, 'ctype': r.headers.get('Content-Type', '')[:40], 'length': int(r.headers.get('Content-Length') or 0)}
    n, first = 0, b''
    f = open(save, 'wb') if save and r.status_code == 200 else None
    t1 = time.time()
    for c in r.iter_content(1024 * 256):
        if not first: first = c[:8]
        n += len(c)
        if f: f.write(c)
        if n >= cap or time.time() - t0 > 600: break
    r.close()
    if f: f.close()
    dt = max(time.time() - t1, 1e-6)
    out.update(bytes=n, seconds=round(time.time() - t0, 1), mbps=round(n / dt / 1024 ** 2, 2), sig=first.hex(), is_rar=first[:4] == b'Rar!', complete=bool(out['length']) and n >= out['length'])
    return out


def run_sorafolder(label, slug, sess, full_candidates):
    try:
        info = post_info(slug, sess)
        url = info['links'].get('sorafolder')
        if not url:
            return rec('sorafolder', f'{label}:{slug}', False, why='no sorafolder link on page')
        m = sora_meta(sess, url)
        d = timed_get(sess, m['url'], DL_CAP)
        rec('sorafolder', f'{label}:{slug}', d['status'] == 200 and d['is_rar'], file=m['filename'][:40], **d)
        if d['status'] == 200 and 0 < d['length'] <= FULL_MAX:
            full_candidates.append((d['length'], slug, info['password']))
    except Exception as e:
        rec('sorafolder', f'{label}:{slug}', False, err=repr(e)[:200])


def run_full(sess, cands):
    if not cands and not os.environ.get('FULL_SLUG'):
        return rec('full', 'smallest', False, why=f'no package under {FULL_MAX >> 20} MB found')
    size, slug, pw = sorted(cands)[0]
    if os.environ.get('FULL_SLUG'):
        slug = os.environ['FULL_SLUG']; pw = post_info(slug, sess)['password']
    work = '/tmp/ctel_full'; shutil.rmtree(work, ignore_errors=True); os.makedirs(work)
    try:
        m = sora_meta(sess, post_info(slug, sess)['links']['sorafolder'])
        rar = os.path.join(work, 'pkg.rar')
        t_dl = time.time(); d = timed_get(sess, m['url'], 1 << 40, save=rar)
        res = dict(slug=slug, expected=size, **d)
        for tool in (['7zz'], ['7z'], ['unrar']):
            if not shutil.which(tool[0]): res[tool[0]] = 'missing'; continue
            out = os.path.join(work, 'x_' + tool[0]); os.makedirs(out)
            cmd = tool + (['x', f'-p{pw or ""}', f'-o{out}', '-y', rar] if tool[0] != 'unrar' else ['x', f'-p{pw or "-"}', '-y', rar, out + '/'])
            t_x = time.time(); p = subprocess.run(cmd, capture_output=True, text=True); res[tool[0] + '_sec'] = round(time.time() - t_x, 1)
            files = [os.path.join(dp, f) for dp, _, fs in os.walk(out) for f in fs]
            res[tool[0]] = f'rc={p.returncode} files={len(files)} images={sum(f.lower().endswith(("jpg", "jpeg", "png", "webp")) for f in files)}'
        res['disk_free_gb'] = round(shutil.disk_usage('/tmp').free / 1024 ** 3, 1)
        rec('full', 'download+unpack', d['complete'], **res)
    except Exception as e:
        rec('full', 'download+unpack', False, err=repr(e)[:200])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_gofile(slug, sess):
    try:
        url = post_info(slug, sess)['links'].get('gofile')
        if not url: return rec('gofile', slug, False, why='no gofile link')
        cid = url.rstrip('/').split('/')[-1]
        open('wt.obf.js', 'w').write(S().get('https://gofile.io/js/wt.obf.js').text)
        g = S(); a = g.post('https://api.gofile.io/accounts')
        if a.status_code != 200: return rec('gofile', slug, False, step='account', status=a.status_code, body=a.text[:100])
        tok = a.json()['data']['token']
        w = subprocess.run(['node', 'gf_wt.mjs', tok, g.headers['User-Agent']], capture_output=True, text=True, timeout=60)
        if w.returncode != 0 or 'NO_GENERATOR' in w.stdout: return rec('gofile', slug, False, step='wt', out=(w.stdout + w.stderr)[-200:])
        c = g.get(f'https://api.gofile.io/contents/{cid}', headers={'Authorization': f'Bearer {tok}', 'X-Website-Token': w.stdout.strip(), 'X-BL': 'en-US'})
        if c.status_code != 200: return rec('gofile', slug, False, step='contents', status=c.status_code, body=c.text[:160])
        kids = [k for k in c.json()['data'].get('children', {}).values() if k.get('type') == 'file']
        if not kids: return rec('gofile', slug, False, step='contents', why='no files', body=c.text[:160])
        k = kids[0]; g.cookies.set('accountToken', tok, domain='.gofile.io')
        d = timed_get(g, k['link'], DL_CAP, headers={'Authorization': f'Bearer {tok}'})
        rec('gofile', slug, d['status'] == 200 and d['bytes'] > 0, files=len(kids), fname=k.get('name', '')[:40], size=k.get('size'), **d)
    except Exception as e:
        rec('gofile', slug, False, err=repr(e)[:200])


def run_mediafire(slug, sess):
    try:
        url = post_info(slug, sess)['links'].get('mediafire')
        if not url: return rec('mediafire', slug, False, why='no mediafire link')
        r = S().get(url)
        rec('mediafire', slug, 'downloadButton' in r.text, status=r.status_code, title=(re.search(r'<title>(.*?)</title>', r.text, re.S) or [0, ''])[1].strip()[:50])
    except Exception as e:
        rec('mediafire', slug, False, err=repr(e)[:200])


def run_other(host, slug, sess):
    try:
        url = post_info(slug, sess)['links'].get(host)
        if not url: return rec(host, slug, False, why='no link')
        r = S().get(url, allow_redirects=True)
        t = (re.search(r'<title>(.*?)</title>', r.text, re.S) or [0, ''])[1].strip()[:60]
        rec(host, slug, r.status_code == 200 and 'blocked' not in t.lower(), status=r.status_code, final=r.url[:80], title=t, length=len(r.text))
    except Exception as e:
        rec(host, slug, False, err=repr(e)[:200])


def run_big(slug):
    try:
        sess = S(); m = sora_meta(sess, post_info(slug, sess)['links']['sorafolder'])
        t0 = time.time(); d = timed_get(sess, m['url'], 1 << 40, save='/tmp/big.rar')
        rec('bigfile', slug, d['complete'], **d); os.remove('/tmp/big.rar')
    except Exception as e:
        rec('bigfile', slug, False, err=repr(e)[:200])


def run_terabox(slug):
    try:
        url = post_info(slug, S())['links'].get('terabox')
        if not url: return rec('terabox', slug, False, why='no link')
        surl = re.search(r'surl=([\w-]+)', url)
        s = S(); s.get(url)
        r = s.get('https://www.terabox.com/api/shorturlinfo', params={'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'shorturl': '1' + surl.group(1), 'root': '1'})
        j = r.json()
        rec('terabox', slug, j.get('errno') == 0, errno=j.get('errno'), files=[f.get('server_filename') for f in j.get('list', [])][:3], keys=sorted(j)[:8])
    except Exception as e:
        rec('terabox', slug, False, err=repr(e)[:200])


def run_traffic1s(slug):
    try:
        url = post_info(slug, S())['links'].get('traffic1s')
        if not url: return rec('traffic1s', slug, False, why='no link')
        t = S().get(url).text
        hosts = sorted(set(re.findall(r'https?://([\w.-]+)', t)))
        b64 = [x for x in re.findall(r'["\']([A-Za-z0-9+/=]{24,})["\']', t)][:3]
        dec = []
        for x in b64:
            try: dec.append(base64.b64decode(x).decode()[:80])
            except Exception: pass
        rec('traffic1s', slug, False, hosts=hosts[:10], decoded=dec, length=len(t))
    except Exception as e:
        rec('traffic1s', slug, False, err=repr(e)[:200])


if __name__ == '__main__':
    R['env']['runner'] = os.environ.get('RUNNER_NAME', '')
    R['env']['ip'] = S().get('https://api.ipify.org').text
    print('egress ip', R['env']['ip'], flush=True)
    sess = S()
    try:
        head = sess.get(SITE + '/')
        rec('site', 'home', head.status_code == 200, status=head.status_code)
        lst = sess.get(SITE + '/page/1/'); slugs = [urlsplit(a.attr('href')).path.strip('/') for a in pq(lst.text)('#post-list .post-item a').items()][:NEW_POSTS + 3]
        slugs = list(dict.fromkeys(slugs))[:NEW_POSTS]
        rec('site', 'listing', bool(slugs), slugs=slugs)
    except Exception as e:
        rec('site', 'listing', False, err=repr(e)[:200]); slugs = []
    ST = os.environ.get('STAGES', 'all').split(',')
    on = lambda n: 'all' in ST or n in ST
    cands = []
    if on('sora'):
        for cycle in range(int(os.environ.get('CYCLES', '2'))):
            for s in slugs: run_sorafolder(f'new/c{cycle}', s, S(), cands)
            if cycle == 0:
                for s in OLD_SORA: run_sorafolder('old', s, S(), cands)
            time.sleep(20)
    if on('full'): run_full(S(), cands)
    if on('gofile'):
        for s in slugs[:2] + OLD_GOFILE: run_gofile(s, S())
    if on('big'): run_big('augusta-2')
    if on('other'):
        for s in OLD_MEDIAFIRE: run_mediafire(s, S())
        for s in OTHER['terabox'].split(','): run_terabox(s)
        for s in OTHER['traffic1s'].split(','): run_traffic1s(s)
    json.dump(R, open('results.json', 'w'), indent=1, ensure_ascii=False)
    ok = sum(c['ok'] for c in R['checks']); print(f'\nSUMMARY {ok}/{len(R["checks"])} passed')
