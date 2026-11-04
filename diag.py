"""Temporary CI diagnosis of why mediafire and gofile turn the asiaon storage job away on a runner.

Read-only: pages and the first kilobyte of files, plus one capped speed sample. Nothing is kept.
"""
import collections
import json
import os
import re
import sys
import time
import traceback

import cloudscraper
import requests
from curl_cffi import requests as cffi
from curl_cffi.requests import BrowserType

sys.path.insert(0, os.getcwd())
from inf.asiaon.hosts import gofile  # noqa: E402
from inf.asiaon.hosts.mediafire import extract_download_link  # noqa: E402

T = json.load(open('diag_targets.json'))
R = {'env': {}, 'mf': [], 'gf': []}
CHROME_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
             'Chrome/131.0.0.0 Safari/537.36')
N_MF = int(os.environ.get('N_MF', '6'))
N_GF = int(os.environ.get('N_GF', '6'))


def log(*a):
    print(*a, flush=True)


def snippet(text, n=160):
    return re.sub(r'\s+', ' ', text or '')[:n]


def title(text):
    m = re.search(r'<title>(.*?)</title>', text or '', re.S | re.I)
    return snippet(m.group(1), 60) if m else None


def cffi_names():
    names = [b.value if hasattr(b, 'value') else str(b) for b in BrowserType]
    pick = []
    for fam in ('chrome', 'safari', 'firefox', 'edge'):
        fam_names = sorted((n for n in names if n.startswith(fam) and 'android' not in n and 'ios' not in n
                            and 'tor' not in n), key=lambda n: [int(x) if x.isdigit() else 0
                                                                  for x in re.split(r'\D+', n)])
        pick += fam_names[-2:]
    return pick


class Stack:
    """One way of making requests: ``get(url, **kw)`` and ``post(url, **kw)`` with a shared cookie jar."""

    def __init__(self, name):
        self.name = name
        kind, _, arg = name.partition(':')
        if kind == 'requests':
            self.s = requests.Session()
            self.s.headers['User-Agent'] = CHROME_UA
        elif kind == 'cloudscraper':
            plat, _, brow = arg.partition('/')
            if arg == 'default':
                self.s = cloudscraper.create_scraper()
            else:
                self.s = cloudscraper.create_scraper(browser={'browser': brow, 'platform': plat, 'desktop': True})
        elif kind == 'cffi':
            self.s = cffi.Session(impersonate=arg)
        else:
            raise ValueError(name)

    def get(self, url, **kw):
        return self.s.get(url, timeout=40, **kw)

    def post(self, url, **kw):
        return self.s.post(url, timeout=40, **kw)


def mf_stacks():
    out = ['requests:ua', 'cloudscraper:default', 'cloudscraper:windows/chrome', 'cloudscraper:linux/firefox']
    return out + [f'cffi:{n}' for n in cffi_names()]


# ---------------------------------------------------------------- mediafire
def probe_mediafire():
    urls = T['mediafire'][:N_MF]
    for sname in mf_stacks():
        ok = 0
        for url in urls:
            rec = {'stack': sname, 'url': url[:70]}
            try:
                st = Stack(sname)
                r = st.get(url)
                rec.update(http=r.status_code, server=r.headers.get('server'), mitig=r.headers.get('cf-mitigated'),
                           title=title(r.text), button='downloadButton' in r.text,
                           challenge='Just a moment' in r.text or 'challenge-platform' in r.text)
                if rec['button']:
                    ok += 1
                    direct = extract_download_link(r.text)
                    rec['direct'] = re.sub(r'^(https?://[^/]+).*', r'\1', direct or '')
                    if direct:
                        d = st.get(direct, headers={'Range': 'bytes=0-1023'}, stream=True)
                        rec.update(dl_http=d.status_code, dl_ctype=d.headers.get('content-type', '')[:30],
                                   dl_len=len(d.content[:2048]))
            except Exception as err:
                rec['err'] = f'{type(err).__name__}: {snippet(str(err), 100)}'
            R['mf'].append(rec)
            log('MF', json.dumps(rec, ensure_ascii=False))
        log(f'MF-SUMMARY {sname}: {ok}/{len(urls)} pages with a download button')
    # the official API, which is not behind the same challenge
    for url in urls[:3]:
        key = re.search(r'/file/([a-z0-9]+)', url)
        if not key:
            continue
        for sname in ('requests:ua', 'cffi:' + cffi_names()[0]):
            rec = {'api': 'get_info', 'stack': sname, 'key': key.group(1)}
            try:
                r = Stack(sname).get(f'https://www.mediafire.com/api/1.5/file/get_info.php?quick_key={key.group(1)}'
                                     f'&response_format=json')
                rec.update(http=r.status_code, body=snippet(r.text, 260))
            except Exception as err:
                rec['err'] = f'{type(err).__name__}: {snippet(str(err), 100)}'
            R['mf'].append(rec)
            log('MF-API', json.dumps(rec, ensure_ascii=False))


# ------------------------------------------------------------------- gofile
def gf_headers(token, wt):
    return {'Authorization': f'Bearer {token}', 'X-Website-Token': wt, 'X-BL': 'en-US'}


def probe_gofile():
    urls = T['gofile'][:N_GF]
    wt_cache = {}
    sample_done = False
    for sname in ('requests:ua', 'cloudscraper:windows/chrome', 'cffi:' + cffi_names()[0]):
        for idx, url in enumerate(urls):
            ident = re.search(r'gofile\.io/d/([\w-]+)', url).group(1)
            rec = {'stack': sname, 'folder': ident}
            try:
                st = Stack(sname)
                acct = st.post('https://api.gofile.io/accounts')
                rec['acct_http'] = acct.status_code
                token = acct.json()['data']['token']
                if token not in wt_cache:
                    wt_cache[token] = gofile.compute_wt(token, requests.Session())
                wt = wt_cache[token]
                c = st.get(f'https://api.gofile.io/contents/{ident}', headers=gf_headers(token, wt))
                rec.update(contents_http=c.status_code)
                if c.status_code != 200:
                    rec['contents_body'] = snippet(c.text, 200)
                    R['gf'].append(rec)
                    log('GF', json.dumps(rec, ensure_ascii=False))
                    continue
                data = c.json()['data']
                files = [x for x in (data.get('children') or {}).values() if x.get('type') == 'file']
                rec.update(files=len(files), names=[f.get('name', '')[:30] for f in files[:3]])
                if not files:
                    R['gf'].append(rec)
                    log('GF', json.dumps(rec, ensure_ascii=False))
                    continue
                link = files[0]['link']
                rec['link_host'] = re.sub(r'^(https?://[^/]+).*', r'\1', link)
                variants = {
                    'bearer+cookie': dict(headers={'Authorization': f'Bearer {token}'}, cookies={'accountToken': token}),
                    'cookie-only': dict(headers={}, cookies={'accountToken': token}),
                    'bearer-only': dict(headers={'Authorization': f'Bearer {token}'}, cookies={}),
                    'bearer+cookie+referer': dict(headers={'Authorization': f'Bearer {token}',
                                                           'Referer': 'https://gofile.io/'},
                                                  cookies={'accountToken': token}),
                    'none': dict(headers={}, cookies={}),
                }
                res = {}
                for vname, v in variants.items():
                    try:
                        sub = Stack(sname)
                        for k, val in v['cookies'].items():
                            sub.s.cookies.set(k, val, domain='.gofile.io')
                        d = sub.get(link, headers={**v['headers'], 'Range': 'bytes=0-1023'}, stream=True)
                        body = d.content[:300]
                        res[vname] = {'http': d.status_code, 'ctype': d.headers.get('content-type', '')[:30],
                                      'server': d.headers.get('server'),
                                      'body': snippet(body.decode('utf-8', 'replace'), 120) if d.status_code >= 400
                                      else f'{len(body)} bytes'}
                    except Exception as err:
                        res[vname] = {'err': f'{type(err).__name__}: {snippet(str(err), 80)}'}
                rec['file'] = res
                if not sample_done and res.get('bearer+cookie', {}).get('http') in (200, 206):
                    # a speed sample: up to 24 MB of the file, with the working header set
                    t0, got = time.time(), 0
                    d = Stack(sname)
                    d.s.cookies.set('accountToken', token, domain='.gofile.io')
                    resp = d.get(link, headers={'Authorization': f'Bearer {token}'}, stream=True)
                    for chunk in resp.iter_content(1 << 20):
                        got += len(chunk)
                        if got >= 24 << 20:
                            break
                    rec['speed_mb_s'] = round(got / (time.time() - t0) / 1e6, 2)
                    sample_done = True
            except Exception as err:
                rec['err'] = f'{type(err).__name__}: {snippet(str(err), 120)}'
            R['gf'].append(rec)
            log('GF', json.dumps(rec, ensure_ascii=False))
        log(f'GF-DONE {sname}')


# ------------------------------------------------- mediafire, as the job asks
def probe_mediafire_job():
    """The job's own session and page request, one after another and then in parallel, to see when 403 begins."""
    from concurrent.futures import ThreadPoolExecutor
    from inf.asiaon.hosts.base import get, get_download_session
    urls = T['mediafire']

    def one(i):
        t0 = time.time()
        try:
            r = get(get_download_session(), urls[i % len(urls)])
            return {'i': i, 'http': r.status_code, 'button': 'downloadButton' in r.text, 's': round(time.time() - t0, 1),
                    'mitig': r.headers.get('cf-mitigated')}
        except Exception as err:
            return {'i': i, 'err': f'{type(err).__name__}: {snippet(str(err), 80)}', 's': round(time.time() - t0, 1)}

    seq = []
    for i in range(40):
        seq.append(one(i))
        time.sleep(0.5)
    log('MFJOB-SEQ', json.dumps([(r['i'], r.get('http'), r.get('button')) for r in seq]))
    with ThreadPoolExecutor(8) as pool:
        par = list(pool.map(one, range(40, 120)))
    log('MFJOB-PAR8', json.dumps([(r['i'], r.get('http'), r.get('button')) for r in par]))
    for name, rows in (('seq', seq), ('par8', par)):
        bad = [r['i'] for r in rows if not r.get('button')]
        R['mf'].append({'job': name, 'requests': len(rows), 'without_button': len(bad), 'first_bad': bad[:1]})
        log(f'MFJOB-SUMMARY {name}: {len(rows) - len(bad)}/{len(rows)} pages with a button, first bad at {bad[:3]}')


# ---------------------------------------------------------- gofile, as the job asks
def probe_gofile_job():
    """The job's own gofile calls: how fast guest accounts may be made, and how much one account may download."""
    from inf.asiaon.hosts.base import get_plain_session
    sess = get_plain_session()
    for delay in (0, 15, 45):
        time.sleep(delay)
        r = sess.post('https://api.gofile.io/accounts', timeout=30)
        hdr = {k: v for k, v in r.headers.items() if k.lower().startswith(('retry-after', 'x-ratelimit', 'cf-'))}
        rec = {'account_after_s': delay, 'http': r.status_code, 'hdr': hdr, 'body': snippet(r.text, 120)}
        R['gf'].append(rec)
        log('GFJOB-ACCT', json.dumps(rec))
        if r.status_code == 200:
            break
    token, wt = gofile._credentials(sess)
    log('GFJOB-CRED', 'token ok' if token else 'no token', 'wt ok' if wt else 'no wt')
    total, started = 0, time.time()
    for url in T['gofile']:
        ident = re.search(r'gofile\.io/d/([\w-]+)', url).group(1)
        rec = {'folder': ident}
        try:
            token, data = gofile._contents(sess, ident)
            files = [x for x in (data.get('children') or {}).values() if x.get('type') == 'file']
            rec['files'] = len(files)
            if not files:
                raise RuntimeError('no files')
            item = files[0]
            rec.update(name=item.get('name', '')[:30], size_mb=round((item.get('size') or 0) / 1e6))
            sess.cookies.set('accountToken', token, domain='.gofile.io')
            resp = sess.get(item['link'], headers={'Authorization': f'Bearer {token}'}, stream=True, timeout=60)
            rec['http'] = resp.status_code
            if resp.status_code != 200:
                rec['body'] = snippet(resp.text, 160)
                rec['hdr'] = {k: v for k, v in resp.headers.items() if k.lower().startswith(('retry-after', 'x-ratelimit', 'cf-', 'server'))}
            else:
                got, t0 = 0, time.time()
                for chunk in resp.iter_content(1 << 20):
                    got += len(chunk)
                    if got >= 1500 << 20:
                        break
                total += got
                rec.update(got_mb=round(got / 1e6), mb_s=round(got / (time.time() - t0) / 1e6, 1),
                           account_total_mb=round(total / 1e6))
        except Exception as err:
            rec['err'] = f'{type(err).__name__}: {snippet(str(err), 160)}'
        R['gf'].append(rec)
        log('GFJOB', json.dumps(rec, ensure_ascii=False))
        if total >= 9000 << 20 or time.time() - started > 1500:
            break


# ------------------------------------------- the mediafire pages that always answer 403
def probe_mediafire_bad():
    """Whether the pages that fail every time yield to another stack, and what a random sample looks like."""
    for url in T['mediafire_bad']:
        key = re.search(r'/file/([a-z0-9]+)', url).group(1)
        for sname in mf_stacks():
            rec = {'key': key, 'stack': sname}
            try:
                r = Stack(sname).get(url)
                rec.update(http=r.status_code, server=r.headers.get('server'), mitig=r.headers.get('cf-mitigated'),
                           title=title(r.text), button='downloadButton' in r.text, body=snippet(r.text, 140))
            except Exception as err:
                rec['err'] = f'{type(err).__name__}: {snippet(str(err), 100)}'
            R['mf'].append(rec)
            log('MFBAD', json.dumps(rec, ensure_ascii=False))
        try:
            r = requests.get(f'https://www.mediafire.com/api/1.5/file/get_info.php?quick_key={key}&response_format=json',
                             timeout=30)
            log('MFBAD-API', key, r.status_code, snippet(r.text, 400))
        except Exception as err:
            log('MFBAD-API-ERR', key, err)
    # a random sample, each page twice with a fresh session, to tell a per-page verdict from a random one
    import collections
    outcome = collections.Counter()
    for url in T['mediafire_rand']:
        codes = []
        for _ in range(2):
            try:
                codes.append(Stack('cffi:' + cffi_names()[0]).get(url).status_code)
            except Exception as err:
                codes.append(type(err).__name__)
        outcome[tuple(codes)] += 1
    log('MFBAD-SAMPLE', json.dumps({str(k): v for k, v in outcome.items()}))
    R['mf'].append({'sample_outcomes': {str(k): v for k, v in outcome.items()}})


# ------------------------------------------------- a random sample of gofile folders
def probe_gofile_sample():
    import collections
    from inf.asiaon.hosts.base import get_plain_session
    sess = get_plain_session()
    token, wt = gofile._credentials(sess)
    outcome, bodies = collections.Counter(), collections.Counter()
    for url in T['gofile_rand']:
        ident = re.search(r'gofile\.io/d/([\w-]+)', url).group(1)
        try:
            c = sess.get(f'https://api.gofile.io/contents/{ident}', timeout=30,
                         headers={'Authorization': f'Bearer {token}', 'X-Website-Token': wt, 'X-BL': 'en-US'})
            if c.status_code != 200:
                outcome[f'contents {c.status_code} {snippet(c.text, 60)}'] += 1
                continue
            data = c.json()['data']
            files = [x for x in (data.get('children') or {}).values() if x.get('type') == 'file']
            if not files:
                outcome['folder without files'] += 1
                continue
            sess.cookies.set('accountToken', token, domain='.gofile.io')
            d = sess.get(files[0]['link'], headers={'Authorization': f'Bearer {token}', 'Range': 'bytes=0-1023'},
                         stream=True, timeout=40)
            if d.status_code in (200, 206):
                outcome['file readable'] += 1
            else:
                outcome[f'file {d.status_code}'] += 1
                bodies[snippet(d.text, 90)] += 1
        except Exception as err:
            outcome[f'err {type(err).__name__}'] += 1
    log('GFSAMPLE', json.dumps(dict(outcome), ensure_ascii=False))
    log('GFSAMPLE-BODIES', json.dumps(dict(bodies), ensure_ascii=False))
    R['gf'].append({'sample_outcomes': dict(outcome), 'bodies': dict(bodies)})


# ------------------------------------- which mediafire fingerprint is the most dependable
def probe_mediafire_hard():
    import collections
    names = [b.value if hasattr(b, 'value') else str(b) for b in BrowserType]
    stacks = [f'cffi:{n}' for n in sorted(names) if n.startswith(('chrome', 'safari', 'edge', 'firefox'))
              and 'android' not in n and 'ios' not in n and 'tor' not in n]
    log('MFHARD-STACKS', json.dumps(stacks))
    urls = T['mediafire_bad']
    table = {}
    for sname in stacks:
        ok = total = 0
        for url in urls:
            for _ in range(4):
                total += 1
                try:
                    ok += 'downloadButton' in Stack(sname).get(url).text
                except Exception:
                    pass
        table[sname] = f'{ok}/{total}'
        log(f'MFHARD {sname}: {ok}/{total}')
    R['mf'].append({'hard_table': table})
    # the best stack on the age sample, one request each
    best = max(table, key=lambda k: int(table[k].split('/')[0]))
    by = collections.defaultdict(collections.Counter)
    for url, month in T['mediafire_age']:
        try:
            by[month]['ok' if 'downloadButton' in Stack(best).get(url).text else 'blocked'] += 1
        except Exception as err:
            by[month][type(err).__name__] += 1
    log('MFHARD-AGE', best, json.dumps({m: dict(c) for m, c in sorted(by.items())}))
    R['mf'].append({'age': {m: dict(c) for m, c in by.items()}, 'best': best})


# ------------------------------------------- gofile: is the content still there, by month
def probe_gofile_age():
    import collections
    from inf.asiaon.hosts.base import get_plain_session
    sess = get_plain_session()
    token, wt = gofile._credentials(sess)
    by = collections.defaultdict(collections.Counter)
    for url, month in T['gofile_age']:
        ident = re.search(r'gofile\.io/d/([\w-]+)', url).group(1)
        verdict = None
        for attempt in range(3):
            try:
                c = sess.get(f'https://api.gofile.io/contents/{ident}', timeout=30,
                             headers={'Authorization': f'Bearer {token}', 'X-Website-Token': wt, 'X-BL': 'en-US'})
                if c.status_code == 429:
                    time.sleep(25)
                    continue
                if c.status_code != 200:
                    verdict = f'contents {c.status_code}'
                    break
                files = [x for x in (c.json()['data'].get('children') or {}).values() if x.get('type') == 'file']
                if not files:
                    verdict = 'emptied'
                    break
                sess.cookies.set('accountToken', token, domain='.gofile.io')
                d = sess.get(files[0]['link'], headers={'Authorization': f'Bearer {token}', 'Range': 'bytes=0-1023'},
                             stream=True, timeout=40)
                if d.status_code in (200, 206):
                    verdict = 'readable'
                elif 'cold storage' in d.text:
                    verdict = 'cold storage'
                else:
                    verdict = f'file {d.status_code}'
                break
            except Exception as err:
                verdict = f'err {type(err).__name__}'
                break
        by[month][verdict or 'rate limited'] += 1
        time.sleep(2.5)
    log('GFAGE', json.dumps({m: dict(c) for m, c in sorted(by.items())}, ensure_ascii=False))
    R['gf'].append({'age': {m: dict(c) for m, c in by.items()}})


# ----------------------------- mediafire end to end with fresh-session retries over several fingerprints
ROTATION = ['chrome152', 'safari15_5', 'chrome151', 'safari17_0', 'chrome120', 'safari155', 'chrome136',
            'chrome119', 'safari170', 'chrome151_macos']


def page_with_retries(url, limit=12):
    """``(html, attempts, fingerprint)`` of the first attempt that carries a download button, else ``(None, n, None)``."""
    for attempt in range(1, limit + 1):
        name = ROTATION[(attempt - 1) % len(ROTATION)]
        try:
            r = cffi.Session(impersonate=name).get(url, timeout=40)
            if 'downloadButton' in r.text:
                return r.text, attempt, name
        except Exception:
            pass
        time.sleep(1)
    return None, limit, None


def probe_mediafire_dl():
    import collections
    urls = T['mediafire_bad'] + [u for u, _ in T['mediafire_age'][:10]]
    attempts = collections.Counter()
    speeds = []
    for url in urls:
        t0 = time.time()
        html, n, fp = page_with_retries(url)
        rec = {'url': url[:60], 'attempts': n, 'fingerprint': fp, 'page_s': round(time.time() - t0, 1)}
        if html:
            direct = extract_download_link(html)
            rec['direct_host'] = re.sub(r'^(https?://[^/]+).*', r'\1', direct or '')
            try:
                t1, got = time.time(), 0
                r = requests.get(direct, stream=True, timeout=60, headers={'User-Agent': CHROME_UA})
                rec['dl_http'] = r.status_code
                if r.status_code == 200:
                    for chunk in r.iter_content(1 << 20):
                        got += len(chunk)
                        if got >= 300 << 20:
                            break
                    rec.update(dl_mb=round(got / 1e6), dl_mb_s=round(got / (time.time() - t1) / 1e6, 1))
                    speeds.append(rec['dl_mb_s'])
            except Exception as err:
                rec['dl_err'] = f'{type(err).__name__}: {snippet(str(err), 80)}'
        attempts[n if html else 'failed'] += 1
        R['mf'].append(rec)
        log('MFDL', json.dumps(rec, ensure_ascii=False))
    log('MFDL-ATTEMPTS', json.dumps({str(k): v for k, v in sorted(attempts.items(), key=str)}))
    log('MFDL-SPEEDS', json.dumps(speeds))


# ------------------------------------------------------------------ pixeldrain, one stream or many
PD_API = 'https://pixeldrain.com/api/file'


def pd_files(min_mb=700):
    out = []
    for url in T['pixeldrain']:
        m = re.search(r'pixeldrain\.com/u/([\w-]+)', url)
        if not m:
            continue
        try:
            info = requests.get(f'{PD_API}/{m.group(1)}/info', timeout=30).json()
            if info.get('success', True) and not info.get('availability') and (info.get('size') or 0) >= min_mb << 20:
                out.append((m.group(1), info['size']))
        except Exception:
            pass
    return sorted(out, key=lambda x: -x[1])


def pd_range(ident, start, end, hold=None, stop_after=None):
    """Bytes of ``[start, end]`` read; ``(got, seconds, http)``."""
    t0, got = time.time(), 0
    r = requests.get(f'{PD_API}/{ident}', headers={'Range': f'bytes={start}-{end}', 'User-Agent': CHROME_UA},
                     params={'download': ''}, stream=True, timeout=60)
    if r.status_code not in (200, 206):
        return 0, time.time() - t0, r.status_code
    for chunk in r.iter_content(1 << 20):
        got += len(chunk)
        if stop_after and time.time() - t0 > stop_after:
            break
    return got, time.time() - t0, r.status_code


def probe_pixeldrain():
    from concurrent.futures import ThreadPoolExecutor
    files = pd_files()
    log('PD-FILES', json.dumps([(i, round(sz / 1e6)) for i, sz in files]))
    if len(files) < 2:
        log('PD-NOFILES')
        return
    mb = 1 << 20
    # A: one stream, speed per 256 MB window
    ident, size = files[0]
    t0, got, win_t, win_b, rates = time.time(), 0, time.time(), 0, []
    r = requests.get(f'{PD_API}/{ident}', params={'download': ''}, stream=True, timeout=60,
                     headers={'User-Agent': CHROME_UA})
    log('PD-A-HTTP', r.status_code, {k: v for k, v in r.headers.items() if k.lower().startswith(('x-', 'cf-', 'retry'))})
    for chunk in r.iter_content(1 << 20):
        got += len(chunk); win_b += len(chunk)
        if win_b >= 256 * mb:
            rates.append(round(win_b / (time.time() - win_t) / 1e6, 1)); win_t, win_b = time.time(), 0
        if got >= 2500 * mb or time.time() - t0 > 150:
            break
    log('PD-A-SINGLE-WINDOWS-MB/s', json.dumps(rates), 'total_mb', round(got / 1e6))
    R['pd_single'] = rates
    # B: several ranges of another file at once
    ident, size = files[1]
    for n in (4, 8):
        span = 128 * mb
        t0 = time.time()
        with ThreadPoolExecutor(n) as pool:
            res = list(pool.map(lambda i: pd_range(ident, i * span, (i + 1) * span - 1), range(n)))
        tot = sum(g for g, _, _ in res)
        log(f'PD-B-{n}-THREADS', 'MB/s aggregate', round(tot / (time.time() - t0) / 1e6, 1),
            'http', sorted({h for _, _, h in res}), 'each MB/s', [round(g / max(s, 1e-6) / 1e6, 1) for g, s, _ in res])
    # C: is a new stream on another file still fast right after
    ident, size = files[min(2, len(files) - 1)]
    g, sec, h = pd_range(ident, 0, 400 * mb, stop_after=45)
    log('PD-C-NEWSTREAM', 'MB/s', round(g / max(sec, 1e-6) / 1e6, 1), 'http', h)
    # D: sustained, eight ranges at a time over a whole file, aggregate per 30 s
    ident, size = files[0]
    span, done, t_start, last, last_bytes, series = 64 * mb, 0, time.time(), time.time(), 0, []
    total = 0
    offsets = list(range(0, size, span))
    with ThreadPoolExecutor(8) as pool:
        futs = []
        for off in offsets:
            futs.append(pool.submit(pd_range, ident, off, min(off + span, size) - 1))
        for f in futs:
            g, _, _ = f.result()
            total += g
            if time.time() - last >= 30:
                series.append(round((total - last_bytes) / (time.time() - last) / 1e6, 1))
                last, last_bytes = time.time(), total
            if time.time() - t_start > 600 or total > 6000 * mb:
                for x in futs:
                    x.cancel()
                break
    log('PD-D-SUSTAINED-8T-MB/s-per-30s', json.dumps(series), 'total_mb', round(total / 1e6),
        'elapsed_s', round(time.time() - t_start))
    R['pd_sustained'] = series
    # E: after a rest, a single stream again
    time.sleep(300)
    g, sec, h = pd_range(files[-1][0], 0, 300 * mb, stop_after=30)
    log('PD-E-AFTER-REST', 'MB/s', round(g / max(sec, 1e-6) / 1e6, 1), 'http', h)


def probe_pixeldrain_heavy():
    """Push past the volume at which pixeldrain was seen to throttle, then see what threads change."""
    from concurrent.futures import ThreadPoolExecutor
    files = pd_files(min_mb=500)
    mb = 1 << 20
    total, throttled_at = 0, None
    for ident, size in files:
        t0, got, win_t, win_b, rates = time.time(), 0, time.time(), 0, []
        r = requests.get(f'{PD_API}/{ident}', params={'download': ''}, stream=True, timeout=60,
                         headers={'User-Agent': CHROME_UA})
        if r.status_code != 200:
            log('PD2-HTTP', ident, r.status_code, snippet(r.text, 200))
            continue
        for chunk in r.iter_content(1 << 20):
            got += len(chunk); win_b += len(chunk); total += len(chunk)
            if win_b >= 256 * mb:
                rate = win_b / (time.time() - win_t) / 1e6
                rates.append(round(rate, 1)); win_t, win_b = time.time(), 0
                if rate < 5 and throttled_at is None:
                    throttled_at = total
            if time.time() - t0 > 200:
                break
        log('PD2-FILE', ident, 'mb', round(got / 1e6), 'windows', json.dumps(rates), 'total_mb', round(total / 1e6))
    log('PD2-THROTTLED-AT-MB', None if throttled_at is None else round(throttled_at / 1e6))

    def probe_after(label):
        ident, size = files[-1]
        g, sec, h = pd_range(ident, 0, 300 * mb, stop_after=30)
        log(f'PD2-{label}-SINGLE', 'MB/s', round(g / max(sec, 1e-6) / 1e6, 2), 'http', h)
        span = 64 * mb
        t0 = time.time()
        with ThreadPoolExecutor(8) as pool:
            res = list(pool.map(lambda i: pd_range(ident, i * span, (i + 1) * span - 1, stop_after=30), range(8)))
        tot = sum(x[0] for x in res)
        log(f'PD2-{label}-8THREADS', 'MB/s aggregate', round(tot / (time.time() - t0) / 1e6, 2),
            'http', sorted({x[2] for x in res}))
        with ThreadPoolExecutor(16) as pool:
            t0 = time.time()
            res = list(pool.map(lambda i: pd_range(ident, i * 32 * mb, (i + 1) * 32 * mb - 1, stop_after=30), range(16)))
        log(f'PD2-{label}-16THREADS', 'MB/s aggregate', round(sum(x[0] for x in res) / (time.time() - t0) / 1e6, 2),
            'http', sorted({x[2] for x in res}))

    probe_after('NOW')
    time.sleep(600)
    probe_after('AFTER10MIN')


# ----------------------------------------- split archives: every volume, joined, then unpacked as the job does
def probe_split():
    import shutil, tempfile
    from inf.asiaon import storage as st
    for item in T['split']:
        work = tempfile.mkdtemp(prefix='split-')
        path = os.path.join(work, 'package.zip')
        expected = sum(p['size'] for p in item['parts'])
        t0, written, attempts = time.time(), 0, []
        ok = True
        with open(path, 'wb') as out:
            for part in item['parts']:
                url = f"https://www.mediafire.com/file/{part['key']}/file"
                html, n, fp = page_with_retries(url)
                attempts.append(n)
                if not html:
                    ok = False
                    log('SPLIT-PAGE-FAILED', part['key'])
                    break
                direct = extract_download_link(html)
                r = requests.get(direct, stream=True, timeout=60, headers={'User-Agent': CHROME_UA})
                disp = r.headers.get('Content-Disposition', '')[:90]
                got = 0
                for chunk in r.iter_content(1 << 20):
                    out.write(chunk)
                    got += len(chunk)
                written += got
                log('SPLIT-PART', part['key'], 'http', r.status_code, 'bytes', got, 'expected', part['size'], 'cd', disp)
                if got != part['size']:
                    ok = False
        dl_s = round(time.time() - t0)
        log('SPLIT-JOINED', item['id'][:40], 'bytes', written, 'expected', expected, 'ok', ok, 'page attempts', attempts,
            'download seconds', dl_s)
        with open(path, 'rb') as f:
            log('SPLIT-HEAD', f.read(8))
        unpack_dir = os.path.join(work, 'unpacked')
        os.makedirs(unpack_dir)
        t1 = time.time()
        try:
            n_files = st.unpack_package(path, unpack_dir, item['password'])
            total = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(unpack_dir) for f in fs)
            log('SPLIT-UNPACK', item['id'][:40], 'files', n_files, 'bytes', total, 'seconds', round(time.time() - t1))
            R['split_ok'] = R.get('split_ok', 0) + 1
        except Exception as err:
            log('SPLIT-UNPACK-FAILED', item['id'][:40], type(err).__name__, snippet(str(err), 300))
        shutil.rmtree(work, ignore_errors=True)


def probe_split_job():
    """The job's own split-archive route, on the real post pages, then its own unpack."""
    import shutil, tempfile
    from inf.asiaon import storage as st
    from inf.asiaon.hosts import mediafire as mf
    for item in T['splitjob']:
        work = tempfile.mkdtemp(prefix='splitjob-')
        t0 = time.time()
        try:
            path = mf.download_mediafire_post_volumes({'id': item['id']}, work)
            log('SPLITJOB-DOWNLOADED', item['id'][:40], os.path.basename(path), os.path.getsize(path), 'bytes',
                round(time.time() - t0), 's', 'left in dir', sorted(os.listdir(work)))
            unpack_dir = os.path.join(work, 'unpacked'); os.makedirs(unpack_dir)
            t1 = time.time()
            n = st.unpack_package(path, unpack_dir, 'asiaon.top')
            total = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(unpack_dir) for f in fs)
            log('SPLITJOB-UNPACKED', item['id'][:40], 'files', n, 'bytes', total, round(time.time() - t1), 's')
        except Exception as err:
            log('SPLITJOB-FAILED', item['id'][:40], type(err).__name__, snippet(str(err), 300), 'unusable',
                getattr(err, 'unusable', None), 'refused', getattr(err, 'refused', None))
        shutil.rmtree(work, ignore_errors=True)


def probe_zerochan():
    import hashlib
    sess = cffi.Session(impersonate='chrome131')

    def clear():
        r = sess.get('https://www.zerochan.net/1girl', timeout=30)
        m = re.search(r'<img\s+src="(/[^"]+)"', r.text)
        if m:
            sess.get('https://www.zerochan.net' + m.group(1), timeout=30)

    try:
        clear()
    except Exception as err:
        log('ZC-CLEAR-ERR', err)
    log('ZC-COOKIES', list(sess.cookies.keys()))
    for host in ('https://www.zerochan.net', 'https://zerochan.net'):
        for path in ('/', '/4733497', '/1girl', '/login'):
            try:
                r = sess.get(host + path, timeout=30, allow_redirects=True)
                if r.status_code == 503 and 'Checking browser' in r.text:
                    clear()
                    r = sess.get(host + path, timeout=30, allow_redirects=True)
                log('ZC-PAGE', host + path, r.status_code, len(r.text), r.headers.get('server'), snippet(r.text, 70))
            except Exception as err:
                log('ZC-PAGE-ERR', host + path, type(err).__name__, snippet(str(err), 80))
    ok = 0
    for item in T['zc_images']:
        try:
            r = requests.get(item['file_url'], timeout=60,
                             headers={'User-Agent': CHROME_UA, 'Referer': 'https://www.zerochan.net/'})
            match = r.status_code == 200 and hashlib.md5(r.content).hexdigest() == item['hash']
            ok += match
            log('ZC-IMG', item['id'], r.status_code, len(r.content), 'md5 match', match)
        except Exception as err:
            log('ZC-IMG-ERR', item['id'], type(err).__name__)
    log('ZC-IMG-SUMMARY', ok, 'of', len(T['zc_images']), 'downloaded with a matching md5')


def probe_danbooru_post():
    sess = cffi.Session(impersonate='chrome131')
    for pid in (11543719, 11543718, 11543717, 11543700):
        try:
            r = sess.get(f'https://danbooru.donmai.us/posts/{pid}.json', timeout=30)
            info = ''
            if r.status_code == 200:
                j = r.json()
                info = {k: j.get(k) for k in ('is_banned', 'is_deleted', 'is_pending', 'rating', 'file_ext', 'file_size',
                                              'uploader_id', 'created_at')}
                for key in ('file_url', 'large_file_url'):
                    url = j.get(key)
                    if not url:
                        info[key] = None
                        continue
                    h = sess.get(url, timeout=60, headers={'Referer': 'https://danbooru.donmai.us/'})
                    info[key] = (h.status_code, h.headers.get('content-type', '')[:20], len(h.content))
            else:
                info = snippet(r.text, 90)
            log('DBPOST', pid, r.status_code, info)
        except Exception as err:
            log('DBPOST-ERR', pid, type(err).__name__, snippet(str(err), 100))


def probe_gelbooru():
    import hashlib, statistics
    from concurrent.futures import ThreadPoolExecutor
    items = json.load(open('gb_sample.json'))
    log('GB-SAMPLE', len(items))
    H = {'User-Agent': CHROME_UA}

    # A: census - status and size of every sample image, without reading the body
    def head(it):
        t0 = time.time()
        try:
            r = requests.get(it['file_url'], headers=H, stream=True, timeout=40)
            out = (r.status_code, int(r.headers.get('Content-Length') or 0), r.headers.get('Content-Type', '')[:14],
                   round(time.time() - t0, 2))
            r.close()
            return out
        except Exception as err:
            return (type(err).__name__, 0, '', round(time.time() - t0, 2))
    with ThreadPoolExecutor(16) as pool:
        res = list(pool.map(head, items))
    codes = collections.Counter(str(x[0]) for x in res)
    sizes = [x[1] for x in res if x[0] == 200 and x[1]]
    log('GB-CENSUS-STATUS', dict(codes))
    if sizes:
        log('GB-CENSUS-SIZE', 'n', len(sizes), 'mean MB', round(statistics.mean(sizes) / 1e6, 2), 'median MB',
            round(statistics.median(sizes) / 1e6, 2), 'p90 MB', round(sorted(sizes)[int(len(sizes) * .9)] / 1e6, 2),
            'max MB', round(max(sizes) / 1e6, 1), 'sum MB', round(sum(sizes) / 1e6))
        by_mime = collections.defaultdict(list)
        for it, x in zip(items, res):
            if x[0] == 200 and x[1]:
                by_mime[it['mimetype']].append(x[1])
        log('GB-CENSUS-BY-MIME', {k: (len(v), round(statistics.mean(v) / 1e6, 2)) for k, v in by_mime.items()})
    # B: whole files with md5 against the index, 16 threads, throughput
    chosen = items[:40] + items[40:140]
    def whole(it):
        t0 = time.time()
        try:
            r = requests.get(it['file_url'], headers=H, timeout=90)
            ok = r.status_code == 200 and hashlib.md5(r.content).hexdigest() == it['md5']
            return (r.status_code, len(r.content), ok, time.time() - t0)
        except Exception as err:
            return (type(err).__name__, 0, False, time.time() - t0)
    t0 = time.time()
    with ThreadPoolExecutor(16) as pool:
        out = list(pool.map(whole, chosen))
    wall = time.time() - t0
    tot = sum(x[1] for x in out)
    log('GB-WHOLE', 'files', len(out), 'md5 ok', sum(x[2] for x in out), 'status', dict(collections.Counter(str(x[0]) for x in out)),
        'MB', round(tot / 1e6), 'wall s', round(wall, 1), 'MB/s', round(tot / 1e6 / wall, 1))
    bad = [(it['id'], x[0]) for it, x in zip(chosen, out) if not x[2]][:6]
    log('GB-WHOLE-BAD', bad)
    # C: how the site answers more threads
    for workers in (32,):
        more = items[140:300]
        t0 = time.time()
        with ThreadPoolExecutor(workers) as pool:
            out2 = list(pool.map(whole, more))
        wall = time.time() - t0
        log(f'GB-THREADS-{workers}', 'files', len(out2), 'md5 ok', sum(x[2] for x in out2), 'status',
            dict(collections.Counter(str(x[0]) for x in out2)), 'MB', round(sum(x[1] for x in out2) / 1e6),
            'MB/s', round(sum(x[1] for x in out2) / 1e6 / wall, 1))
    # D: another client stack for comparison
    def whole_cffi(it):
        try:
            r = cffi.Session(impersonate='chrome131').get(it['file_url'], timeout=90)
            return r.status_code == 200 and hashlib.md5(r.content).hexdigest() == it['md5']
        except Exception:
            return False
    with ThreadPoolExecutor(8) as pool:
        ok = list(pool.map(whole_cffi, items[:24]))
    log('GB-CFFI', sum(ok), 'of', len(ok), 'md5 ok')


def main():
    t0 = time.time()
    for url in ('https://api.ipify.org?format=json', 'https://ipinfo.io/json'):
        try:
            r = requests.get(url, timeout=20)
            R['env'][url] = snippet(r.text, 300)
            log('ENV', url, snippet(r.text, 300))
        except Exception as err:
            log('ENV-ERR', url, err)
    sections = os.environ.get('SECTIONS', 'gb').split(',')
    for name, fn in (('mediafire', probe_mediafire), ('gofile', probe_gofile), ('mfjob', probe_mediafire_job),
                     ('gfjob', probe_gofile_job), ('mfbad', probe_mediafire_bad), ('gfsample', probe_gofile_sample), ('mfhard', probe_mediafire_hard),
                     ('gfage', probe_gofile_age), ('mfdl', probe_mediafire_dl),
                     ('pd', probe_pixeldrain), ('pd2', probe_pixeldrain_heavy),
                     ('split', probe_split), ('splitjob', probe_split_job), ('zc', probe_zerochan), ('dbpost', probe_danbooru_post), ('gb', probe_gelbooru)):
        if name in sections:
            try:
                fn()
            except Exception:
                log('SECTION-ERR', name, traceback.format_exc()[-500:])
    R['elapsed_s'] = round(time.time() - t0)
    json.dump(R, open('diag_results.json', 'w'), ensure_ascii=False, indent=1)
    log('DONE', R['elapsed_s'])


main()
