"""Temporary CI diagnosis of why mediafire and gofile turn the asiaon storage job away on a runner.

Read-only: pages and the first kilobyte of files, plus one capped speed sample. Nothing is kept.
"""
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


def main():
    t0 = time.time()
    for url in ('https://api.ipify.org?format=json', 'https://ipinfo.io/json'):
        try:
            r = requests.get(url, timeout=20)
            R['env'][url] = snippet(r.text, 300)
            log('ENV', url, snippet(r.text, 300))
        except Exception as err:
            log('ENV-ERR', url, err)
    sections = os.environ.get('SECTIONS', 'mfdl').split(',')
    for name, fn in (('mediafire', probe_mediafire), ('gofile', probe_gofile), ('mfjob', probe_mediafire_job),
                     ('gfjob', probe_gofile_job), ('mfbad', probe_mediafire_bad), ('gfsample', probe_gofile_sample), ('mfhard', probe_mediafire_hard),
                     ('gfage', probe_gofile_age), ('mfdl', probe_mediafire_dl)):
        if name in sections:
            try:
                fn()
            except Exception:
                log('SECTION-ERR', name, traceback.format_exc()[-500:])
    R['elapsed_s'] = round(time.time() - t0)
    json.dump(R, open('diag_results.json', 'w'), ensure_ascii=False, indent=1)
    log('DONE', R['elapsed_s'])


main()
