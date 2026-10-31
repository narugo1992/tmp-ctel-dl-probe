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


def main():
    t0 = time.time()
    for url in ('https://api.ipify.org?format=json', 'https://ipinfo.io/json'):
        try:
            r = requests.get(url, timeout=20)
            R['env'][url] = snippet(r.text, 300)
            log('ENV', url, snippet(r.text, 300))
        except Exception as err:
            log('ENV-ERR', url, err)
    for name, fn in (('mediafire', probe_mediafire), ('gofile', probe_gofile)):
        if name in os.environ.get('SECTIONS', 'mediafire,gofile'):
            try:
                fn()
            except Exception:
                log('SECTION-ERR', name, traceback.format_exc()[-500:])
    R['elapsed_s'] = round(time.time() - t0)
    json.dump(R, open('diag_results.json', 'w'), ensure_ascii=False, indent=1)
    log('DONE', R['elapsed_s'])


main()
