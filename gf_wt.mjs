import fs from 'node:fs'; import vm from 'node:vm';
const [,, accountToken, ua] = process.argv;
const ctx = { console, performance, Date, Math, TextEncoder, TextDecoder, crypto: globalThis.crypto, setTimeout, clearTimeout, btoa, atob,
  navigator: { userAgent: ua, language: 'en-US', languages: ['en-US', 'en'], platform: 'Linux x86_64' },
  location: { href: 'https://gofile.io/', origin: 'https://gofile.io', hostname: 'gofile.io' }, document: { cookie: '', createElement: () => ({}) },
  localStorage: { getItem: () => null, setItem() {} }, screen: { width: 1920, height: 1080 } };
ctx.window = ctx; ctx.self = ctx; ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync('wt.obf.js', 'utf8'), ctx);
console.log(typeof ctx.generateWT === 'function' ? await ctx.generateWT(accountToken) : 'NO_GENERATOR keys=' + Object.keys(ctx).join(','));
