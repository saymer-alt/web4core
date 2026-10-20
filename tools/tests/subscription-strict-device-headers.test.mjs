import test from 'node:test';
import assert from 'node:assert/strict';
import {fetchSubscription} from '../../src/core/subscription.js';

// Strict portable-preview contract: synthetic-only. Never inspect real subscriptions.
const url = 'https://subscription.example.invalid/feed';
const hwid = '11111111111111111111111111111111';
const response = () => new Response(
  'vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?type=tcp#fixture',
  {status:200, headers:{'content-type':'text/plain'}}
);
function mockBrowser(t, handler) {
  const original = {fetch:globalThis.fetch,window:globalThis.window};
  const calls = [];
  globalThis.window = {document:{}};
  globalThis.fetch = async (target,opts) => {
    calls.push({target:String(target),method:opts?.method||'GET',
      headers:new Headers(opts?.headers || {}) ,body:opts?.body});
    return handler(String(target),opts||{});
  };
  t.after(()=>{
    globalThis.fetch=original.fetch;
    if (original.window===undefined) delete globalThis.window;
    else globalThis.window=original.window;
  });
  return calls;
}
test('strict support is an explicitly discoverable function capability',()=>{
  assert.equal(fetchSubscription.supportsStrictDeviceHeaders,true);
  assert.equal(fetchSubscription.supportsStrictOriginPolicy,true);
});
test('missing x-hwid in strict mode fails before any network',async t=>{
  const calls=mockBrowser(t,()=>{throw new Error('unexpected fetch')});
  await assert.rejects(fetchSubscription(url,{requireDeviceHeaders:true}),/requires x-hwid/);
  assert.equal(calls.length,0);
});
test('strict preview refuses no-header GET fallback when Worker POST cannot carry identity',async t=>{
  const calls=mockBrowser(t,(target,opts)=>{
    if(target===url)return new Response('',{status:404});
    if(target.endsWith('/.well-known/subscription-policy-v1'))
      return new Response('strict-same-origin-v1',{status:200,
        headers:{'X-Saymer-Device-Header-Policy':'strict-same-origin-v1'}});
    if(opts.method==='POST')return new Response('',{status:405,
      headers:{'X-Saymer-Device-Header-Policy':'strict-same-origin-v1'}});
    if(opts.method==='GET')return response(); // deliberately tempting anonymous success
    throw new Error('unexpected');
  });
  let error='';
  try {await fetchSubscription(url,{headers:{'x-hwid':hwid,'x-device-model':'Fixture'},requireDeviceHeaders:true});}
  catch(e){error=e.message;}
  assert.ok(error,'strict should reject the anonymous-success scenario');
  assert.ok(!error.includes(hwid)&&!error.includes(url),'errors must be secret-free');
  assert.ok(calls.some(c=>c.method==='POST'),'strict attempts authenticated Worker POST');
  assert.ok(!calls.some(c=>c.target.includes('?url=') && c.method==='GET'),'strict NEVER does anonymous fallback');
  const probe=calls.find(c=>c.target.endsWith('/.well-known/subscription-policy-v1'));
  assert.ok(probe,'unauthenticated worker capability checked before POST');
  assert.equal(probe.headers.has('x-hwid'),false);
  assert.equal(probe.target.includes(url),false);
  assert.equal(calls.indexOf(probe)<calls.findIndex(c=>c.method==='POST'),true);
  const post=calls.find(c=>c.method==='POST');
  const json=JSON.parse(post.body);
  assert.equal(json.url,url);
  assert.deepEqual(json.headers,{'x-hwid':hwid,'x-device-model':'Fixture'});
  assert.equal(json.strictDeviceHeaders,true);
});
test('legacy preview keeps existing GET fallback compatibility when opt-in absent',async t=>{
  const calls=mockBrowser(t,(target,opts)=>{
    if(target===url)return new Response('',{status:404});
    if(opts.method==='POST')return new Response('',{status:405});
    if(opts.method==='GET')return response();
    throw new Error('unexpected');
  });
  const result=await fetchSubscription(url,{headers:{'x-hwid':hwid}});
  assert.match(result,/^vless:\/\//);
  assert.ok(calls.some(c=>c.target!==url&&c.method==='GET'),'legacy GET retained');
  const fallback=calls.find(c=>c.target!==url&&c.method==='GET');
  assert.equal(fallback.headers.has('x-hwid'),false,'anonymous fallback preserves legacy contract');
});
test('direct source accepts strict x-hwid without worker or unexpected extra headers',async t=>{
  const calls=mockBrowser(t,()=>response());
  const result=await fetchSubscription(url,{headers:{'x-hwid':hwid,'x-device-model':'Fixture','authorization':'forbidden'},requireDeviceHeaders:true});
  assert.match(result,/^vless:\/\//);
  assert.equal(calls.length,1);
  assert.equal(calls[0].target,url);
  assert.equal(calls[0].headers.get('x-hwid'),hwid);
  assert.equal(calls[0].headers.get('x-device-model'),'Fixture');
  assert.equal(calls[0].headers.has('authorization'),false);
  assert.equal(calls[0].method,'GET');
});

test('strict CORS fallback never sends URL/HWID to old Worker lacking capability',async t=>{
  const calls=mockBrowser(t,(target)=>{
    if(target===url)return new Response('',{status:404});
    if(target.endsWith('/.well-known/subscription-policy-v1'))
      return new Response('Add ?url=URL',{status:400}); // old Worker
    throw new Error('strict POST must never happen');
  });
  await assert.rejects(fetchSubscription(url,{headers:{'x-hwid':hwid},
    requireDeviceHeaders:true}));
  assert.ok(calls.some(c=>c.target.endsWith('/.well-known/subscription-policy-v1')));
  assert.ok(!calls.some(c=>c.method==='POST'));
  assert.ok(!calls.some(c=>c.target.includes('?url=')));
  assert.ok(!calls.some(c=>c.target!==url&&c.target.includes(hwid)));
});
test('strict worker capability must not redirect to another URL',async t=>{
  const calls=mockBrowser(t,(target)=>{
    if(target===url)return new Response('',{status:404});
    return new Response(null,{status:302,headers:{Location:'https://other.example.invalid'}});
  });
  await assert.rejects(fetchSubscription(url,{headers:{'x-hwid':hwid},
    requireDeviceHeaders:true}));
  assert.ok(!calls.some(c=>c.method==='POST'));
});
test('strict browser direct request uses manual redirects, refusing automatic cross-origin forwarding',async t=>{
  const calls=mockBrowser(t,(target)=>{
    if(target===url)return new Response(null,{status:302,
      headers:{Location:'https://other.example.invalid/secret'}});
    return new Response('',{status:400});
  });
  await assert.rejects(fetchSubscription(url,{headers:{'x-hwid':hwid},
    requireDeviceHeaders:true}));
  assert.equal(calls[0].target,url);
  // Browser sees only opaqueredirect, but the crucial property is no fetch.follow
  assert.equal(calls[0].headers.get('x-hwid'),hwid);
  assert.ok(!calls.some(c=>c.target.startsWith('https://other.example.invalid')));
});
test('strict follow-on URL in body cannot transfer identity to a second origin',async t=>{
  const calls=mockBrowser(t,()=>new Response('https://other.example.invalid/secret',{status:200}));
  await assert.rejects(fetchSubscription(url,{headers:{'x-hwid':hwid},
    requireDeviceHeaders:true}),/origin changed/);
  assert.equal(calls.length,1);
});
test('strict verified Worker POST success preserves identity and policy evidence',async t=>{
  const calls=mockBrowser(t,(target,opts)=>{
    if(target===url)return new Response('',{status:404});
    if(target.endsWith('/.well-known/subscription-policy-v1'))
      return new Response('strict-same-origin-v1',{status:200,
        headers:{'X-Saymer-Device-Header-Policy':'strict-same-origin-v1'}});
    if(opts.method==='POST')return responseWithProof();
    throw new Error('unexpected fallback');
  });
  const responseWithProof=()=>new Response(
    'vless://00000000-0000-4000-8000-000000000001@192.0.2.10:443?type=tcp#fixture',
    {status:200,headers:{'X-Saymer-Device-Header-Policy':'strict-same-origin-v1'}});
  const result=await fetchSubscription(url,{headers:{'x-hwid':hwid},requireDeviceHeaders:true});
  assert.match(result,/^vless:\/\//);
  const posts=calls.filter(c=>c.method==='POST');
  assert.equal(posts.length,1);
  assert.equal(JSON.parse(posts[0].body).strictDeviceHeaders,true);
});
test('strict Worker must also return response policy proof; do not trust capability alone',async t=>{
  const calls=mockBrowser(t,(target,opts)=>{
    if(target===url)return new Response('',{status:404});
    if(target.endsWith('/.well-known/subscription-policy-v1'))
      return new Response('ok',{status:200,
        headers:{'X-Saymer-Device-Header-Policy':'strict-same-origin-v1'}});
    if(opts.method==='POST')return response(); // malicious/stale middle hop omits proof
    throw new Error('unexpected');
  });
  await assert.rejects(fetchSubscription(url,{headers:{'x-hwid':hwid},
    requireDeviceHeaders:true}));
  assert.equal(calls.filter(c=>c.method==='POST').length,1);
});
