import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../../workers/subscription/index.js';

// All domains and HWIDs below are fake. Tests must never make real fetches.
const ORIGIN='https://subscription.example.invalid';
const URL0=ORIGIN+'/feed';
const OTHER='https://another.example.invalid/seen';
const H='11111111111111111111111111111111';
const POLICY='strict-same-origin-v1';
function req(body){return new Request('https://sub.example.invalid/',{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});}
function strict(url=URL0){return req({url,headers:{'x-hwid':H,'x-device-model':'Test fixture'},
  strictDeviceHeaders:true});}
async function withMock(t,mock,fn){
  const original=globalThis.fetch;
  const calls=[];
  globalThis.fetch=async(url,opts)=>{
    const value={url:String(url),headers:new Headers(opts?.headers||{}),opts};
    calls.push(value);
    return mock(value,calls.length);
  };
  t.after(()=>{globalThis.fetch=original});
  return await fn(calls);
}
test('policy discovery is safe without fetching an upstream or receiving identity',async t=>{
  await withMock(t,()=>{throw Error('upstream fetch unexpectedly called')},async calls=>{
    const result=await worker.fetch(new Request('https://sub.example.invalid/.well-known/subscription-policy-v1'));
    assert.equal(result.status,200);
    assert.equal(result.headers.get('X-Saymer-Device-Header-Policy'),POLICY);
    assert.equal(result.headers.get('Access-Control-Expose-Headers'),'X-Saymer-Device-Header-Policy');
    assert.equal(result.headers.get('Cache-Control'),'no-store');
    assert.equal(await result.text(),POLICY);
    assert.equal(calls.length,0);
  });
});
test('strict same-origin relative redirect preserves identity and returns policy proof',async t=>{
  await withMock(t,(r,n)=>{
    assert.equal(r.headers.get('x-hwid'),H);
    assert.equal(r.opts.redirect,'manual');
    if(n===1)return new Response(null,{status:302,headers:{Location:'/next?token=synthetic'}});
    return new Response('ok',{status:200});
  },async calls=>{
    const result=await worker.fetch(strict());
    assert.equal(result.status,200);
    assert.equal(await result.text(),'ok');
    assert.equal(result.headers.get('X-Saymer-Device-Header-Policy'),POLICY);
    assert.deepEqual(calls.map(c=>c.url),[URL0,ORIGIN+'/next?token=synthetic']);
  });
});
test('strict cross-origin redirect stops BEFORE identity can reach another host',async t=>{
  await withMock(t,()=>new Response(null,{status:302,headers:{Location:OTHER}}),async calls=>{
    const result=await worker.fetch(strict());
    assert.equal(result.status,502);
    assert.equal(calls.length,1);
    assert.equal(calls[0].url,URL0);
    assert.equal(calls[0].headers.get('x-hwid'),H);
    const error=await result.text();
    assert.match(error,/Cross-origin redirect rejected/);
    assert.equal(error.includes(OTHER),false);
    assert.equal(error.includes(H),false);
  });
});
test('strict http-to-https scheme upgrade is also an origin change',async t=>{
  await withMock(t,()=>new Response(null,{status:302,
    headers:{Location:'http://subscription.example.invalid/unencrypted'}}),async calls=>{
    const result=await worker.fetch(strict());
    assert.equal(result.status,502);
    assert.equal(calls.length,1);
  });
});
test('strict domain comparison ignores pathname but includes explicit ports',async t=>{
  await withMock(t,()=>new Response(null,{status:302,
    headers:{Location:'https://subscription.example.invalid:4443/feed'}}),async calls=>{
    const result=await worker.fetch(strict());
    assert.equal(result.status,502);
    assert.equal(calls.length,1);
  });
});
test('strict blocks malformed/non-http scheme redirects without a second fetch',async t=>{
  for (const location of ['file:///etc/passwd','http://[unmatched','javascript:alert(1)']) {
    await withMock(t,()=>new Response(null,{status:302,headers:{Location:location}}),async calls=>{
      const result=await worker.fetch(strict());
      assert.equal(result.status,502);
      assert.equal(calls.length,1);
      const error=await result.text();
      assert.equal(error.includes(H),false);
      assert.equal(error.includes(location),false);
    });
  }
});
test('strict request without valid x-hwid fails BEFORE any external fetch',async t=>{
  await withMock(t,()=>{throw Error('must not fetch')},async calls=>{
    const result=await worker.fetch(req({url:URL0,headers:{'x-hwid':'abc\r\ninjected:yes'},strictDeviceHeaders:true}));
    assert.equal(result.status,400);
    assert.equal(calls.length,0);
    assert.equal((await result.text()).includes(H),false);
  });
});
test('legacy POST behavior remains unchanged until separate policy review',async t=>{
  await withMock(t,(call,n)=>{
    if(n===1)return new Response(null,{status:302,headers:{Location:OTHER}});
    return new Response('legacy',{status:200});
  },async calls=>{
    const res=await worker.fetch(req({url:URL0,headers:{'x-hwid':H}}));
    assert.equal(res.status,200);
    assert.equal(await res.text(),'legacy');
    assert.equal(calls.length,2);
    assert.equal(calls[1].url,OTHER);
    assert.equal(calls[1].headers.get('x-hwid'),H);
    assert.equal(res.headers.has('X-Saymer-Device-Header-Policy'),false);
  });
});
