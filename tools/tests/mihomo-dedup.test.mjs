import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFromRequest } from '../../src/build.js';

const opts = { addTun: false, addSocks: true, webUI: false, mihomoSubscriptionMode: false };
const UUID = '00000000-0000-4000-8000-000000000001';
const base = 'vless://' + UUID + '@192.0.2.3:443?encryption=none';

function build(lines) {
  return buildFromRequest({ core: 'mihomo', input: lines.join('\n'), options: opts }).data;
}

function vlessCount(yaml) {
  return (yaml.match(/^\s*type: vless$/gm) || []).length;
}

test('exact semantic duplicates still collapse even with different names', () => {
  const yaml = build([
    base + '&security=tls&type=ws&path=%2Fsame#A',
    base + '&security=tls&type=ws&path=%2Fsame#B',
  ]);
  assert.equal(vlessCount(yaml), 1);
});

const cases = [
  ['WS path',
    '&security=tls&type=ws&path=%2Fa',
    '&security=tls&type=ws&path=%2Fb',
    'path: "/a"', 'path: "/b"'],
  ['WS Host header',
    '&security=tls&type=ws&path=%2F&host=a.example',
    '&security=tls&type=ws&path=%2F&host=b.example',
    'Host: a.example', 'Host: b.example'],
  ['gRPC service name',
    '&security=tls&type=grpc&serviceName=svc-a',
    '&security=tls&type=grpc&serviceName=svc-b',
    'grpc-service-name: "svc-a"', 'grpc-service-name: "svc-b"'],
  ['HTTP path',
    '&security=tls&type=h2&path=%2Fa&host=cdn.example',
    '&security=tls&type=h2&path=%2Fb&host=cdn.example',
    '- "/a"', '- "/b"'],
  ['SNI',
    '&security=tls&type=tcp&sni=a.example',
    '&security=tls&type=tcp&sni=b.example',
    'servername: a.example', 'servername: b.example'],
  ['Reality public key',
    '&security=reality&type=tcp&sni=example.com&pbk=KEYA&sid=aa&fp=chrome',
    '&security=reality&type=tcp&sni=example.com&pbk=KEYB&sid=aa&fp=chrome',
    'public-key: KEYA', 'public-key: KEYB'],
  ['Reality short id',
    '&security=reality&type=tcp&sni=example.com&pbk=KEY&sid=aa&fp=chrome',
    '&security=reality&type=tcp&sni=example.com&pbk=KEY&sid=bb&fp=chrome',
    'short-id: aa', 'short-id: bb'],
  ['fingerprint',
    '&security=tls&type=tcp&sni=example.com&fp=chrome',
    '&security=tls&type=tcp&sni=example.com&fp=firefox',
    'client-fingerprint: chrome', 'client-fingerprint: firefox'],
  ['ALPN',
    '&security=tls&type=tcp&sni=example.com&alpn=h2',
    '&security=tls&type=tcp&sni=example.com&alpn=http%2F1.1',
    '- h2', '- "http/1.1"'],
  ['network',
    '&security=tls&type=ws&path=%2F',
    '&security=tls&type=grpc&serviceName=svc',
    'network: ws', 'network: grpc'],
];

for (const item of cases) {
  const label = item[0];
  const left = item[1];
  const right = item[2];
  const expectedA = item[3];
  const expectedB = item[4];
  test('dedup preserves proxies that differ by ' + label, () => {
    const yaml = build([base + left + '#A', base + right + '#B']);
    assert.equal(vlessCount(yaml), 2, yaml);
    assert.ok(yaml.includes(expectedA), label + ' A');
    assert.ok(yaml.includes(expectedB), label + ' B');
  });
}
