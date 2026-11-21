// Development tool only (not part of the kit). Records WebAuthn fixtures; see README.md.
// Drives a real Firefox over WebDriver (geckodriver) with a WebDriver virtual authenticator to record WebAuthn responses.
import crypto from 'node:crypto'; import fs from 'node:fs';
const [,, label, transport, alg, outFile] = process.argv;
const W = 'http://127.0.0.1:4444';
const call = async (method, p, body) => { const r = await fetch(W + p, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }); const j = await r.json(); if (j.value && j.value.error) throw new Error(JSON.stringify(j.value)); return j.value; };
const sess = await call('POST', '/session', { capabilities: { alwaysMatch: { acceptInsecureCerts: true, 'moz:firefoxOptions': { prefs: {
  'network.proxy.type': 1, 'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': 8899, 'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': 8899, 'network.proxy.no_proxies_on': '', 'network.proxy.allow_hijacking_localhost': true, 'security.webauth.webauthn_enable_softtoken': true, 'security.webauth.webauthn_enable_usbtoken': false,
} } } } });
const sid = sess.sessionId; const S = `/session/${sid}`;
try {
  await call('POST', `${S}/url`, { url: 'https://example.com/' });
  console.log('loc', await call('POST', `${S}/execute/sync`, { script: 'return location.href + " secure=" + isSecureContext', args: [] }));
  const authId = await call('POST', `${S}/webauthn/authenticator`, { protocol: 'ctap2', transport, hasResidentKey: true, hasUserVerification: true, isUserConsenting: true, isUserVerified: true });
  console.log('auth', authId);
  const b64u = (b) => Buffer.from(b).toString('base64url');
  const userId = crypto.randomBytes(16); const regChallenge = crypto.randomBytes(32);
  const helpers = `const e=(b)=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');const d=(s)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((s.length+3)%4)),c=>c.charCodeAt(0));`;
  const run = (body) => call('POST', `${S}/execute/async`, { script: `const done=arguments[arguments.length-1];(async()=>{${helpers}${body}})().then(done,(x)=>done({error:String(x)}));`, args: [] });
  const reg = await run(`const c=await navigator.credentials.create({publicKey:{rp:{id:'example.com',name:'Example Cockpit'},user:{id:d('${b64u(userId)}'),name:'ada.example',displayName:'Ada Example'},challenge:d('${b64u(regChallenge)}'),pubKeyCredParams:[{type:'public-key',alg:${alg}}],authenticatorSelection:{residentKey:'required',userVerification:'required'},attestation:'none',timeout:60000}});
return {id:c.id,rawId:e(c.rawId),type:c.type,response:{clientDataJSON:e(c.response.clientDataJSON),attestationObject:e(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]},authenticatorAttachment:c.authenticatorAttachment,clientExtensionResults:c.getClientExtensionResults()};`);
  if (reg.error) throw new Error(reg.error);
  const auths = [];
  for (let i = 0; i < 2; i += 1) {
    const ch = crypto.randomBytes(32);
    const a = await run(`const c=await navigator.credentials.get({publicKey:{rpId:'example.com',challenge:d('${b64u(ch)}'),allowCredentials:[{type:'public-key',id:d('${reg.rawId}')}],userVerification:'required',timeout:60000}});
return {id:c.id,rawId:e(c.rawId),type:c.type,response:{clientDataJSON:e(c.response.clientDataJSON),authenticatorData:e(c.response.authenticatorData),signature:e(c.response.signature),userHandle:c.response.userHandle?e(c.response.userHandle):null},authenticatorAttachment:c.authenticatorAttachment,clientExtensionResults:c.getClientExtensionResults()};`);
    if (a.error) throw new Error(a.error);
    auths.push({ challenge: b64u(ch), response: a });
  }
  const fixture = {
    provenance: { browser: 'Mozilla Firefox', browser_version: sess.capabilities.browserVersion, os: 'Linux x86_64', authenticator: label, captured: new Date().toISOString().slice(0, 10),
      method: `Recorded from a real Mozilla Firefox browser calling navigator.credentials.create() and get() on https://example.com (routed to a local test server). The authenticator is Firefox's WebDriver virtual authenticator (WebDriver WebAuthn extension via geckodriver, CTAP2, transport ${transport}, user verification on), not a physical device. Firefox prefs: security.webauth.webauthn_enable_softtoken=true, security.webauth.webauthn_enable_usbtoken=false.`,
      notes: 'Invented user (Ada Example). Random user id and challenges generated for the capture. No real origins or identifiers.' },
    rp_id: 'example.com', origin: 'https://example.com',
    user: { id: b64u(userId), name: 'ada.example', display_name: 'Ada Example' },
    registration: { challenge: b64u(regChallenge), response: reg }, authentications: auths,
  };
  fs.writeFileSync(outFile, JSON.stringify(fixture, null, 2) + '\n');
  console.log('wrote', outFile, Buffer.from(reg.response.clientDataJSON, 'base64url').toString());
} finally { await call('DELETE', S); }
