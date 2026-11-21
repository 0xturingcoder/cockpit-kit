// Development tool only (not part of the kit). Records WebAuthn fixtures; see README.md.
// Drives a real Chrome over CDP with a virtual authenticator to record WebAuthn responses.
import crypto from 'node:crypto';
import fs from 'node:fs';
const [,, port, label, transport, alg, outFile] = process.argv;
const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const page = targets.find((t) => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0; const pending = new Map();
ws.addEventListener('message', (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } });
const send = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => { const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true, userGesture: true }); if (r.result.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails)); return r.result.result.value; };
await send('Page.enable');
await send('Page.navigate', { url: 'https://example.com/' });
await new Promise((r) => setTimeout(r, 1500));
console.log('location', await ev('location.href'), 'secure', await ev('isSecureContext'));
await send('WebAuthn.enable', { enableUI: false });
const va = await send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport, hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
console.log('authenticator', JSON.stringify(va.result ?? va.error));
const b64u = (b) => Buffer.from(b).toString('base64url');
const userId = crypto.randomBytes(16); const regChallenge = crypto.randomBytes(32);
const helpers = `const e=(b)=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');const d=(s)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'==='.slice((s.length+3)%4)),c=>c.charCodeAt(0));`;
const reg = await ev(`(async()=>{${helpers}
const c=await navigator.credentials.create({publicKey:{rp:{id:'example.com',name:'Example Cockpit'},user:{id:d('${b64u(userId)}'),name:'ada.example',displayName:'Ada Example'},challenge:d('${b64u(regChallenge)}'),pubKeyCredParams:[{type:'public-key',alg:${alg}}],authenticatorSelection:{residentKey:'required',userVerification:'required'},attestation:'none',timeout:60000}});
return {id:c.id,rawId:e(c.rawId),type:c.type,response:{clientDataJSON:e(c.response.clientDataJSON),attestationObject:e(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]},authenticatorAttachment:c.authenticatorAttachment,clientExtensionResults:c.getClientExtensionResults()};})()`);
const auths = [];
for (let i = 0; i < 2; i += 1) {
  const ch = crypto.randomBytes(32);
  const a = await ev(`(async()=>{${helpers}
const c=await navigator.credentials.get({publicKey:{rpId:'example.com',challenge:d('${b64u(ch)}'),allowCredentials:${i===0?`[{type:'public-key',id:d('${reg.rawId}')}]`:'[]'},userVerification:'required',timeout:60000}});
return {id:c.id,rawId:e(c.rawId),type:c.type,response:{clientDataJSON:e(c.response.clientDataJSON),authenticatorData:e(c.response.authenticatorData),signature:e(c.response.signature),userHandle:c.response.userHandle?e(c.response.userHandle):null},authenticatorAttachment:c.authenticatorAttachment,clientExtensionResults:c.getClientExtensionResults()};})()`);
  auths.push({ challenge: b64u(ch), response: a });
}
const version = (await send('Browser.getVersion')).result;
const fixture = {
  provenance: { browser: 'Google Chrome', browser_version: version.product.replace('Chrome/', ''), os: 'Linux x86_64', authenticator: label, captured: new Date().toISOString().slice(0, 10),
    method: `Recorded from a real Google Chrome browser calling navigator.credentials.create() and get() on https://example.com (resolved to a local test server). The authenticator is Chrome's built-in CTAP2 virtual authenticator (DevTools WebAuthn domain, transport ${transport}, user verification on), not a physical device.`,
    notes: 'Invented user (Ada Example). Random user id and challenges generated for the capture. The first sign-in lists the credential in allowCredentials; the second is usernameless (empty allowCredentials), as the server does. No real origins or identifiers.' },
  rp_id: 'example.com', origin: 'https://example.com',
  user: { id: b64u(userId), name: 'ada.example', display_name: 'Ada Example' },
  registration: { challenge: b64u(regChallenge), response: reg }, authentications: auths,
};
fs.writeFileSync(outFile, JSON.stringify(fixture, null, 2) + '\n');
console.log('wrote', outFile, 'alg', alg, JSON.stringify(Buffer.from(reg.response.clientDataJSON, 'base64url').toString()));
ws.close(); process.exit(0);
