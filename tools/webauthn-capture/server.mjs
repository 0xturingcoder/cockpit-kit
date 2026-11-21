// Development tool only (not part of the kit). Records WebAuthn fixtures; see README.md.
import https from 'node:https'; import fs from 'node:fs';
https.createServer({ key: fs.readFileSync('key.pem'), cert: fs.readFileSync('cert.pem') }, (req, res) => {
  res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><title>capture</title><h1>WebAuthn capture</h1>');
}).listen(8443, '127.0.0.1', () => console.log('listening'));
