// Development tool only (not part of the kit). Records WebAuthn fixtures; see README.md.
import http from 'node:http'; import net from 'node:net';
const s = http.createServer((q, r) => { r.writeHead(400); r.end(); });
s.on('connect', (req, sock, head) => {
  if (req.url !== 'example.com:443') { sock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
  const up = net.connect(8443, '127.0.0.1', () => { sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); up.write(head); up.pipe(sock); sock.pipe(up); });
  up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
});
s.listen(8899, '127.0.0.1', () => console.log('proxy'));
