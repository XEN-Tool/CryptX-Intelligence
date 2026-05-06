const express = require('express');
const cors = require('cors');
const net = require('net');
const dns = require('dns').promises;
const { exec } = require('child_process');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const ABUSE_KEY = '1a2379c7faf2a195f7d7931580b19836e173aa022c1eebbae894801ac57d459efa53c2d677f1c58e';
const INTELX_KEY = '5dc6a784-f6a8-4c07-a6d8-35a8e34fc5d6';

// ─── GEO IP ───────────────────────────────────────────────
app.get('/api/geo/:query', async (req, res) => {
  try {
    const r = await fetch(`http://ip-api.com/json/${req.params.query}?fields=66842623`);
    res.json(await r.json());
  } catch(e) { res.status(500).json({error: e.message}); }
});

// ─── WHOIS ────────────────────────────────────────────────
app.get('/api/whois/:query', async (req, res) => {
  try {
    const r = await fetch(`https://whoisjson.com/api/v1/whois?domain=${encodeURIComponent(req.params.query)}`);
    res.json(await r.json());
  } catch(e) { res.status(500).json({error: e.message}); }
});

// ─── DNS RECORDS ──────────────────────────────────────────
app.get('/api/dns/:query', async (req, res) => {
  const q = req.params.query;
  const results = {};
  const types = ['A','AAAA','MX','TXT','NS','CNAME'];
  await Promise.allSettled(types.map(async t => {
    try {
      const fn = {
        A: () => dns.resolve4(q),
        AAAA: () => dns.resolve6(q),
        MX: () => dns.resolveMx(q),
        TXT: () => dns.resolveTxt(q),
        NS: () => dns.resolveNs(q),
        CNAME: () => dns.resolveCname(q),
      }[t];
      results[t] = await fn();
    } catch { results[t] = []; }
  }));
  res.json(results);
});

// ─── REVERSE DNS ──────────────────────────────────────────
app.get('/api/rdns/:ip', async (req, res) => {
  try {
    const hostnames = await dns.reverse(req.params.ip);
    res.json({ hostnames });
  } catch(e) { res.json({ hostnames: [] }); }
});

// ─── PORT SCAN ────────────────────────────────────────────
const COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017];
const PORT_NAMES = {21:'FTP',22:'SSH',23:'TELNET',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',3306:'MYSQL',3389:'RDP',5432:'POSTGRES',6379:'REDIS',8080:'HTTP-ALT',8443:'HTTPS-ALT',8888:'HTTP-ALT2',9200:'ELASTICSEARCH',27017:'MONGODB'};

function scanPort(host, port, timeout = 2000) {
  return new Promise(resolve => {
    const sock = new net.Socket();
    let status = 'closed';
    sock.setTimeout(timeout);
    sock.on('connect', () => { status = 'open'; sock.destroy(); });
    sock.on('timeout', () => { status = 'filtered'; sock.destroy(); });
    sock.on('error', (e) => { status = e.code === 'ECONNREFUSED' ? 'closed' : 'filtered'; });
    sock.on('close', () => resolve({ port, name: PORT_NAMES[port]||'UNKNOWN', status }));
    sock.connect(port, host);
  });
}

app.get('/api/ports/:host', async (req, res) => {
  try {
    const results = await Promise.all(COMMON_PORTS.map(p => scanPort(req.params.host, p)));
    res.json(results);
  } catch(e) { res.status(500).json({error: e.message}); }
});

// ─── TRACEROUTE ───────────────────────────────────────────
app.get('/api/traceroute/:host', (req, res) => {
  const host = req.params.host;
  const isWin = process.platform === 'win32';
  const cmd = isWin ? `tracert -h 15 ${host}` : `traceroute -m 15 -w 2 ${host}`;
  exec(cmd, { timeout: 30000 }, (err, stdout) => {
    const lines = (stdout||'').split('\n').filter(l => l.trim());
    const hops = [];
    lines.forEach(line => {
      const match = line.match(/^\s*(\d+)\s+([\d.]+\s+ms|[\d.]+\s+ms|\*)/i);
      const ipMatch = line.match(/\(?([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})\)?/);
      const msMatch = line.match(/([\d.]+)\s+ms/);
      const hopNum = line.match(/^\s*(\d+)/);
      if (hopNum) {
        hops.push({
          hop: parseInt(hopNum[1]),
          ip: ipMatch ? ipMatch[1] : '*',
          ms: msMatch ? msMatch[1]+'ms' : '*'
        });
      }
    });
    res.json(hops.slice(0, 15));
  });
});

// ─── ABUSEIPDB ────────────────────────────────────────────
app.get('/api/abuse/:ip', async (req, res) => {
  try {
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(req.params.ip)}&maxAgeInDays=90`, {
      headers: { 'Key': ABUSE_KEY, 'Accept': 'application/json' }
    });
    res.json(await r.json());
  } catch(e) { res.status(500).json({error: e.message}); }
});

// ─── INTELX SEARCH ────────────────────────────────────────
app.post('/api/intelx/search', async (req, res) => {
  try {
    const { query } = req.body;
    const r = await fetch('https://2.intelx.io/intelligent/search', {
      method: 'POST',
      headers: { 'x-key': INTELX_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        term: query,
        buckets: ['leaks.public.wikileaks','leaks.public.general','dumpster','documents.public.scihub'],
        lookuplevel: 0, maxresults: 30, timeout: 15,
        datefrom: '', dateto: '', sort: 4, media: 0, terminate: []
      })
    });
    const j = await r.json();
    if (!j.id) return res.json({ records: [] });
    await new Promise(r => setTimeout(r, 2500));
    const r2 = await fetch(`https://2.intelx.io/intelligent/search/result?id=${j.id}&limit=30&offset=0`, {
      headers: { 'x-key': INTELX_KEY }
    });
    const j2 = await r2.json();
    res.json({ records: j2.records || [] });
  } catch(e) { res.status(500).json({ error: e.message, records: [] }); }
});

// ─── SSL CHECK ────────────────────────────────────────────
app.get('/api/ssl/:host', (req, res) => {
  const host = req.params.host.replace(/^https?:\/\//, '');
  const tls = require('tls');
  try {
    const sock = tls.connect(443, host, { servername: host, rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate(true);
      sock.end();
      if (!cert || !cert.subject) return res.json({ error: 'No cert' });
      res.json({
        subject: cert.subject?.CN || 'N/A',
        issuer: cert.issuer?.O || cert.issuer?.CN || 'N/A',
        validFrom: cert.valid_from || 'N/A',
        validTo: cert.valid_to || 'N/A',
        serial: cert.serialNumber || 'N/A',
        fingerprint: cert.fingerprint || 'N/A',
        san: cert.subjectaltname || 'N/A',
        valid: new Date(cert.valid_to) > new Date()
      });
    });
    sock.on('error', e => res.json({ error: e.message }));
    sock.setTimeout(5000, () => { sock.destroy(); res.json({ error: 'timeout' }); });
  } catch(e) { res.json({ error: e.message }); }
});

// ─── BGP / ASN INFO ───────────────────────────────────────
app.get('/api/asn/:asn', async (req, res) => {
  try {
    const r = await fetch(`https://api.bgpview.io/asn/${req.params.asn.replace('AS','')}`);
    res.json(await r.json());
  } catch(e) { res.status(500).json({error: e.message}); }
});

// ─── SERVE FRONTEND ───────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CryptX running on http://localhost:${PORT}`));