const https = require('https');
const fs = require('fs');
const forge = require('node-forge');
const express = require('express');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();

app.use(cookieParser());
app.use(express.static('public'));

const p12Buffer = fs.readFileSync('localhost.p12');
const password = process.env.P12_PASSWORD;

const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

let key, cert;
for (const safeContent of p12.safeContents) {
  for (const safeBag of safeContent.safeBags) {
    if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
      key = forge.pki.privateKeyToPem(safeBag.key);
    } else if (safeBag.type === forge.pki.oids.certBag) {
      cert = forge.pki.certificateToPem(safeBag.cert);
    }
  }
}

const options = {
  key,
  cert,
  secureProtocol: 'TLSv1_2_method',
  ciphers: 'TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA'
};

const clientId = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;
const casdoorEndpoint = process.env.CASDOOR_ENDPOINT;
const redirectUri = 'https://localhost:8443/callback';

app.get("/login", (req, res) => {
  const authUrl = `${casdoorEndpoint}/login/oauth/authorize` +
    `?client_id=${clientId}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=openid` +
    `&state=123`;
  res.redirect(authUrl);
});

app.get("/callback", async (req, res) => {
  const code = req.query.code;

  const tokenRes = await fetch(`${casdoorEndpoint}/api/login/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "authorization_code",
      redirect_uri: redirectUri
    })
  });

  const tokenData = await tokenRes.json();
  res.cookie("token", tokenData.access_token, { httpOnly: true });
  res.redirect("/");
});

const jwt = require('jsonwebtoken');

app.get("/userinfo", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not logged in" });

  try {
    const decoded = jwt.decode(token); 
    const userId = decoded.sub;
    const username = decoded.name || decoded.preferred_username;

    res.json({ userId, username });
  } catch (err) {
    res.status(400).json({ error: "Invalid token" });
  }
});

function login() {
  window.location.href = "/login";
}

async function getUserInfo() {
  const res = await fetch("/userinfo");
  if (res.status === 401) {
    document.getElementById("status").textContent = "log in to view";
    return;
  }
  const data = await res.json();
  document.getElementById("userinfo").textContent = JSON.stringify(data, null, 2);
  document.getElementById("status").textContent = "Already logged in!";
}

const WebSocket = require('ws');

const server = https.createServer(options, app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  const cookies = require('cookie').parse(req.headers.cookie || '');
  const token = cookies.token;

  if (!token) {
    ws.send(JSON.stringify({ error: 'Not logged in' }));
    ws.close();
    return;
  }

  const binanceSocket = new WebSocket('wss://stream.binance.com:9443/stream?streams=btcusdt@ticker/ethusdt@ticker/xrpusdt@ticker/dogeusdt@ticker');

  binanceSocket.on('message', data => {
    ws.send(data.toString());
  });

  ws.on('close', () => binanceSocket.close());
});


server.listen(8443, () => {
  console.log('HTTPS сервер запущено на https://localhost:8443');
});
