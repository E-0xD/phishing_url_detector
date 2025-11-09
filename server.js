
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const NodeCache = require('node-cache');


// Import custom modules
const featureExtractor = require('./modules/featureExtractor');
const classifier = require('./modules/classifier');
const explanationGenerator = require('./modules/explanationGenerator');

const app = express();
const PORT = process.env.PORT || 3000;

// Cache setup (24 hour TTL for WHOIS/DNS data)
const cache = new NodeCache({ stdTTL: 86400, checkperiod: 3600 });

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ============================================
// ROUTES (mounted from separate files)
// ============================================

// Provide shared dependencies to route modules
const routeDeps = {
  cache,
  featureExtractor,
  classifier,
  explanationGenerator
};

// Mount route modules
app.use('/', require('./routes/home')(routeDeps));
app.use('/about', require('./routes/about')(routeDeps));
app.use('/api', require('./routes/health')(routeDeps));
app.use('/', require('./routes/check_url')(routeDeps)); // mounts /api/check-url
app.use('/', require('./routes/form_submission')(routeDeps)); // mounts /check

// 404 and error middleware (last)
app.use(require('./routes/404')(routeDeps));
app.use(require('./routes/error-handler')(routeDeps));

// Start server
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════╗
║   Phishing URL Detection System                    ║
║   Server running on http://localhost:${PORT}       ║
║   Press Ctrl+C to stop                             ║
╚════════════════════════════════════════════════════╝
  `);
});
