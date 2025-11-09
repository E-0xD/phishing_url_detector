const express = require('express');

module.exports = (deps) => {
  const router = express.Router();
  const { cache, classifier } = deps || {};

  // Mounted in server under /api, so endpoint is /api/health
  router.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      uptime: process.uptime(),
      modelLoaded: typeof classifier?.isModelLoaded === 'function' ? classifier.isModelLoaded() : false,
      cacheSize: cache && typeof cache.keys === 'function' ? cache.keys().length : 0,
      timestamp: new Date().toISOString()
    });
  });

  return router;
};