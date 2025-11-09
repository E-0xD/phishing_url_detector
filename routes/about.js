const express = require('express');

module.exports = (deps) => {
  const router = express.Router();

  // Mounted in server as /about
  router.get('/', (req, res) => {
    res.render('about', {
      title: 'About - Phishing URL Detector'
    });
  });

  return router;
};