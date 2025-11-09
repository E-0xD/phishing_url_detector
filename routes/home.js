const express = require('express');

module.exports = (deps) => {
  const router = express.Router();

  router.get('/', (req, res) => {
    res.render('index', {
      title: 'Phishing URL Detector',
      result: null
    });
  });

  return router;
};