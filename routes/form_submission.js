const express = require('express');

module.exports = (deps) => {
  const router = express.Router();
  const { cache, featureExtractor, classifier, explanationGenerator } = deps || {};

  router.post('/check', async (req, res) => {
    const startTime = Date.now();

    try {
      const { url } = req.body;

      // Validate URL format
      let urlObj;
      try {
        urlObj = new URL(url);
      } catch (error) {
        return res.render('index', {
          title: 'Phishing URL Detector',
          result: {
            error: 'Invalid URL format. Please enter a valid URL including protocol (http:// or https://)'
          }
        });
      }

      // Extract features
      const features = await featureExtractor.extractAllFeatures(url, cache);

      if (!features) {
        return res.render('index', {
          title: 'Phishing URL Detector',
          result: {
            error: 'Failed to extract features from URL'
          }
        });
      }

      // Classify
      const classification = classifier.classify(features);

      // Generate explanation
      const explanation = explanationGenerator.generate(features, classification);

      // Calculate processing time
      const processingTime = Date.now() - startTime;

      // Render result
      res.render('index', {
        title: 'Phishing URL Detector',
        result: {
          url: url,
          classification: classification.label,
          confidence: classification.confidence,
          probability: classification.probability,
          explanation: explanation,
          processingTime: processingTime
        }
      });

    } catch (error) {
      console.error('Error processing URL:', error);
      res.render('index', {
        title: 'Phishing URL Detector',
        result: {
          error: 'An error occurred while processing the URL. Please try again.'
        }
      });
    }
  });

  return router;
};