const express = require('express');

module.exports = (deps) => {
  const router = express.Router();
  const { cache, featureExtractor, classifier, explanationGenerator } = deps || {};

  router.post('/api/check-url', async (req, res) => {
    const startTime = Date.now();

    try {
      const { url } = req.body;

      // Validate input
      if (!url || typeof url !== 'string') {
        return res.status(400).json({
          success: false,
          error: 'Invalid URL provided'
        });
      }

      // Validate URL format
      let urlObj;
      try {
        urlObj = new URL(url);
      } catch (error) {
        return res.status(400).json({
          success: false,
          error: 'Invalid URL format. Please enter a valid URL including protocol (http:// or https://)'
        });
      }

      // Extract features (with caching)
      const features = await featureExtractor.extractAllFeatures(url, cache);

      if (!features) {
        return res.status(500).json({
          success: false,
          error: 'Failed to extract features from URL'
        });
      }

      // Classify URL
      const classification = classifier.classify(features);

      // Generate explanation
      const explanation = explanationGenerator.generate(features, classification);

      // Calculate processing time
      const processingTime = Date.now() - startTime;

      // Return result
      res.json({
        success: true,
        data: {
          url: url,
          classification,
          explanation,
          features,
          processingTime
        }
      });

    } catch (error) {
      console.error('Error processing URL:', error);
      res.status(500).json({
        success: false,
        error: 'An error occurred while processing the URL. Please try again.'
      });
    }
  });

  return router;
};
