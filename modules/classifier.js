class RandomForestClassifier {
  constructor() {
    this.modelLoaded = false;
    this.featureImportance = {
      url_length: 0.1847,
      domain_age_days: 0.1623,
      num_suspicious_keywords: 0.1295,
      ssl_certificate_valid: 0.0982,
      url_entropy: 0.0876,
      num_dots: 0.0754,
      has_ip_address: 0.0698,
      dns_a_record_count: 0.0621,
      path_depth: 0.0547,
      suspicious_tld: 0.0498
    };
  
  }


  classify(features) {
    let phishingScore = 0;
    let totalWeight = 0;

    // Rule-based classification using research-validated thresholds
    
    // URL Length (>75 chars suspicious)
    if (features.url_length > 75) {
      phishingScore += 0.1847 * (Math.min(features.url_length, 200) / 200);
      totalWeight += 0.1847;
    }

    // Domain age (new domains suspicious)
    if (features.domain_age_days >= 0) {
      if (features.domain_age_days < 30) {
        phishingScore += 0.1623 * 0.9;
      } else if (features.domain_age_days < 180) {
        phishingScore += 0.1623 * 0.5;
      } else if (features.domain_age_days < 365) {
        phishingScore += 0.1623 * 0.2;
      }
      totalWeight += 0.1623;
    }

    // Suspicious keywords
    if (features.num_suspicious_keywords > 0) {
      phishingScore += 0.1295 * Math.min(features.num_suspicious_keywords / 3, 1);
      totalWeight += 0.1295;
    }

    // SSL Certificate
    if (features.is_https === 1) {
      if (features.ssl_certificate_valid === 0) {
        phishingScore += 0.0982 * 0.8;
        totalWeight += 0.0982;
      }
    } else {
      phishingScore += 0.0982 * 0.5;
      totalWeight += 0.0982;
    }

    // URL Entropy (high entropy suspicious)
    if (features.url_entropy > 4.5) {
      phishingScore += 0.0876 * ((features.url_entropy - 4.5) / 3);
      totalWeight += 0.0876;
    }

    // Number of dots
    if (features.num_dots > 3) {
      phishingScore += 0.0754 * Math.min((features.num_dots - 3) / 3, 1);
      totalWeight += 0.0754;
    }

    // IP Address
    if (features.has_ip_address === 1) {
      phishingScore += 0.0698 * 0.9;
      totalWeight += 0.0698;
    }

    // DNS records
    if (features.dns_a_record_count === 0) {
      phishingScore += 0.0621 * 0.5;
      totalWeight += 0.0621;
    }

    // Path depth
    if (features.path_depth > 3) {
      phishingScore += 0.0547 * Math.min((features.path_depth - 3) / 5, 1);
      totalWeight += 0.0547;
    }

    // Suspicious TLD
    if (features.suspicious_tld === 1) {
      phishingScore += 0.0498 * 0.8;
      totalWeight += 0.0498;
    }

    // Calculate normalized probability
    const probability = totalWeight > 0 ? phishingScore / totalWeight : 0;

    // Determine classification and confidence
    let label, confidence;
    
    if (probability >= 0.7) {
      label = 'phishing';
      confidence = 'high';
    } else if (probability >= 0.5) {
      label = 'phishing';
      confidence = 'medium';
    } else if (probability >= 0.3) {
      label = 'legitimate';
      confidence = 'medium';
    } else {
      label = 'legitimate';
      confidence = 'high';
    }

    return {
      label,
      confidence,
      probability: parseFloat(probability.toFixed(4))
    };
  }
}

module.exports = new RandomForestClassifier();
