class ExplanationGenerator {
  
  generate(features, classification) {
    const explanations = [];
    
    // URL Length
    if (features.url_length > 100) {
      explanations.push(`URL is unusually long (${features.url_length} characters). Phishing URLs are typically longer to hide malicious intent.`);
    } else if (features.url_length > 75) {
      explanations.push(`URL length (${features.url_length} characters) is above average. Legitimate URLs are usually shorter.`);
    }

    // Domain Age
    if (features.domain_age_days >= 0) {
      if (features.domain_age_days < 30) {
        explanations.push(`Domain was registered very recently (${features.domain_age_days} days ago). New domains are commonly used for phishing.`);
      } else if (features.domain_age_days < 180) {
        explanations.push(`Domain is relatively new (${features.domain_age_days} days old). Established sites typically have older domains.`);
      }
    }

    // Suspicious Keywords
    if (features.num_suspicious_keywords > 2) {
      explanations.push(`Contains ${features.num_suspicious_keywords} suspicious keywords often used in phishing (e.g., 'login', 'verify', 'account', 'secure').`);
    } else if (features.num_suspicious_keywords > 0) {
      explanations.push(`Contains ${features.num_suspicious_keywords} keyword(s) commonly found in phishing URLs.`);
    }

    // SSL Certificate
    if (features.is_https === 0) {
      explanations.push('URL uses HTTP instead of HTTPS. Legitimate sites handling sensitive data always use HTTPS.');
    } else if (features.ssl_certificate_valid === 0) {
      explanations.push('SSL certificate is invalid or expired. This is a major red flag for phishing sites.');
    }

    // IP Address
    if (features.has_ip_address === 1) {
      explanations.push('URL uses an IP address instead of a domain name. Legitimate organizations use recognizable domain names.');
    }

    // Suspicious TLD
    if (features.suspicious_tld === 1) {
      explanations.push('Top-level domain (TLD) is commonly associated with phishing sites (e.g., .tk, .ml, .ga, .click).');
    }

    // Number of dots
    if (features.num_dots > 4) {
      explanations.push(`URL contains ${features.num_dots} dots. Excessive dots often indicate misleading subdomains.`);
    }

    // Path depth
    if (features.path_depth > 4) {
      explanations.push(`URL has deep directory structure (${features.path_depth} levels). This may be used to obscure the true destination.`);
    }

    // @ symbol
    if (features.num_at_symbols > 0) {
      explanations.push('URL contains @ symbol, which can be used to trick users about the actual destination.');
    }

    // High entropy
    if (features.url_entropy > 5) {
      explanations.push('URL contains random-looking characters (high entropy), which is common in automatically generated phishing URLs.');
    }

    // If no specific red flags but classified as phishing
    if (explanations.length === 0 && classification.label === 'phishing') {
      explanations.push('Multiple subtle indicators suggest this may be a phishing attempt. Exercise caution.');
    }

    // If legitimate
    if (classification.label === 'legitimate' && explanations.length === 0) {
      explanations.push('URL structure appears normal with standard characteristics of legitimate websites.');
      
      if (features.is_https === 1 && features.ssl_certificate_valid === 1) {
        explanations.push('Valid HTTPS connection with proper SSL certificate.');
      }
      
      if (features.domain_age_days > 365) {
        explanations.push('Domain has been registered for over a year, indicating an established presence.');
      }
    }

    return explanations.slice(0, 5); // Return top 5 explanations
  }
}

module.exports = new ExplanationGenerator();