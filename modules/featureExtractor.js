const dns = require('dns').promises;
const https = require('https');
const whois = require('whois-json');
const tls = require('tls');

class FeatureExtractor {
  
  async extractAllFeatures(urlString, cache) {
    try {
      const urlObj = new URL(urlString);
      
      // Extract different feature categories
      const lexicalFeatures = this.extractLexicalFeatures(urlString, urlObj);
      const hostBasedFeatures = await this.extractHostBasedFeatures(urlObj.hostname, cache);
      const heuristicFeatures = this.extractHeuristicFeatures(urlObj);
      
      console.log(hostBasedFeatures);
      
      // Combine all features
      return {
        url: urlString,
        ...lexicalFeatures,
        ...hostBasedFeatures,
        ...heuristicFeatures
      };
    } catch (error) {
      console.error('Error extracting features:', error);
      return null;
    }
  }

  extractLexicalFeatures(urlString, urlObj) {
    const features = {};
    
    // Feature 1: URL Length
    features.url_length = urlString.length;
    
    // Feature 2: Number of dots
    features.num_dots = (urlString.match(/\./g) || []).length;
    
    // Feature 3: Number of hyphens
    features.num_hyphens = (urlString.match(/-/g) || []).length;
    
    // Feature 4: Number of underscores
    features.num_underscores = (urlString.match(/_/g) || []).length;
    
    // Feature 5: Number of slashes
    features.num_slashes = (urlString.match(/\//g) || []).length;
    
    // Feature 6: Number of question marks
    features.num_question_marks = (urlString.match(/\?/g) || []).length;
    
    // Feature 7: Number of equals signs
    features.num_equals = (urlString.match(/=/g) || []).length;
    
    // Feature 8: Number of @ symbols
    features.num_at_symbols = (urlString.match(/@/g) || []).length;
    
    // Feature 9: Number of ampersands
    features.num_ampersands = (urlString.match(/&/g) || []).length;
    
    // Feature 10: Number of digits
    features.num_digits = (urlString.match(/\d/g) || []).length;
    
    // Feature 11: Has IP address
    const ipv4Pattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const ipv6Pattern = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/;
    features.has_ip_address = (ipv4Pattern.test(urlString) || ipv6Pattern.test(urlString)) ? 1 : 0;
    
    // Feature 12: Suspicious keywords
    const suspiciousKeywords = [
      'login', 'signin', 'verify', 'update', 'secure', 'account',
      'banking', 'confirm', 'suspended', 'password', 'credential',
      'payment', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft','url'
    ];
    const lowerUrl = urlString.toLowerCase();
    features.num_suspicious_keywords = suspiciousKeywords.filter(keyword => 
      lowerUrl.includes(keyword)
    ).length;
    
    // Feature 13: URL Entropy
    features.url_entropy = this.calculateEntropy(urlString);
    
    // Feature 14: Path depth
    const pathParts = urlObj.pathname.split('/').filter(part => part.length > 0);
    features.path_depth = pathParts.length;
    
    // Feature 15: Number of query parameters
    features.num_query_params = Array.from(urlObj.searchParams.keys()).length;
    
    // Feature 16: Domain length
    features.domain_length = urlObj.hostname.length;
    
    // Feature 17: TLD length
    const tldMatch = urlObj.hostname.match(/\.([^.]+)$/);
    features.tld_length = tldMatch ? tldMatch[1].length : 0;
    
    // Feature 18: Number of subdomains
    const domainParts = urlObj.hostname.split('.');
    features.num_subdomains = Math.max(0, domainParts.length - 2);
    
    // Feature 19: Is HTTPS
    features.is_https = urlObj.protocol === 'https:' ? 1 : 0;
    
    // Feature 20: Digit ratio
    features.digit_ratio = features.num_digits / urlString.length;
    
    return features;
  }

  async extractHostBasedFeatures(hostname, cache) {
    const features = {
      domain_age_days: -1,
      registration_length_days: -1,
      whois_privacy: -1,
      dns_a_record_count: 0,
      has_mx_records: 0,
      dns_ttl: -1,
      ssl_certificate_age_days: -1,
      ssl_certificate_valid: 0,
      ssl_is_ev: 0
    };

    try {
      // Check cache
      const cacheKey = `host:${hostname}`;
      const cached = cache.get(cacheKey);
      if (cached) return cached;

      // --- DNS A Records ---
      try {
        const aRecords = await dns.resolve4(hostname);
        features.dns_a_record_count = aRecords.length;
      } catch (error) {
        // Ignore DNS resolution errors
      }

      // --- MX Records ---
      try {
        const mxRecords = await dns.resolveMx(hostname);
        features.has_mx_records = mxRecords.length > 0 ? 1 : 0;
      } catch (error) {
        // Ignore MX errors
      }

      // --- TTL (DNS Time To Live) ---
      try {
        const ttlRecords = await dns.resolveAny(hostname);
        if (ttlRecords && ttlRecords.length > 0 && ttlRecords[0].ttl)
          features.dns_ttl = ttlRecords[0].ttl;
      } catch (error) {
        // Ignore TTL errors
      }

      // --- WHOIS Data ---
      try {
        const whoisData = await whois(hostname);

        const createdDate = whoisData.creationDate || whoisData.createdDate || whoisData.registered || whoisData.created;
        const expiryDate = whoisData.expirationDate || whoisData.expires || whoisData.registrarRegistrationExpirationDate;
        const registrantInfo = whoisData.registrant || whoisData.registrantOrganization || whoisData['Registrant Organization'];

        const currentDate = new Date();

        if (createdDate) {
          const creation = new Date(createdDate);
          features.domain_age_days = Math.floor((currentDate - creation) / (1000 * 60 * 60 * 24));
        }

        if (createdDate && expiryDate) {
          const creation = new Date(createdDate);
          const expiry = new Date(expiryDate);
          features.registration_length_days = Math.floor((expiry - creation) / (1000 * 60 * 60 * 24));
        }

        // Whois privacy detection (crude check)
        const whoisText = JSON.stringify(whoisData).toLowerCase();
        if (
          whoisText.includes('privacy') ||
          whoisText.includes('proxy') ||
          whoisText.includes('guard') ||
          whoisText.includes('redacted')
        ) {
          features.whois_privacy = 1;
        } else {
          features.whois_privacy = 0;
        }

      } catch (error) {
        // WHOIS lookup failed, keep default values
      }

      // --- SSL Certificate ---
      try {
        const certInfo = await this.getSSLCertificateInfo(hostname);
        if (certInfo.validFrom) {
          const validFrom = new Date(certInfo.validFrom);
          const currentDate = new Date();
          features.ssl_certificate_age_days = Math.floor((currentDate - validFrom) / (1000 * 60 * 60 * 24));
        }
        features.ssl_certificate_valid = certInfo.valid ? 1 : 0;
        features.ssl_is_ev = certInfo.isEV ? 1 : 0;
      } catch (error) {
        // SSL check failed
      }

      // --- Cache results ---
      cache.set(cacheKey, features);

      return features;
    } catch (error) {
      console.error('Error extracting host-based features:', error);
      return features;
    }
  }

  // --- Helper: SSL Certificate Info ---
  async getSSLCertificateInfo(hostname) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(443, hostname, { servername: hostname }, () => {
        const cert = socket.getPeerCertificate();
        if (!cert || Object.keys(cert).length === 0) {
          socket.end();
          return reject(new Error('No certificate found'));
        }

        const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
        const isValid = validTo && validTo > new Date();
        const isEV = cert.subject && cert.subject.O && cert.subject.O.includes('Inc'); // Simple EV detection

        socket.end();
        resolve({
          validFrom,
          validTo,
          valid: !!isValid,
          isEV
        });
      });

      socket.on('error', reject);
    });
  }

  extractHeuristicFeatures(urlObj) {
    const features = {};
    
    // Feature 30: Suspicious TLD
    const suspiciousTLDs = [
      'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'link',
      'pw', 'buzz', 'loan', 'win', 'download', 'stream', 'zip'
    ];
    const tldMatch = urlObj.hostname.match(/\.([^.]+)$/);
    const tld = tldMatch ? tldMatch[1].toLowerCase() : '';
    features.suspicious_tld = suspiciousTLDs.includes(tld) ? 1 : 0;
    
    return features;
  }

  calculateEntropy(str) {
    const frequencies = {};
    for (let char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    let entropy = 0;
    const length = str.length;
    
    for (let char in frequencies) {
      const probability = frequencies[char] / length;
      entropy -= probability * Math.log2(probability);
    }
    
    return entropy;
  }

  getSSLCertificateInfo(hostname) {
    return new Promise((resolve) => {
      const options = {
        host: hostname,
        port: 443,
        method: 'GET',
        rejectUnauthorized: false,
        timeout: 5000
      };

      const req = https.request(options, (res) => {
        const certificate = res.socket.getPeerCertificate();
        
        if (certificate && Object.keys(certificate).length > 0) {
          const certInfo = {
            validFrom: certificate.valid_from,
            validTo: certificate.valid_to,
            valid: new Date() >= new Date(certificate.valid_from) &&
                   new Date() <= new Date(certificate.valid_to),
            issuer: certificate.issuer,
            isEV: certificate.subject && certificate.subject.businessCategory === 'Private Organization' ? 1 : 0
          };
          resolve(certInfo);
        } else {
          resolve({
            validFrom: null,
            validTo: null,
            valid: false,
            isEV: false
          });
        }
      });

      req.on('error', () => {
        resolve({
          validFrom: null,
          validTo: null,
          valid: false,
          isEV: false
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          validFrom: null,
          validTo: null,
          valid: false,
          isEV: false
        });
      });

      req.end();
    });
  }
}

module.exports = new FeatureExtractor();
