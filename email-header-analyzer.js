/**
 * EmailHeaderAnalyzer - Advanced email authentication and header analysis
 * Checks SPF, DKIM, DMARC, sender IP geolocation, and spoofing detection
 */
class EmailHeaderAnalyzer {
  constructor() {
    // Suspicious country codes (known for high phishing activity)
    this.suspiciousCountries = ['CN', 'RU', 'NG', 'PK', 'IN', 'VN', 'BR'];

    // Legitimate NJIT IP ranges (example - should be updated with real ranges)
    this.njitIPRanges = [
      '128.235.', // NJIT's primary range
      '165.230.'  // NJIT's secondary range
    ];
  }

  /**
   * Main analysis method - extracts and analyzes email headers
   * @param {string} sender - Email address
   * @param {Object} headerData - Raw header data from Gmail
   * @returns {Object} Header analysis results
   */
  async analyze(sender, headerData = null) {
    const results = {
      authentication: {
        spf: { status: 'unknown', details: '' },
        dkim: { status: 'unknown', details: '' },
        dmarc: { status: 'unknown', details: '' }
      },
      sender: {
        ip: null,
        country: null,
        countryCode: null,
        isSuspicious: false,
        isNJITNetwork: false
      },
      spoofing: {
        displayNameMismatch: false,
        details: ''
      },
      routing: {
        hops: 0,
        suspiciousHops: []
      },
      overallRisk: 0
    };

    // If we have header data, parse it
    if (headerData) {
      this.parseAuthenticationHeaders(headerData, results);
      this.parseSenderIP(headerData, results);
      this.analyzeRouting(headerData, results);
    }

    // Check for display name spoofing
    this.checkDisplayNameSpoofing(sender, results);

    // Calculate overall risk score
    results.overallRisk = this.calculateRiskScore(results);

    return results;
  }

  /**
   * Parse SPF, DKIM, DMARC from Authentication-Results header
   */
  parseAuthenticationHeaders(headerData, results) {
    // Gmail typically includes Authentication-Results header
    const authHeader = this.findHeader(headerData, 'Authentication-Results');

    if (!authHeader) {
      return;
    }

    const authLower = authHeader.toLowerCase();

    // Parse SPF
    if (authLower.includes('spf=pass')) {
      results.authentication.spf.status = 'pass';
      results.authentication.spf.details = 'Sender authorized to send from this domain';
    } else if (authLower.includes('spf=fail')) {
      results.authentication.spf.status = 'fail';
      results.authentication.spf.details = 'Sender NOT authorized - possible spoofing';
    } else if (authLower.includes('spf=softfail')) {
      results.authentication.spf.status = 'softfail';
      results.authentication.spf.details = 'Sender questionable - domain owner suggests failure';
    } else if (authLower.includes('spf=neutral') || authLower.includes('spf=none')) {
      results.authentication.spf.status = 'neutral';
      results.authentication.spf.details = 'No SPF policy found';
    }

    // Parse DKIM
    if (authLower.includes('dkim=pass')) {
      results.authentication.dkim.status = 'pass';
      results.authentication.dkim.details = 'Email signature verified';
    } else if (authLower.includes('dkim=fail')) {
      results.authentication.dkim.status = 'fail';
      results.authentication.dkim.details = 'Email signature invalid - possible tampering';
    } else if (authLower.includes('dkim=neutral') || authLower.includes('dkim=none')) {
      results.authentication.dkim.status = 'neutral';
      results.authentication.dkim.details = 'No DKIM signature found';
    }

    // Parse DMARC
    if (authLower.includes('dmarc=pass')) {
      results.authentication.dmarc.status = 'pass';
      results.authentication.dmarc.details = 'Domain policy satisfied';
    } else if (authLower.includes('dmarc=fail')) {
      results.authentication.dmarc.status = 'fail';
      results.authentication.dmarc.details = 'Domain policy not satisfied - HIGH RISK';
    } else if (authLower.includes('dmarc=neutral') || authLower.includes('dmarc=none')) {
      results.authentication.dmarc.status = 'neutral';
      results.authentication.dmarc.details = 'No DMARC policy found';
    }
  }

  /**
   * Extract and analyze sender IP address
   */
  parseSenderIP(headerData, results) {
    // Try to find Received header with sender IP
    const receivedHeader = this.findHeader(headerData, 'Received');

    if (!receivedHeader) {
      return;
    }

    // Extract IP address (IPv4 pattern)
    const ipMatch = receivedHeader.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);

    if (ipMatch && ipMatch[1]) {
      results.sender.ip = ipMatch[1];

      // Check if IP is from NJIT network
      results.sender.isNJITNetwork = this.njitIPRanges.some(range =>
        results.sender.ip.startsWith(range)
      );

      // Get geolocation (using IP-API.com free service)
      // Note: In production, this would be done server-side
      this.getIPGeolocation(results.sender.ip, results);
    }
  }

  /**
   * Get IP geolocation data
   */
  async getIPGeolocation(ip, results) {
    try {
      // Use free IP geolocation service
      const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode`);
      const data = await response.json();

      if (data.status === 'success') {
        results.sender.country = data.country;
        results.sender.countryCode = data.countryCode;

        // Check if country is suspicious
        results.sender.isSuspicious = this.suspiciousCountries.includes(data.countryCode);
      }
    } catch (error) {
      console.log('Could not fetch IP geolocation:', error);
      // Fallback: analyze IP range
      this.analyzeIPRange(ip, results);
    }
  }

  /**
   * Analyze IP range to detect suspicious origins
   */
  analyzeIPRange(ip, results) {
    const firstOctet = parseInt(ip.split('.')[0]);

    // Private/local IPs (suspicious if claiming to be external)
    if (firstOctet === 10 || firstOctet === 192 || firstOctet === 172) {
      results.sender.isSuspicious = true;
      results.sender.country = 'Private Network';
    }
  }

  /**
   * Check for display name spoofing
   */
  checkDisplayNameSpoofing(sender, results) {
    // Extract email address parts
    const emailMatch = sender.match(/(.*)<(.+@.+)>/);

    if (emailMatch) {
      const displayName = emailMatch[1].trim();
      const actualEmail = emailMatch[2].toLowerCase();

      // Check if display name contains different domain than actual email
      const displayDomainMatch = displayName.match(/[@]([a-zA-Z0-9.-]+)/);

      if (displayDomainMatch) {
        const displayDomain = displayDomainMatch[1].toLowerCase();
        const actualDomain = actualEmail.split('@')[1];

        if (displayDomain !== actualDomain) {
          results.spoofing.displayNameMismatch = true;
          results.spoofing.details = `Display shows "${displayDomain}" but actual sender is "${actualDomain}"`;
        }
      }

      // Check for NJIT impersonation
      if (displayName.toLowerCase().includes('njit') && !actualEmail.includes('njit.edu')) {
        results.spoofing.displayNameMismatch = true;
        results.spoofing.details = `Display name mentions "NJIT" but sender is not from njit.edu`;
      }
    }
  }

  /**
   * Analyze email routing path
   */
  analyzeRouting(headerData, results) {
    const receivedHeaders = this.findAllHeaders(headerData, 'Received');
    results.routing.hops = receivedHeaders.length;

    // Check for suspicious relays
    receivedHeaders.forEach((header, index) => {
      const headerLower = header.toLowerCase();

      // Look for suspicious relay servers
      if (headerLower.includes('.tk') ||
          headerLower.includes('.ml') ||
          headerLower.includes('.ga') ||
          headerLower.includes('anonymizer') ||
          headerLower.includes('proxy')) {
        results.routing.suspiciousHops.push({
          hop: index + 1,
          reason: 'Suspicious relay server detected'
        });
      }
    });
  }

  /**
   * Calculate overall risk score from header analysis
   */
  calculateRiskScore(results) {
    let risk = 0;

    // Authentication failures (high weight)
    if (results.authentication.spf.status === 'fail') risk += 30;
    else if (results.authentication.spf.status === 'softfail') risk += 15;

    if (results.authentication.dkim.status === 'fail') risk += 25;

    if (results.authentication.dmarc.status === 'fail') risk += 30;

    // Suspicious sender location
    if (results.sender.isSuspicious) risk += 20;

    // NJIT impersonation (critical)
    if (results.spoofing.displayNameMismatch &&
        results.spoofing.details.toLowerCase().includes('njit')) {
      risk += 40;
    } else if (results.spoofing.displayNameMismatch) {
      risk += 25;
    }

    // Suspicious routing
    if (results.routing.suspiciousHops.length > 0) {
      risk += 15 * results.routing.suspiciousHops.length;
    }

    // If from NJIT network with valid auth, reduce risk
    if (results.sender.isNJITNetwork &&
        results.authentication.spf.status === 'pass') {
      risk = Math.max(0, risk - 30);
    }

    return Math.min(risk, 100);
  }

  /**
   * Helper: Find header value
   */
  findHeader(headerData, headerName) {
    if (!headerData || !headerData.headers) return null;

    const header = headerData.headers.find(h =>
      h.name.toLowerCase() === headerName.toLowerCase()
    );

    return header ? header.value : null;
  }

  /**
   * Helper: Find all instances of a header
   */
  findAllHeaders(headerData, headerName) {
    if (!headerData || !headerData.headers) return [];

    return headerData.headers
      .filter(h => h.name.toLowerCase() === headerName.toLowerCase())
      .map(h => h.value);
  }

  /**
   * Get human-readable status icon
   */
  getStatusIcon(status) {
    switch(status) {
      case 'pass': return '✓';
      case 'fail': return '✗';
      case 'softfail': return '⚠';
      case 'neutral': return '○';
      default: return '?';
    }
  }

  /**
   * Get status color class
   */
  getStatusClass(status) {
    switch(status) {
      case 'pass': return 'status-pass';
      case 'fail': return 'status-fail';
      case 'softfail': return 'status-warning';
      case 'neutral': return 'status-neutral';
      default: return 'status-unknown';
    }
  }
}

// Export to window for content script access
if (typeof window !== 'undefined') {
  window.EmailHeaderAnalyzer = EmailHeaderAnalyzer;
}
