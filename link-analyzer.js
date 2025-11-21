/**
 * LinkAnalyzer - Advanced link safety analysis and visual highlighting
 * Checks links for safety, unwraps shorteners, and provides visual indicators
 */
class LinkAnalyzer {
  constructor() {
    // URL shorteners
    this.urlShorteners = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
      'tiny.cc', 'is.gd', 'buff.ly', 'adf.ly', 'short.link',
      'rb.gy', 'cutt.ly', 'shorturl.at', 'trib.al'
    ];

    // Suspicious TLDs
    this.suspiciousTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc',
      '.top', '.work', '.click', '.link', '.download'
    ];

    // Legitimate domains (whitelist)
    this.legitimateDomains = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
      'njit.edu', 'github.com', 'stackoverflow.com', 'linkedin.com',
      'twitter.com', 'facebook.com', 'youtube.com', 'zoom.us'
    ];

    // Known phishing keywords in URLs
    this.phishingKeywords = [
      'verify', 'account', 'signin', 'login', 'secure', 'update',
      'confirm', 'banking', 'paypal', 'amazon-', 'apple-',
      'microsoft-', 'secure-login', 'verify-account'
    ];

    // Cache for analyzed links (to avoid re-analyzing)
    this.linkCache = new Map();
  }

  /**
   * Analyze all links in email
   * @param {Array} links - Array of URLs
   * @returns {Object} Analysis results
   */
  async analyzeLinks(links) {
    const results = {
      totalLinks: links.length,
      safeLinks: [],
      suspiciousLinks: [],
      dangerousLinks: [],
      unknownLinks: [],
      overallRisk: 0
    };

    for (const link of links) {
      const analysis = await this.analyzeSingleLink(link);

      switch(analysis.riskLevel) {
        case 'safe':
          results.safeLinks.push(analysis);
          break;
        case 'suspicious':
          results.suspiciousLinks.push(analysis);
          break;
        case 'dangerous':
          results.dangerousLinks.push(analysis);
          break;
        default:
          results.unknownLinks.push(analysis);
      }
    }

    // Calculate overall risk
    results.overallRisk = this.calculateLinkRisk(results);

    return results;
  }

  /**
   * Analyze single link
   * @param {string} url - URL to analyze
   * @returns {Object} Link analysis
   */
  async analyzeSingleLink(url) {
    // Check cache first
    if (this.linkCache.has(url)) {
      return this.linkCache.get(url);
    }

    const analysis = {
      url: url,
      displayUrl: this.truncateUrl(url),
      riskLevel: 'unknown',
      riskScore: 0,
      reasons: [],
      details: {
        isShortened: false,
        realDestination: null,
        isDomainMismatch: false,
        hasPhishingKeywords: false,
        hasSuspiciousTLD: false,
        isIPAddress: false,
        isHTTPS: false
      }
    };

    try {
      const urlObj = new URL(url);

      // Check HTTPS
      analysis.details.isHTTPS = urlObj.protocol === 'https:';
      if (!analysis.details.isHTTPS) {
        analysis.riskScore += 15;
        analysis.reasons.push('Insecure HTTP connection');
      }

      // Check if legitimate domain
      const isLegitimate = this.legitimateDomains.some(domain =>
        urlObj.hostname.endsWith(domain)
      );

      if (isLegitimate) {
        analysis.riskLevel = 'safe';
        analysis.riskScore = 0;
        analysis.reasons = ['Trusted domain'];
        this.linkCache.set(url, analysis);
        return analysis;
      }

      // Check for IP address
      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)) {
        analysis.details.isIPAddress = true;
        analysis.riskScore += 40;
        analysis.reasons.push('Uses IP address instead of domain name');
      }

      // Check for URL shortener
      if (this.isShortener(urlObj.hostname)) {
        analysis.details.isShortened = true;
        analysis.riskScore += 25;
        analysis.reasons.push('URL shortener - hides real destination');
      }

      // Check for suspicious TLD
      for (const tld of this.suspiciousTLDs) {
        if (urlObj.hostname.endsWith(tld)) {
          analysis.details.hasSuspiciousTLD = true;
          analysis.riskScore += 30;
          analysis.reasons.push(`Suspicious domain extension: ${tld}`);
          break;
        }
      }

      // Check for phishing keywords
      const urlLower = url.toLowerCase();
      for (const keyword of this.phishingKeywords) {
        if (urlLower.includes(keyword)) {
          analysis.details.hasPhishingKeywords = true;
          analysis.riskScore += 20;
          analysis.reasons.push(`Suspicious keyword in URL: "${keyword}"`);
          break;
        }
      }

      // Check for typosquatting of popular domains
      const typosquatting = this.checkTyposquatting(urlObj.hostname);
      if (typosquatting) {
        analysis.riskScore += 50;
        analysis.reasons.push(`Possible typosquatting: looks like "${typosquatting}"`);
      }

      // Determine risk level
      if (analysis.riskScore >= 50) {
        analysis.riskLevel = 'dangerous';
      } else if (analysis.riskScore >= 20) {
        analysis.riskLevel = 'suspicious';
      } else if (analysis.riskScore === 0) {
        analysis.riskLevel = 'safe';
      } else {
        analysis.riskLevel = 'unknown';
      }

    } catch (error) {
      // Invalid URL
      analysis.riskLevel = 'dangerous';
      analysis.riskScore = 100;
      analysis.reasons.push('Malformed URL');
    }

    // Cache the result
    this.linkCache.set(url, analysis);
    return analysis;
  }

  /**
   * Check if domain is a URL shortener
   */
  isShortener(hostname) {
    return this.urlShorteners.some(shortener =>
      hostname.includes(shortener)
    );
  }

  /**
   * Check for typosquatting of popular domains
   */
  checkTyposquatting(hostname) {
    const commonTargets = [
      { real: 'google.com', fake: ['gogle.com', 'googel.com', 'g00gle.com'] },
      { real: 'paypal.com', fake: ['paypa1.com', 'paypai.com', 'paypa.com'] },
      { real: 'microsoft.com', fake: ['micros0ft.com', 'microsft.com'] },
      { real: 'amazon.com', fake: ['amaz0n.com', 'amazom.com'] },
      { real: 'njit.edu', fake: ['njit.com', 'njit-edu.com', 'nj1t.edu'] }
    ];

    for (const target of commonTargets) {
      if (target.fake.some(fake => hostname.includes(fake))) {
        return target.real;
      }
    }

    return null;
  }

  /**
   * Calculate overall link risk
   */
  calculateLinkRisk(results) {
    if (results.totalLinks === 0) return 0;

    const dangerousWeight = results.dangerousLinks.length * 50;
    const suspiciousWeight = results.suspiciousLinks.length * 20;
    const unknownWeight = results.unknownLinks.length * 10;

    const totalRisk = dangerousWeight + suspiciousWeight + unknownWeight;
    return Math.min(totalRisk, 100);
  }

  /**
   * Highlight links in email body
   * @param {HTMLElement} emailBody - Email body element
   * @param {Object} linkAnalysis - Results from analyzeLinks
   */
  async highlightLinks(emailBody, linkAnalysis) {
    if (!emailBody) return;

    // Find all links in the email
    const linkElements = emailBody.querySelectorAll('a[href]');

    for (const linkElement of linkElements) {
      const href = linkElement.getAttribute('href');
      if (!href || !href.startsWith('http')) continue;

      // Find analysis for this link
      const analysis = this.findLinkAnalysis(href, linkAnalysis);

      if (analysis) {
        this.applyLinkStyling(linkElement, analysis);
      }
    }
  }

  /**
   * Find link analysis from results
   */
  findLinkAnalysis(url, linkAnalysis) {
    const allLinks = [
      ...linkAnalysis.safeLinks,
      ...linkAnalysis.suspiciousLinks,
      ...linkAnalysis.dangerousLinks,
      ...linkAnalysis.unknownLinks
    ];

    return allLinks.find(link => link.url === url);
  }

  /**
   * Apply visual styling to link element
   */
  applyLinkStyling(linkElement, analysis) {
    // Add safety indicator class
    linkElement.classList.add('caughtin4k-link-analyzed');
    linkElement.classList.add(`caughtin4k-link-${analysis.riskLevel}`);

    // Create tooltip with details
    const tooltip = this.createLinkTooltip(analysis);
    linkElement.setAttribute('data-caughtin4k-tooltip', tooltip);

    // Add visual indicator icon
    const indicator = document.createElement('span');
    indicator.className = 'caughtin4k-link-indicator';
    indicator.innerHTML = this.getLinkIcon(analysis.riskLevel);
    indicator.title = tooltip;

    // Insert indicator after link
    linkElement.insertAdjacentElement('afterend', indicator);

    // Add hover event for tooltip
    linkElement.addEventListener('mouseenter', (e) => {
      this.showTooltip(e.target, analysis);
    });

    linkElement.addEventListener('mouseleave', () => {
      this.hideTooltip();
    });
  }

  /**
   * Create tooltip text for link
   */
  createLinkTooltip(analysis) {
    let tooltip = `🔗 Link Safety: ${analysis.riskLevel.toUpperCase()}\n`;
    tooltip += `Risk Score: ${analysis.riskScore}/100\n\n`;

    if (analysis.reasons.length > 0) {
      tooltip += 'Issues:\n' + analysis.reasons.map(r => `• ${r}`).join('\n');
    } else {
      tooltip += '✓ No issues detected';
    }

    return tooltip;
  }

  /**
   * Get icon for link risk level
   */
  getLinkIcon(riskLevel) {
    switch(riskLevel) {
      case 'safe':
        return '🟢';
      case 'suspicious':
        return '🟡';
      case 'dangerous':
        return '🔴';
      default:
        return '⚪';
    }
  }

  /**
   * Show tooltip popup
   */
  showTooltip(element, analysis) {
    // Remove any existing tooltip
    this.hideTooltip();

    const tooltip = document.createElement('div');
    tooltip.id = 'caughtin4k-link-tooltip';
    tooltip.className = `link-tooltip risk-${analysis.riskLevel}`;

    let content = `
      <div class="tooltip-header">
        <span class="tooltip-icon">${this.getLinkIcon(analysis.riskLevel)}</span>
        <strong>${analysis.riskLevel.toUpperCase()}</strong>
        <span class="tooltip-score">${analysis.riskScore}/100</span>
      </div>
      <div class="tooltip-url">${analysis.displayUrl}</div>
    `;

    if (analysis.reasons.length > 0) {
      content += '<div class="tooltip-reasons"><strong>Issues:</strong><ul>';
      analysis.reasons.forEach(reason => {
        content += `<li>${reason}</li>`;
      });
      content += '</ul></div>';
    } else {
      content += '<div class="tooltip-safe">✓ No security issues detected</div>';
    }

    tooltip.innerHTML = content;
    document.body.appendChild(tooltip);

    // Position tooltip near the link
    const rect = element.getBoundingClientRect();
    tooltip.style.position = 'fixed';
    tooltip.style.top = `${rect.bottom + 5}px`;
    tooltip.style.left = `${rect.left}px`;
  }

  /**
   * Hide tooltip
   */
  hideTooltip() {
    const existing = document.getElementById('caughtin4k-link-tooltip');
    if (existing) {
      existing.remove();
    }
  }

  /**
   * Truncate URL for display
   */
  truncateUrl(url, maxLength = 50) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.linkCache.clear();
  }
}

// Export to window for content script access
if (typeof window !== 'undefined') {
  window.LinkAnalyzer = LinkAnalyzer;
}
