/**
 * ScamDetector - Local pattern-based scam email detection
 * Analyzes emails using multiple detection categories with weighted scoring
 */
class ScamDetector {
  constructor() {
    // Detection patterns organized by category with weights
    this.patterns = {
      urgency: {
        weight: 15,
        keywords: [
          'urgent', 'immediately', 'act now', 'expire', 'expires soon',
          'limited time', 'act fast', 'don\'t delay', 'hurry', 'quick action',
          'time sensitive', 'expires today', 'last chance', 'final notice'
        ]
      },
      money: {
        weight: 20,
        keywords: [
          'you\'ve won', 'lottery', 'prize', 'claim your', 'wire transfer',
          'bank account', 'credit card', 'payment required', 'refund',
          'tax refund', 'inheritance', 'million dollars', 'cash prize',
          'unclaimed funds', 'send money', 'processing fee', 'transfer funds'
        ]
      },
      requests: {
        weight: 25,
        keywords: [
          'verify account', 'confirm identity', 'update information',
          'reset password', 'click here', 'download attachment',
          'open attachment', 'provide details', 'social security',
          'account details', 'personal information', 'banking details',
          'credit card number', 'verification required'
        ]
      },
      impersonation: {
        weight: 20,
        keywords: [
          'dear customer', 'dear user', 'dear member', 'valued customer',
          'account holder', 'njit admin', 'it department', 'security team',
          'support team', 'billing department', 'customer service',
          'technical support', 'helpdesk'
        ]
      },
      threats: {
        weight: 15,
        keywords: [
          'account suspended', 'account closed', 'legal action',
          'lawsuit', 'suspended', 'terminated', 'blocked', 'disabled',
          'unusual activity', 'unauthorized access', 'security alert',
          'fraud alert', 'take action', 'consequences'
        ]
      },
      suspicious: {
        weight: 5,
        keywords: [
          'congratulations', 'selected', 'winner', 'free', 'no cost',
          'risk-free', 'guarantee', 'exclusive offer', 'special promotion',
          'limited offer', 'act today', 'call now', 'click below'
        ]
      }
    };

    // Legitimate NJIT domains
    this.legitimateDomains = [
      'njit.edu',
      'highlander.njit.edu',
      'ucm.njit.edu',
      'ist.njit.edu'
    ];

    // Suspicious TLDs
    this.suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc'];

    // URL shorteners
    this.urlShorteners = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
      'tiny.cc', 'is.gd', 'buff.ly', 'adf.ly'
    ];
  }

  /**
   * Main analysis method - analyzes email and returns scam assessment
   * @param {Object} emailData - {subject, sender, body, links}
   * @returns {Object} Analysis results
   */
  analyze(emailData) {
    const results = {
      isScam: false,
      probability: 0,
      riskLevel: 'safe',
      detectedPatterns: [],
      timestamp: new Date().toISOString()
    };

    let totalScore = 0;

    // Analyze content patterns
    const content = `${emailData.subject} ${emailData.body}`.toLowerCase();

    for (const [category, config] of Object.entries(this.patterns)) {
      const matches = this.findMatches(content, config.keywords);
      if (matches.length > 0) {
        totalScore += config.weight;
        results.detectedPatterns.push({
          category: category,
          matches: matches,
          severity: config.weight
        });
      }
    }

    // Analyze sender
    const senderAnalysis = this.analyzeSender(emailData.sender);
    if (senderAnalysis.suspicious) {
      totalScore += 15;
      results.detectedPatterns.push({
        category: 'sender',
        matches: [senderAnalysis.reason],
        severity: 15
      });
    }

    // Analyze links
    if (emailData.links && emailData.links.length > 0) {
      const linkAnalysis = this.analyzeLinks(emailData.links);
      if (linkAnalysis.suspicious) {
        totalScore += 10;
        results.detectedPatterns.push({
          category: 'links',
          matches: linkAnalysis.reasons,
          severity: 10
        });
      }
    }

    // Grammar and formatting checks
    const grammarIssues = this.checkGrammar(emailData.subject, emailData.body);
    if (grammarIssues.length > 0) {
      totalScore += 5;
      results.detectedPatterns.push({
        category: 'grammar',
        matches: grammarIssues,
        severity: 5
      });
    }

    // Calculate final probability (cap at 100)
    results.probability = Math.min(totalScore, 100);
    results.isScam = results.probability >= 30;
    results.riskLevel = this.getRiskLevel(results.probability);

    return results;
  }

  /**
   * Find matching keywords in content
   */
  findMatches(content, keywords) {
    const matches = [];
    for (const keyword of keywords) {
      if (content.includes(keyword.toLowerCase())) {
        matches.push(keyword);
      }
    }
    return matches;
  }

  /**
   * Analyze sender email address for suspicious patterns
   */
  analyzeSender(sender) {
    const result = { suspicious: false, reason: '' };

    if (!sender) {
      return result;
    }

    const senderLower = sender.toLowerCase();

    // Check for legitimate NJIT domains
    const isLegitimate = this.legitimateDomains.some(domain =>
      senderLower.includes(domain)
    );

    if (isLegitimate) {
      return result;
    }

    // Check for typosquatting (njit- or -njit patterns)
    if (senderLower.includes('njit-') || senderLower.includes('-njit')) {
      result.suspicious = true;
      result.reason = 'Potential NJIT domain typosquatting';
      return result;
    }

    // Check for suspicious TLDs
    for (const tld of this.suspiciousTLDs) {
      if (senderLower.endsWith(tld)) {
        result.suspicious = true;
        result.reason = `Suspicious TLD: ${tld}`;
        return result;
      }
    }

    return result;
  }

  /**
   * Analyze links for suspicious patterns
   */
  analyzeLinks(links) {
    const result = { suspicious: false, reasons: [] };

    for (const link of links) {
      const linkLower = link.toLowerCase();

      // Check for IP addresses instead of domains
      if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)) {
        result.suspicious = true;
        result.reasons.push('Link contains IP address instead of domain');
      }

      // Check for URL shorteners
      for (const shortener of this.urlShorteners) {
        if (linkLower.includes(shortener)) {
          result.suspicious = true;
          result.reasons.push(`URL shortener detected: ${shortener}`);
        }
      }

      // Check for fake NJIT domains
      if (linkLower.includes('njit') &&
          !this.legitimateDomains.some(domain => linkLower.includes(domain))) {
        result.suspicious = true;
        result.reasons.push('Fake NJIT domain link');
      }
    }

    return result;
  }

  /**
   * Check for grammar and formatting issues
   */
  checkGrammar(subject, body) {
    const issues = [];
    const combined = `${subject} ${body}`;

    // Multiple exclamation marks
    if (/!{2,}/.test(combined)) {
      issues.push('Multiple exclamation marks');
    }

    // Excessive caps (more than 30% of text)
    const capsCount = (combined.match(/[A-Z]/g) || []).length;
    const totalLetters = (combined.match(/[a-zA-Z]/g) || []).length;
    if (totalLetters > 0 && (capsCount / totalLetters) > 0.3) {
      issues.push('Excessive use of capital letters');
    }

    // Multiple spaces or poor formatting
    if (/\s{3,}/.test(combined)) {
      issues.push('Poor formatting (excessive spacing)');
    }

    return issues;
  }

  /**
   * Determine risk level based on probability
   */
  getRiskLevel(probability) {
    if (probability < 30) return 'safe';
    if (probability < 50) return 'medium';
    if (probability < 70) return 'high';
    return 'critical';
  }
}

// Export to window for content script access
if (typeof window !== 'undefined') {
  window.ScamDetector = ScamDetector;
}
