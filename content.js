/**
 * Content Script - Gmail Integration
 * Monitors Gmail for opened emails and performs scam detection
 */

// Initialize detectors
let scamDetector = null;
let claudeAPI = null;
let headerAnalyzer = null;
let linkAnalyzer = null;
let lastCheckedEmailId = null;
let isProcessing = false;

// Initialize on load
function initialize() {
  scamDetector = new ScamDetector();
  claudeAPI = new ClaudeAPI();
  headerAnalyzer = new EmailHeaderAnalyzer();
  linkAnalyzer = new LinkAnalyzer();

  // Start monitoring Gmail
  startMonitoring();

  // Listen for API key updates
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'apiKeyUpdated') {
      // Reinitialize Claude API
      claudeAPI = new ClaudeAPI();
    }
  });
}

/**
 * Start monitoring Gmail for email changes
 */
function startMonitoring() {
  // Check every 3 seconds
  setInterval(() => {
    checkForOpenEmail();
  }, 3000);

  // Also observe DOM changes
  const observer = new MutationObserver(() => {
    checkForOpenEmail();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

/**
 * Check if an email is currently open
 */
async function checkForOpenEmail() {
  if (isProcessing) return;

  try {
    const emailData = extractEmailData();

    if (!emailData) {
      lastCheckedEmailId = null;
      return;
    }

    // Create unique ID for this email
    const emailId = `${emailData.sender}-${emailData.subject}`;

    // Skip if we already analyzed this email
    if (emailId === lastCheckedEmailId) {
      return;
    }

    lastCheckedEmailId = emailId;
    isProcessing = true;

    // Remove any existing warning
    removeWarning();

    // Run local analysis first (instant)
    const localResults = scamDetector.analyze(emailData);

    // Run header analysis
    const headerResults = await headerAnalyzer.analyze(emailData.sender);

    // Run link analysis
    const linkResults = await linkAnalyzer.analyzeLinks(emailData.links || []);

    // Combine all risk scores
    const combinedScore = Math.round(
      (localResults.probability * 0.5) +
      (headerResults.overallRisk * 0.3) +
      (linkResults.overallRisk * 0.2)
    );

    localResults.probability = Math.min(combinedScore, 100);
    localResults.riskLevel = scamDetector.getRiskLevel(localResults.probability);

    // Show warning if probability >= 30%
    if (localResults.probability >= 30) {
      displayWarning(emailData, localResults, null, headerResults, linkResults);
    }

    // Highlight links in email body
    const emailBody = document.querySelector('.a3s.aiL') ||
                      document.querySelector('[data-message-id] .ii.gt');
    if (emailBody && linkResults.totalLinks > 0) {
      await linkAnalyzer.highlightLinks(emailBody, linkResults);
    }

    // Update badge
    chrome.runtime.sendMessage({
      type: 'updateBadge',
      probability: localResults.probability
    });

    // Save to statistics
    await updateStatistics(emailData, localResults);

    // Try AI analysis if available (async)
    if (claudeAPI.isConfigured()) {
      try {
        const aiResults = await claudeAPI.analyzeEmail(emailData);

        if (aiResults.success) {
          // Combine results: 40% local, 60% AI
          const combinedProbability = Math.round(
            (localResults.probability * 0.4) + (aiResults.probability * 0.6)
          );

          const combinedResults = {
            ...localResults,
            probability: combinedProbability,
            riskLevel: scamDetector.getRiskLevel(combinedProbability),
            aiEnhanced: true
          };

          // Update warning with AI results
          if (combinedProbability >= 30) {
            displayWarning(emailData, combinedResults, aiResults, headerResults, linkResults);
          } else {
            removeWarning();
          }

          // Re-highlight links (in case they were removed)
          if (emailBody && linkResults.totalLinks > 0) {
            await linkAnalyzer.highlightLinks(emailBody, linkResults);
          }

          // Update badge with combined results
          chrome.runtime.sendMessage({
            type: 'updateBadge',
            probability: combinedProbability
          });

          // Update statistics with final results
          await updateStatistics(emailData, combinedResults);
        }
      } catch (error) {
        console.error('AI analysis failed:', error);
      }
    }
  } catch (error) {
    console.error('Error checking email:', error);
  } finally {
    isProcessing = false;
  }
}

/**
 * Extract email data from Gmail DOM
 * Uses multiple selector strategies for reliability
 */
function extractEmailData() {
  // Check if an email is open
  const emailView = document.querySelector('[role="main"]');
  if (!emailView) return null;

  // Extract subject (try multiple selectors)
  let subject = '';
  const subjectSelectors = [
    'h2[data-legacy-message-id]',
    'h2.hP',
    '[role="main"] h2'
  ];

  for (const selector of subjectSelectors) {
    const element = document.querySelector(selector);
    if (element && element.textContent.trim()) {
      subject = element.textContent.trim();
      break;
    }
  }

  if (!subject) return null;

  // Extract sender
  let sender = '';
  const senderSelectors = [
    'span.gD[email]',
    '[email]',
    '.go'
  ];

  for (const selector of senderSelectors) {
    const element = document.querySelector(selector);
    if (element) {
      sender = element.getAttribute('email') || element.textContent.trim();
      if (sender) break;
    }
  }

  // Extract body
  let body = '';
  const bodySelectors = [
    '.a3s.aiL',
    '[data-message-id] .ii.gt',
    '.ii.gt',
    '[role="main"] [dir="ltr"]'
  ];

  for (const selector of bodySelectors) {
    const element = document.querySelector(selector);
    if (element && element.textContent.trim()) {
      body = element.textContent.trim();
      break;
    }
  }

  // Extract links
  const links = [];
  const linkElements = document.querySelectorAll('[role="main"] a[href^="http"]');
  linkElements.forEach(link => {
    const href = link.getAttribute('href');
    if (href && !links.includes(href)) {
      links.push(href);
    }
  });

  return {
    subject: subject,
    sender: sender,
    body: body.substring(0, 5000), // Limit body length
    links: links.slice(0, 20) // Limit links
  };
}

/**
 * Display warning banner
 */
function displayWarning(emailData, results, aiResults, headerResults, linkResults) {
  // Remove existing warning
  removeWarning();

  const warning = document.createElement('div');
  warning.id = 'caughtin4k-warning';
  warning.className = `scam-warning risk-${results.riskLevel}`;

  // Build warning content
  let content = `
    <div class="warning-header">
      <div class="warning-title">
        <span class="warning-icon">⚠️</span>
        <strong>POTENTIAL SCAM DETECTED</strong>
        ${results.aiEnhanced ? '<span class="ai-badge">AI Enhanced</span>' : ''}
      </div>
      <div class="warning-probability">${results.probability}% Scam Probability</div>
    </div>
    <div class="warning-body">
      <div class="warning-section">
        <strong>Risk Level:</strong> <span class="risk-badge">${results.riskLevel.toUpperCase()}</span>
      </div>
  `;

  // Add detected patterns
  if (results.detectedPatterns.length > 0) {
    content += '<div class="warning-section"><strong>Detected Issues:</strong><ul>';
    results.detectedPatterns.forEach(pattern => {
      content += `<li><strong>${pattern.category}:</strong> ${pattern.matches.join(', ')}</li>`;
    });
    content += '</ul></div>';
  }

  // Add AI reasoning if available
  if (aiResults && aiResults.reasoning) {
    content += `
      <div class="warning-section ai-section">
        <div class="ai-header">
          <strong>🤖 Claude AI Analysis</strong>
          ${aiResults.model ? `<span class="ai-model">${aiResults.model}</span>` : ''}
        </div>
        <div class="ai-reasoning">
          <strong>Assessment:</strong>
          <p>${aiResults.reasoning}</p>
        </div>
        ${aiResults.redFlags.length > 0 ? `
          <div class="ai-red-flags">
            <strong>🚩 Red Flags Detected:</strong>
            <ul>
              ${aiResults.redFlags.map(flag => `<li>${flag}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
        ${aiResults.chainOfThought ? `
          <div class="chain-of-thought">
            <div class="section-header" onclick="this.parentElement.classList.toggle('expanded')">
              <strong>🧠 AI Chain-of-Thought Reasoning</strong>
              <span class="expand-icon">▼</span>
            </div>
            <div class="section-content">
              <div class="thought-item">
                <strong>Sender Analysis:</strong>
                <p>${aiResults.chainOfThought.senderAnalysis}</p>
              </div>
              <div class="thought-item">
                <strong>Content Analysis:</strong>
                <p>${aiResults.chainOfThought.contentAnalysis}</p>
              </div>
              <div class="thought-item">
                <strong>Link Analysis:</strong>
                <p>${aiResults.chainOfThought.linkAnalysis}</p>
              </div>
              <div class="thought-item">
                <strong>Context Analysis:</strong>
                <p>${aiResults.chainOfThought.contextAnalysis}</p>
              </div>
            </div>
          </div>
        ` : ''}
        <div class="ai-confidence">
          <span class="confidence-label">AI Confidence:</span>
          <div class="confidence-bar">
            <div class="confidence-fill" style="width: ${aiResults.confidence}%"></div>
          </div>
          <span class="confidence-value">${aiResults.confidence}%</span>
        </div>
      </div>
    `;
  }

  // Add header analysis section
  if (headerResults) {
    content += `
      <div class="warning-section header-section">
        <div class="section-header" onclick="this.parentElement.classList.toggle('expanded')">
          <strong>🔒 Email Authentication & Headers</strong>
          <span class="expand-icon">▼</span>
        </div>
        <div class="section-content">
          <div class="auth-grid">
            <div class="auth-item">
              <span class="auth-label">SPF:</span>
              <span class="auth-value ${headerAnalyzer.getStatusClass(headerResults.authentication.spf.status)}">
                ${headerAnalyzer.getStatusIcon(headerResults.authentication.spf.status)} ${headerResults.authentication.spf.status.toUpperCase()}
              </span>
              <div class="auth-detail">${headerResults.authentication.spf.details}</div>
            </div>
            <div class="auth-item">
              <span class="auth-label">DKIM:</span>
              <span class="auth-value ${headerAnalyzer.getStatusClass(headerResults.authentication.dkim.status)}">
                ${headerAnalyzer.getStatusIcon(headerResults.authentication.dkim.status)} ${headerResults.authentication.dkim.status.toUpperCase()}
              </span>
              <div class="auth-detail">${headerResults.authentication.dkim.details}</div>
            </div>
            <div class="auth-item">
              <span class="auth-label">DMARC:</span>
              <span class="auth-value ${headerAnalyzer.getStatusClass(headerResults.authentication.dmarc.status)}">
                ${headerAnalyzer.getStatusIcon(headerResults.authentication.dmarc.status)} ${headerResults.authentication.dmarc.status.toUpperCase()}
              </span>
              <div class="auth-detail">${headerResults.authentication.dmarc.details}</div>
            </div>
          </div>
          ${headerResults.sender.ip ? `
            <div class="sender-info">
              <strong>Sender IP:</strong> ${headerResults.sender.ip}
              ${headerResults.sender.country ? `
                <span class="sender-location ${headerResults.sender.isSuspicious ? 'suspicious' : ''}">
                  📍 ${headerResults.sender.country} ${headerResults.sender.isSuspicious ? '⚠️ Suspicious' : ''}
                </span>
              ` : ''}
            </div>
          ` : ''}
          ${headerResults.spoofing.displayNameMismatch ? `
            <div class="spoofing-alert">
              ⚠️ <strong>Display Name Spoofing Detected!</strong><br>
              ${headerResults.spoofing.details}
            </div>
          ` : ''}
        </div>
      </div>
    `;
  }

  // Add link analysis section
  if (linkResults && linkResults.totalLinks > 0) {
    content += `
      <div class="warning-section link-section">
        <div class="section-header" onclick="this.parentElement.classList.toggle('expanded')">
          <strong>🔗 Link Analysis (${linkResults.totalLinks} links)</strong>
          <span class="expand-icon">▼</span>
        </div>
        <div class="section-content">
          <div class="link-summary">
            ${linkResults.safeLinks.length > 0 ? `<span class="link-stat safe">🟢 ${linkResults.safeLinks.length} Safe</span>` : ''}
            ${linkResults.suspiciousLinks.length > 0 ? `<span class="link-stat suspicious">🟡 ${linkResults.suspiciousLinks.length} Suspicious</span>` : ''}
            ${linkResults.dangerousLinks.length > 0 ? `<span class="link-stat dangerous">🔴 ${linkResults.dangerousLinks.length} Dangerous</span>` : ''}
          </div>
          ${linkResults.dangerousLinks.length > 0 ? `
            <div class="dangerous-links">
              <strong>⚠️ Dangerous Links Found:</strong>
              <ul>
                ${linkResults.dangerousLinks.slice(0, 3).map(link => `
                  <li>
                    <div class="link-url">${link.displayUrl}</div>
                    <div class="link-reasons">${link.reasons.join(', ')}</div>
                  </li>
                `).join('')}
              </ul>
            </div>
          ` : ''}
          ${linkResults.suspiciousLinks.length > 0 && linkResults.dangerousLinks.length === 0 ? `
            <div class="suspicious-links">
              <strong>Suspicious Links:</strong>
              <ul>
                ${linkResults.suspiciousLinks.slice(0, 3).map(link => `
                  <li>${link.displayUrl} - ${link.reasons[0]}</li>
                `).join('')}
              </ul>
            </div>
          ` : ''}
          <div class="link-note">💡 Links in the email are color-coded for safety</div>
        </div>
      </div>
    `;
  }

  // Add action buttons
  content += `
    <div class="warning-actions">
      <button class="btn-delete" title="Delete this email">🗑️ Delete Email</button>
      <button class="btn-report" title="Report as spam">🚫 Report Spam</button>
      ${results.probability > 40 ? '<button class="btn-notify-njit" title="Notify NJIT IST Service Desk">🚨 Notify NJIT</button>' : ''}
      <button class="btn-dismiss" title="Dismiss this warning">✕ Dismiss</button>
    </div>
  `;

  content += '</div>';
  warning.innerHTML = content;

  // Add event listeners
  warning.querySelector('.btn-delete').addEventListener('click', () => {
    deleteEmail();
  });

  warning.querySelector('.btn-report').addEventListener('click', () => {
    reportSpam();
  });

  // Add NJIT notification button listener if present
  if (results.probability > 40) {
    warning.querySelector('.btn-notify-njit').addEventListener('click', () => {
      notifyNJIT(emailData, results, aiResults);
    });
  }

  warning.querySelector('.btn-dismiss').addEventListener('click', () => {
    removeWarning();
  });

  // Insert warning at top of email
  const emailView = document.querySelector('[role="main"]');
  if (emailView) {
    emailView.insertBefore(warning, emailView.firstChild);
  }
}

/**
 * Remove warning banner
 */
function removeWarning() {
  const existing = document.getElementById('caughtin4k-warning');
  if (existing) {
    existing.remove();
  }
}

/**
 * Delete email action
 */
function deleteEmail() {
  // Find and click Gmail's delete button
  const deleteButton = document.querySelector('[data-tooltip="Delete"], [aria-label*="Delete"]');
  if (deleteButton) {
    deleteButton.click();
    removeWarning();
  } else {
    alert('Could not find delete button. Please delete manually.');
  }
}

/**
 * Report spam action
 */
function reportSpam() {
  // Find and click Gmail's report spam button
  const reportButton = document.querySelector('[data-tooltip*="spam"], [aria-label*="spam" i]');
  if (reportButton) {
    reportButton.click();
    removeWarning();
  } else {
    alert('Could not find report spam button. Please report manually.');
  }
}

/**
 * Notify NJIT IST Service Desk
 */
async function notifyNJIT(emailData, results, aiResults) {
  try {
    // Disable button and show loading state
    const notifyBtn = document.querySelector('.btn-notify-njit');
    if (notifyBtn) {
      notifyBtn.disabled = true;
      notifyBtn.innerHTML = '⏳ Generating Alert...';
    }

    // Check if Claude API is configured
    if (!claudeAPI.isConfigured()) {
      // Generate basic alert without AI
      const subject = encodeURIComponent('SCAM ALERT: Potential Phishing Email Detected');
      const body = encodeURIComponent(
        `Dear NJIT IST Service Desk,\n\n` +
        `I am reporting a potential scam/phishing email that I received. Please alert other students to prevent anyone from getting scammed.\n\n` +
        `SCAM EMAIL DETAILS:\n` +
        `- Subject: ${emailData.subject}\n` +
        `- Sender: ${emailData.sender}\n` +
        `- Scam Probability: ${results.probability}%\n` +
        `- Risk Level: ${results.riskLevel.toUpperCase()}\n\n` +
        `DETECTED ISSUES:\n` +
        results.detectedPatterns.map(p => `- ${p.category}: ${p.matches.join(', ')}`).join('\n') +
        `\n\nPlease investigate this email and warn other students if it is indeed a scam.\n\n` +
        `Thank you,\n` +
        `NJIT Student\n\n` +
        `---\n` +
        `This alert was automatically generated by Caughtin4KNJIT Gmail Scam Detector`
      );

      // Open mailto link to NJIT IST Service Desk
      window.location.href = `mailto:kathayatsubodh@gmail.com?subject=${subject}&body=${body}`;

      // Re-enable button
      if (notifyBtn) {
        notifyBtn.disabled = false;
        notifyBtn.innerHTML = '✅ Email Opened';
        setTimeout(() => {
          notifyBtn.innerHTML = '🚨 Notify NJIT';
        }, 3000);
      }
      return;
    }

    // Use AI to generate personalized alert
    const alertEmail = await claudeAPI.generateAlertEmail(emailData, {
      probability: results.probability,
      riskLevel: results.riskLevel,
      detectedPatterns: results.detectedPatterns,
      aiResults: aiResults
    });

    if (alertEmail.success) {
      // Encode subject and body for mailto
      const subject = encodeURIComponent(alertEmail.subject);
      const body = encodeURIComponent(alertEmail.body);

      // Open mailto link to NJIT IST Service Desk
      window.location.href = `mailto:kathayatsubodh@gmail.com?subject=${subject}&body=${body}`;

      // Re-enable button with success message
      if (notifyBtn) {
        notifyBtn.disabled = false;
        notifyBtn.innerHTML = '✅ Email Opened';
        setTimeout(() => {
          notifyBtn.innerHTML = '🚨 Notify NJIT';
        }, 3000);
      }
    } else {
      // Fallback to basic alert if AI fails
      console.error('AI alert generation failed:', alertEmail.error);

      const subject = encodeURIComponent('SCAM ALERT: Potential Phishing Email Detected');
      const body = encodeURIComponent(
        `Dear NJIT IST Service Desk,\n\n` +
        `I am reporting a potential scam/phishing email that I received. Please alert other students to prevent anyone from getting scammed.\n\n` +
        `SCAM EMAIL DETAILS:\n` +
        `- Subject: ${emailData.subject}\n` +
        `- Sender: ${emailData.sender}\n` +
        `- Scam Probability: ${results.probability}%\n` +
        `- Risk Level: ${results.riskLevel.toUpperCase()}\n\n` +
        `DETECTED ISSUES:\n` +
        results.detectedPatterns.map(p => `- ${p.category}: ${p.matches.join(', ')}`).join('\n') +
        `\n\nPlease investigate this email and warn other students if it is indeed a scam.\n\n` +
        `Thank you,\n` +
        `NJIT Student\n\n` +
        `---\n` +
        `This alert was automatically generated by Caughtin4KNJIT Gmail Scam Detector`
      );

      window.location.href = `mailto:ServiceDesk@njit.edu?subject=${subject}&body=${body}`;

      if (notifyBtn) {
        notifyBtn.disabled = false;
        notifyBtn.innerHTML = '✅ Email Opened';
        setTimeout(() => {
          notifyBtn.innerHTML = '🚨 Notify NJIT';
        }, 3000);
      }
    }
  } catch (error) {
    console.error('Error notifying NJIT:', error);
    alert('Error generating notification. Please try again or contact IST Service Desk manually at ServiceDesk@njit.edu');

    const notifyBtn = document.querySelector('.btn-notify-njit');
    if (notifyBtn) {
      notifyBtn.disabled = false;
      notifyBtn.innerHTML = '🚨 Notify NJIT';
    }
  }
}

/**
 * Update statistics in storage
 */
async function updateStatistics(emailData, results) {
  try {
    const stats = await chrome.storage.local.get(['scamStats']);
    const scamStats = stats.scamStats || {
      totalScanned: 0,
      scamsDetected: 0,
      recentScans: []
    };

    scamStats.totalScanned++;

    if (results.isScam) {
      scamStats.scamsDetected++;
    }

    // Add to recent scans (keep last 5)
    scamStats.recentScans.unshift({
      subject: emailData.subject.substring(0, 50),
      sender: emailData.sender,
      probability: results.probability,
      riskLevel: results.riskLevel,
      timestamp: new Date().toISOString()
    });

    scamStats.recentScans = scamStats.recentScans.slice(0, 5);

    await chrome.storage.local.set({ scamStats: scamStats });
  } catch (error) {
    console.error('Error updating statistics:', error);
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initialize);
} else {
  initialize();
}
