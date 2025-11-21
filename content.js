/**
 * Content Script - Gmail Integration
 * Monitors Gmail for opened emails and performs scam detection
 */

// Initialize detectors
let scamDetector = null;
let claudeAPI = null;
let lastCheckedEmailId = null;
let isProcessing = false;

// Initialize on load
function initialize() {
  scamDetector = new ScamDetector();
  claudeAPI = new ClaudeAPI();

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

    // Show warning if probability >= 30%
    if (localResults.probability >= 30) {
      displayWarning(emailData, localResults, null);
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
            displayWarning(emailData, combinedResults, aiResults);
          } else {
            removeWarning();
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
function displayWarning(emailData, results, aiResults) {
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
        <strong>AI Analysis:</strong>
        <p>${aiResults.reasoning}</p>
        ${aiResults.redFlags.length > 0 ? `
          <div><strong>Red Flags:</strong> ${aiResults.redFlags.join(', ')}</div>
        ` : ''}
        <div class="ai-confidence">Confidence: ${aiResults.confidence}%</div>
      </div>
    `;
  }

  // Add action buttons
  content += `
    <div class="warning-actions">
      <button class="btn-delete" title="Delete this email">🗑️ Delete Email</button>
      <button class="btn-report" title="Report as spam">🚫 Report Spam</button>
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
