/**
 * Popup Dashboard - Statistics and Configuration
 */

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
  loadStatistics();
  loadApiKeyStatus();
  setupEventListeners();
});

/**
 * Load and display statistics
 */
async function loadStatistics() {
  try {
    const result = await chrome.storage.local.get(['scamStats']);
    const stats = result.scamStats || {
      totalScanned: 0,
      scamsDetected: 0,
      recentScans: []
    };

    // Update statistics display
    document.getElementById('totalScanned').textContent = stats.totalScanned;
    document.getElementById('scamsDetected').textContent = stats.scamsDetected;

    // Calculate protection rate
    const protectionRate = stats.totalScanned > 0
      ? Math.round((stats.scamsDetected / stats.totalScanned) * 100)
      : 0;
    document.getElementById('protectionRate').textContent = `${protectionRate}%`;

    // Display recent scans
    displayRecentScans(stats.recentScans);
  } catch (error) {
    console.error('Error loading statistics:', error);
  }
}

/**
 * Display recent scans list
 */
function displayRecentScans(scans) {
  const container = document.getElementById('recentScans');

  if (!scans || scans.length === 0) {
    container.innerHTML = '<div class="empty-state">No scans yet. Open an email in Gmail to start!</div>';
    return;
  }

  container.innerHTML = '';

  scans.forEach(scan => {
    const scanItem = document.createElement('div');
    scanItem.className = `scan-item risk-${scan.riskLevel}`;

    const timeAgo = formatTimeAgo(new Date(scan.timestamp));

    scanItem.innerHTML = `
      <div class="scan-subject">${escapeHtml(scan.subject)}</div>
      <div class="scan-details">
        <span>${escapeHtml(scan.sender)}</span>
        <span class="scan-probability">${scan.probability}%</span>
      </div>
      <div class="scan-details">
        <span style="font-size: 10px; opacity: 0.7;">${timeAgo}</span>
        <span style="font-size: 10px; text-transform: uppercase; font-weight: 600;">${scan.riskLevel}</span>
      </div>
    `;

    container.appendChild(scanItem);
  });
}

/**
 * Format timestamp to relative time
 */
function formatTimeAgo(date) {
  const seconds = Math.floor((new Date() - date) / 1000);

  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Load API key status
 */
async function loadApiKeyStatus() {
  try {
    const result = await chrome.storage.local.get(['claudeApiKey']);
    const hasApiKey = !!result.claudeApiKey;

    updateApiKeyUI(hasApiKey);
  } catch (error) {
    console.error('Error loading API key status:', error);
  }
}

/**
 * Update API key UI based on status
 */
function updateApiKeyUI(hasApiKey) {
  const statusIndicator = document.getElementById('aiStatus');
  const statusText = document.getElementById('aiStatusText');
  const removeButton = document.getElementById('removeApiKey');
  const apiKeyInput = document.getElementById('apiKeyInput');

  if (hasApiKey) {
    statusIndicator.className = 'status-indicator status-active';
    statusText.textContent = 'Active';
    removeButton.style.display = 'block';
    apiKeyInput.placeholder = 'API Key configured (hidden for security)';
    apiKeyInput.value = '';
  } else {
    statusIndicator.className = 'status-indicator status-inactive';
    statusText.textContent = 'Not Configured';
    removeButton.style.display = 'none';
    apiKeyInput.placeholder = 'Enter your Claude API key (sk-ant-...)';
    apiKeyInput.value = '';
  }
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
  // Save API key
  document.getElementById('saveApiKey').addEventListener('click', async () => {
    const apiKey = document.getElementById('apiKeyInput').value.trim();

    if (!apiKey) {
      showMessage('Please enter an API key', 'error');
      return;
    }

    if (!apiKey.startsWith('sk-ant-')) {
      showMessage('Invalid API key format. Should start with sk-ant-', 'error');
      return;
    }

    try {
      await chrome.storage.local.set({ claudeApiKey: apiKey });

      // Notify background script and content scripts
      chrome.runtime.sendMessage({ type: 'apiKeyUpdated' });

      updateApiKeyUI(true);
      showMessage('API key saved successfully!', 'success');
      document.getElementById('apiKeyInput').value = '';
    } catch (error) {
      showMessage('Error saving API key: ' + error.message, 'error');
    }
  });

  // Remove API key
  document.getElementById('removeApiKey').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to remove the API key?')) {
      return;
    }

    try {
      await chrome.storage.local.remove(['claudeApiKey']);

      // Notify background script and content scripts
      chrome.runtime.sendMessage({ type: 'apiKeyUpdated' });

      updateApiKeyUI(false);
      showMessage('API key removed successfully', 'success');
    } catch (error) {
      showMessage('Error removing API key: ' + error.message, 'error');
    }
  });

  // Clear statistics
  document.getElementById('clearStats').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to clear all statistics?')) {
      return;
    }

    try {
      const initialStats = {
        totalScanned: 0,
        scamsDetected: 0,
        recentScans: []
      };

      await chrome.storage.local.set({ scamStats: initialStats });
      loadStatistics();
      showMessage('Statistics cleared successfully', 'success');
    } catch (error) {
      showMessage('Error clearing statistics: ' + error.message, 'error');
    }
  });

  // Enter key to save API key
  document.getElementById('apiKeyInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      document.getElementById('saveApiKey').click();
    }
  });

  // Export as JSON
  document.getElementById('exportJSON').addEventListener('click', async () => {
    try {
      const result = await chrome.storage.local.get(['scamStats']);
      const stats = result.scamStats || {
        totalScanned: 0,
        scamsDetected: 0,
        recentScans: []
      };

      const exportData = {
        exportDate: new Date().toISOString(),
        extension: 'Caughtin4KNJIT Gmail Scam Detector',
        version: '2.1.0',
        statistics: stats
      };

      downloadFile(
        JSON.stringify(exportData, null, 2),
        `scam-detector-report-${getFormattedDate()}.json`,
        'application/json'
      );

      showMessage('Report exported successfully!', 'success');
    } catch (error) {
      showMessage('Error exporting data: ' + error.message, 'error');
    }
  });

  // Export as CSV
  document.getElementById('exportCSV').addEventListener('click', async () => {
    try {
      const result = await chrome.storage.local.get(['scamStats']);
      const stats = result.scamStats || {
        totalScanned: 0,
        scamsDetected: 0,
        recentScans: []
      };

      let csv = 'Subject,Sender,Probability,Risk Level,Timestamp\n';

      stats.recentScans.forEach(scan => {
        csv += `"${scan.subject.replace(/"/g, '""')}","${scan.sender.replace(/"/g, '""')}",${scan.probability},${scan.riskLevel},"${scan.timestamp}"\n`;
      });

      // Add summary row
      csv += `\n"Total Scanned","","${stats.totalScanned}","",""\n`;
      csv += `"Scams Detected","","${stats.scamsDetected}","",""\n`;
      csv += `"Detection Rate","","${stats.totalScanned > 0 ? ((stats.scamsDetected / stats.totalScanned) * 100).toFixed(2) : 0}%","",""\n`;

      downloadFile(
        csv,
        `scam-detector-report-${getFormattedDate()}.csv`,
        'text/csv'
      );

      showMessage('Report exported successfully!', 'success');
    } catch (error) {
      showMessage('Error exporting data: ' + error.message, 'error');
    }
  });
}

/**
 * Download file helper
 */
function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Get formatted date for filename
 */
function getFormattedDate() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  return `${year}${month}${day}-${hours}${minutes}`;
}

/**
 * Show message to user
 */
function showMessage(text, type) {
  const message = document.getElementById('apiMessage');
  message.textContent = text;
  message.className = `message ${type} show`;

  setTimeout(() => {
    message.classList.remove('show');
  }, 3000);
}
