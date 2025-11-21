/**
 * Background Service Worker
 * Handles badge updates and Claude API calls to avoid CORS issues
 */

// Initialize statistics on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['scamStats'], (result) => {
    if (!result.scamStats) {
      const initialStats = {
        totalScanned: 0,
        scamsDetected: 0,
        recentScans: []
      };
      chrome.storage.local.set({ scamStats: initialStats });
    }
  });
});

// Listen for messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'updateBadge') {
    updateBadge(request.probability, sender.tab.id);
    sendResponse({ success: true });
  } else if (request.type === 'analyzeWithClaude') {
    // Handle Claude API call asynchronously
    handleClaudeAnalysis(request.emailData, request.apiKey)
      .then(sendResponse)
      .catch(error => {
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep channel open for async response
  } else if (request.type === 'apiKeyUpdated') {
    // Broadcast to all Gmail tabs
    chrome.tabs.query({ url: 'https://mail.google.com/*' }, (tabs) => {
      tabs.forEach(tab => {
        chrome.tabs.sendMessage(tab.id, { type: 'apiKeyUpdated' }).catch(() => {
          // Ignore errors if content script not ready
        });
      });
    });
    sendResponse({ success: true });
  }
  return true;
});

/**
 * Update extension badge with scam probability
 */
function updateBadge(probability, tabId) {
  const text = probability >= 30 ? `${Math.round(probability)}%` : '';
  const color = getBadgeColor(probability);

  chrome.action.setBadgeText({ text: text, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
}

/**
 * Get badge color based on risk level
 */
function getBadgeColor(probability) {
  if (probability < 30) return '#4CAF50'; // Green
  if (probability < 50) return '#FF9800'; // Orange
  if (probability < 70) return '#F44336'; // Red
  return '#B71C1C'; // Dark Red
}

/**
 * Handle Claude AI analysis request
 */
async function handleClaudeAnalysis(emailData, apiKey) {
  try {
    const prompt = buildPrompt(emailData);

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true'
      },
      body: JSON.stringify({
        model: 'claude-3-5-sonnet-20240620',
        max_tokens: 1024,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Claude API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();

    // Extract JSON from Claude's response
    const content = data.content[0].text;
    const jsonMatch = content.match(/\{[\s\S]*\}/);

    if (!jsonMatch) {
      throw new Error('Failed to parse Claude response');
    }

    const analysis = JSON.parse(jsonMatch[0]);

    return {
      success: true,
      probability: analysis.probability || 0,
      riskLevel: analysis.riskLevel || 'safe',
      redFlags: analysis.redFlags || [],
      reasoning: analysis.reasoning || '',
      confidence: analysis.confidence || 0
    };
  } catch (error) {
    console.error('Claude API error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Build prompt for Claude analysis
 */
function buildPrompt(emailData) {
  return `You are an expert email security analyst. Analyze the following email for phishing and scam indicators.

Email Details:
- Subject: ${emailData.subject}
- From: ${emailData.sender}
- Body: ${emailData.body.substring(0, 2000)} ${emailData.body.length > 2000 ? '...' : ''}
${emailData.links && emailData.links.length > 0 ? `- Links: ${emailData.links.slice(0, 10).join(', ')}` : ''}

Please analyze this email and respond with a JSON object containing:
{
  "probability": <number 0-100 representing scam likelihood>,
  "riskLevel": <"safe", "medium", "high", or "critical">,
  "redFlags": [<array of specific red flags found>],
  "reasoning": "<brief explanation of your assessment>",
  "confidence": <number 0-100 representing confidence in assessment>
}

Focus on:
- Sender legitimacy and domain authenticity
- Urgency tactics and psychological manipulation
- Requests for sensitive information
- Suspicious links or attachments
- Grammar and formatting issues
- Impersonation attempts
- Financial scam indicators

Respond ONLY with the JSON object, no additional text.`;
}
