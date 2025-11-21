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
  } else if (request.type === 'generateNJITAlert') {
    // Handle NJIT alert email generation
    handleNJITAlertGeneration(request.emailData, request.analysisResults, request.apiKey)
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
  // Try multiple models in order of preference
  const models = [
    'claude-3-5-sonnet-20241022',
    'claude-3-5-sonnet-20240620',
    'claude-3-sonnet-20240229',
    'claude-3-haiku-20240307'
  ];

  let lastError = null;

  for (const model of models) {
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
          model: model,
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
        const error = new Error(`Claude API error with ${model}: ${response.status} - ${errorText}`);

        // If model not found, try next model
        if (response.status === 404 && errorText.includes('not_found_error')) {
          console.log(`Model ${model} not available, trying next...`);
          lastError = error;
          continue;
        }

        throw error;
      }

      const data = await response.json();

      // Extract JSON from Claude's response
      const content = data.content[0].text;
      const jsonMatch = content.match(/\{[\s\S]*\}/);

      if (!jsonMatch) {
        throw new Error('Failed to parse Claude response');
      }

      const analysis = JSON.parse(jsonMatch[0]);

      console.log(`Successfully analyzed with model: ${model}`);

      return {
        success: true,
        probability: analysis.probability || 0,
        riskLevel: analysis.riskLevel || 'safe',
        redFlags: analysis.redFlags || [],
        reasoning: analysis.reasoning || '',
        confidence: analysis.confidence || 0,
        chainOfThought: analysis.chainOfThought || null,
        model: model
      };

    } catch (error) {
      // If not a model-not-found error, throw it
      if (!error.message.includes('not_found_error')) {
        console.error('Claude API error:', error);
        return {
          success: false,
          error: error.message
        };
      }
      lastError = error;
    }
  }

  // If all models failed, return the last error
  console.error('All Claude models failed:', lastError);
  return {
    success: false,
    error: lastError ? lastError.message : 'All models unavailable'
  };
}

/**
 * Handle NJIT alert email generation
 */
async function handleNJITAlertGeneration(emailData, analysisResults, apiKey) {
  const models = [
    'claude-3-5-sonnet-20241022',
    'claude-3-5-sonnet-20240620',
    'claude-3-sonnet-20240229',
    'claude-3-haiku-20240307'
  ];

  let lastError = null;

  for (const model of models) {
    try {
      const prompt = buildNJITAlertPrompt(emailData, analysisResults);

      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true'
        },
        body: JSON.stringify({
          model: model,
          max_tokens: 2048,
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
        const error = new Error(`Claude API error with ${model}: ${response.status} - ${errorText}`);

        if (response.status === 404 && errorText.includes('not_found_error')) {
          console.log(`Model ${model} not available, trying next...`);
          lastError = error;
          continue;
        }

        throw error;
      }

      const data = await response.json();
      const content = data.content[0].text;

      // Extract JSON from Claude's response
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('Failed to parse Claude response');
      }

      const alertData = JSON.parse(jsonMatch[0]);

      console.log(`Successfully generated NJIT alert with model: ${model}`);

      return {
        success: true,
        subject: alertData.subject || 'SCAM ALERT: Potential Phishing Email Detected',
        body: alertData.body || 'Alert email body'
      };

    } catch (error) {
      if (!error.message.includes('not_found_error')) {
        console.error('NJIT alert generation error:', error);
        return {
          success: false,
          error: error.message
        };
      }
      lastError = error;
    }
  }

  console.error('All Claude models failed for NJIT alert:', lastError);
  return {
    success: false,
    error: lastError ? lastError.message : 'All models unavailable'
  };
}

/**
 * Build prompt for NJIT alert email generation
 */
function buildNJITAlertPrompt(emailData, analysisResults) {
  const redFlagsText = analysisResults.aiResults?.redFlags?.length > 0
    ? analysisResults.aiResults.redFlags.map(flag => `- ${flag}`).join('\n')
    : analysisResults.detectedPatterns?.map(p => `- ${p.category}: ${p.matches.join(', ')}`).join('\n') || 'See analysis below';

  const aiReasoning = analysisResults.aiResults?.reasoning || 'Automated scam detection analysis detected multiple red flags in this email.';

  return `You are writing a professional security alert email to NJIT's IST Service Desk on behalf of a student who received a potential scam/phishing email.

<scam_email_details>
Subject: ${emailData.subject}
Sender: ${emailData.sender}
Scam Probability: ${analysisResults.probability}%
Risk Level: ${analysisResults.riskLevel.toUpperCase()}

Body Preview:
${emailData.body.substring(0, 500)}${emailData.body.length > 500 ? '...' : ''}

Links Found:
${emailData.links && emailData.links.length > 0 ? emailData.links.slice(0, 5).join('\n') : 'No links detected'}

AI Analysis:
${aiReasoning}

Detected Red Flags:
${redFlagsText}
</scam_email_details>

<task>
Generate a professional, clear, and actionable alert email to ServiceDesk@njit.edu. The email should:

1. Be professional and concise
2. Clearly identify this as a scam alert from a student
3. Include key details about the scam email (subject, sender, risk level)
4. Highlight the most critical red flags
5. Request that IST alert other students to prevent them from falling for this scam
6. Express urgency appropriate to the risk level
7. Thank them for their attention

The tone should be:
- Professional but urgent
- Clear and actionable
- Respectful of IST's time
- Emphasize protecting other students
</task>

Respond with ONLY a valid JSON object (no markdown, no code blocks):
{
  "subject": "<concise email subject line that clearly indicates scam alert>",
  "body": "<complete email body with greeting, details, request, and closing>"
}`;
}

/**
 * Build advanced prompt for Claude analysis with few-shot learning and chain-of-thought
 */
function buildPrompt(emailData) {
  return `You are an expert email security analyst specializing in phishing and scam detection. Use chain-of-thought reasoning to analyze this email.

<examples>
Example 1 - CRITICAL SCAM:
Email: "Subject: URGENT: Your account will be suspended! From: security@paypa1-verify.com
Body: Dear valued customer, We detected unusual activity. Click here immediately to verify your account or it will be locked permanently. http://paypal-verify.tk/login"

Analysis:
1. Sender domain "paypa1-verify.com" uses number "1" instead of "l" - typosquatting
2. Suspicious TLD ".tk" commonly used for phishing
3. Creates artificial urgency ("immediately", "will be locked permanently")
4. Generic greeting ("Dear valued customer") instead of personalized
5. Requests immediate action without proper context
Result: {"probability": 95, "riskLevel": "critical", "redFlags": ["Typosquatting domain (paypa1)", "Suspicious TLD .tk", "Urgent language", "Generic greeting", "Suspicious link"], "reasoning": "Multiple high-confidence phishing indicators: typosquatted domain mimicking PayPal, free suspicious TLD, urgency tactics, and link to fake login page", "confidence": 98}

Example 2 - SAFE EMAIL:
Email: "Subject: Your GitHub security alert From: noreply@github.com
Body: Hi username, We detected a new login to your account from Chrome on Windows in New York. If this was you, no action needed. If not, secure your account here: https://github.com/settings/security"

Analysis:
1. Legitimate sender domain "github.com"
2. HTTPS link to actual GitHub domain
3. Informational tone, not demanding immediate action
4. Provides specific details (device, browser, location)
5. Offers optional action if needed
Result: {"probability": 5, "riskLevel": "safe", "redFlags": [], "reasoning": "Legitimate security notification from verified GitHub domain with proper HTTPS links and reasonable, non-urgent tone", "confidence": 95}

Example 3 - MEDIUM RISK:
Email: "Subject: You've won! From: promotions@marketing-deals.com
Body: Congratulations! You've been selected to receive a FREE iPhone 15. Click here to claim your prize. Limited time offer!"

Analysis:
1. Unexpected prize offer with no context
2. Generic domain "marketing-deals.com" not associated with known brand
3. Uses excitement/scarcity tactics ("FREE", "Limited time")
4. Vague sender with no brand association
5. No personalization or prior relationship
Result: {"probability": 45, "riskLevel": "medium", "redFlags": ["Unsolicited prize offer", "Generic sender domain", "Urgency tactics", "Too good to be true offer"], "reasoning": "Likely marketing scam or prize phishing. No legitimate company gives away expensive prizes unsolicited", "confidence": 75}
</examples>

Now analyze this email using the same chain-of-thought approach:

<email>
Subject: ${emailData.subject}
From: ${emailData.sender}
Body: ${emailData.body.substring(0, 2000)}${emailData.body.length > 2000 ? '...' : ''}
${emailData.links && emailData.links.length > 0 ? `Links found: ${emailData.links.slice(0, 10).join(', ')}` : 'No links found'}
</email>

<analysis_instructions>
Step 1: Examine the sender domain for:
- Typosquatting (g00gle.com, paypa1.com, micros0ft.com)
- Suspicious TLDs (.tk, .ml, .ga, .cf, .gq)
- Domain-display name mismatches
- Free email services for business communication

Step 2: Analyze the language for:
- Urgency tactics ("immediate", "expires", "act now", "final notice")
- Psychological manipulation (fear, greed, curiosity)
- Generic greetings ("Dear customer" vs personalized)
- Grammar and spelling errors
- Excessive capitalization or punctuation

Step 3: Evaluate requests for:
- Credentials (username, password, 2FA codes)
- Financial information (credit cards, bank accounts, SSN)
- Personal data (DOB, address, phone)
- Immediate action on links/attachments
- Money transfers or gift cards

Step 4: Inspect links for:
- Domain mismatch (display text vs actual URL)
- URL shorteners hiding destination
- IP addresses instead of domains
- HTTP vs HTTPS
- Typosquatted domains

Step 5: Consider context:
- Is this expected communication?
- Does sender match claimed organization?
- Are there verifiable contact details?
- Is the offer/request reasonable?
</analysis_instructions>

Respond with ONLY a valid JSON object (no markdown, no code blocks):
{
  "probability": <0-100 integer>,
  "riskLevel": <"safe"|"medium"|"high"|"critical">,
  "redFlags": [<array of specific red flags as strings>],
  "reasoning": "<2-3 sentence explanation using insights from chain-of-thought analysis>",
  "confidence": <0-100 integer>,
  "chainOfThought": {
    "senderAnalysis": "<brief assessment of sender legitimacy>",
    "contentAnalysis": "<brief assessment of email content and tactics>",
    "linkAnalysis": "<brief assessment of any links>",
    "contextAnalysis": "<brief assessment of overall context and likelihood>"
  }
}`;
}
