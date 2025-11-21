/**
 * ClaudeAPI - Wrapper for Claude AI integration
 * Handles communication with Anthropic API via background script to avoid CORS
 */
class ClaudeAPI {
  constructor() {
    this.apiKey = null;
    this.initialized = false;
    this.init();
  }

  /**
   * Initialize API by loading key from storage
   */
  async init() {
    try {
      const result = await chrome.storage.local.get(['claudeApiKey']);
      if (result.claudeApiKey) {
        this.apiKey = result.claudeApiKey;
        this.initialized = true;
      }
    } catch (error) {
      console.error('Error initializing Claude API:', error);
    }
  }

  /**
   * Check if API is configured
   */
  isConfigured() {
    return this.initialized && this.apiKey !== null;
  }

  /**
   * Set API key
   */
  async setApiKey(apiKey) {
    try {
      await chrome.storage.local.set({ claudeApiKey: apiKey });
      this.apiKey = apiKey;
      this.initialized = true;

      // Notify content scripts of API key update
      chrome.runtime.sendMessage({ type: 'apiKeyUpdated' }).catch(() => {
        // Ignore errors if no listeners
      });

      return { success: true };
    } catch (error) {
      console.error('Error setting API key:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Remove API key
   */
  async removeApiKey() {
    try {
      await chrome.storage.local.remove(['claudeApiKey']);
      this.apiKey = null;
      this.initialized = false;

      // Notify content scripts of API key removal
      chrome.runtime.sendMessage({ type: 'apiKeyUpdated' }).catch(() => {
        // Ignore errors if no listeners
      });

      return { success: true };
    } catch (error) {
      console.error('Error removing API key:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Analyze email using Claude AI
   * Sends request to background script to avoid CORS issues
   * @param {Object} emailData - {subject, sender, body, links}
   * @returns {Object} AI analysis results
   */
  async analyzeEmail(emailData) {
    if (!this.isConfigured()) {
      return {
        success: false,
        error: 'Claude API not configured'
      };
    }

    try {
      // Send message to background script to make API call
      const response = await chrome.runtime.sendMessage({
        type: 'analyzeWithClaude',
        emailData: emailData,
        apiKey: this.apiKey
      });

      if (response.success) {
        return {
          success: true,
          probability: response.probability,
          riskLevel: response.riskLevel,
          redFlags: response.redFlags,
          reasoning: response.reasoning,
          confidence: response.confidence
        };
      } else {
        return {
          success: false,
          error: response.error || 'Unknown error'
        };
      }
    } catch (error) {
      console.error('Error analyzing email with Claude:', error);
      return {
        success: false,
        error: error.message || 'Failed to communicate with Claude API'
      };
    }
  }

  /**
   * Build the prompt for Claude analysis
   */
  buildPrompt(emailData) {
    return `You are an expert email security analyst. Analyze the following email for phishing and scam indicators.

Email Details:
- Subject: ${emailData.subject}
- From: ${emailData.sender}
- Body: ${emailData.body}
${emailData.links && emailData.links.length > 0 ? `- Links: ${emailData.links.join(', ')}` : ''}

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
}

// Export to window for content script access
if (typeof window !== 'undefined') {
  window.ClaudeAPI = ClaudeAPI;
}
