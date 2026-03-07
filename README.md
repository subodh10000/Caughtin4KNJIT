# Caughtin4KNJIT 🛡️

**Advanced AI-Powered Gmail Scam Email Detector**

A Chrome extension for the NJIT community that combines local pattern matching with Claude AI's chain-of-thought reasoning to protect users from phishing and scam emails.

## ✨ Key Features

- **Multi-Layer Protection**: Real-time email monitoring combining local pattern detection (40%), email authentication (SPF/DKIM/DMARC - 30%), and advanced link/URL safety analysis (20%).
- **🤖 Claude AI Integration**: Opt-in advanced LLM reasoning (contributes 60% weight to risk scoring when enabled) with visual, expandable chain-of-thought explanations.
- **Real-Time Visual Warnings**: Color-coded banners (Safe, Medium, High, Critical) are automatically injected into the Gmail web interface with quick response actions (Delete/Report).
- **Comprehensive Dashboard**: View total scans, detection statistics, recent history, and easily export data as JSON or CSV.
- **Privacy-First**: Pattern matching happens locally on your device. No analytics or telemetry. AI features strictly use your personal Anthropic API key to interact with Claude.

## 🚀 Installation & Setup

1. Clone or download this repository.
2. Navigate to `chrome://extensions/` in Chrome or an Edge/Chromium-based browser.
3. Enable **Developer mode** in the top right corner.
4. Click **Load unpacked** and select the `Caughtin4KNJIT` directory.
5. **(Optional) Enable AI**: Click the extension's badge icon in your toolbar, enter a valid Claude API key (`sk-ant-...`), and click Save.

## 🛠️ Project Structure

The extension follows Manifest V3 standards and is organized inside the `src/` directory:

- `src/background/` - Extension service worker handling external API requests and state persistence.
- `src/content/` - Core email extraction logic and Gmail DOM integration.
- `src/utils/` - Modular helper utilities for Claude API, email header parsing, and typosquatting/link analysis.
- `src/popup/` - The extension's interactive dashboard UI and local storage manager.
- `src/styles/` - CSS rules handling the display and animations of the injected warning banners.

## 💡 How It Works

1. As you open an email in Gmail, the extension instantly extracts the content, headers, and embedded links.
2. The local detection engine calculates an initial probability score checking for urgency tactics, credential phishing, sender spoofing, and suspicious domains.
3. If configured, the Claude AI engine simultaneously analyzes the data and provides step-by-step reasoning.
4. Scores are aggregated (Local + AI) and if the risk exceeds the safe threshold, a visually distinct protection banner is rendered directly inside the email interface.

## 🤝 Contributing & Support

This is an educational project built for the Caughtin4K cybersecurity initiative at NJIT. Contributions are welcome! Simply fork the repository, create a feature branch, and submit a PR.

*Note: For issues, please check the browser console (`F12`) for content and background script errors, and ensure your Claude API key is valid and funded.*
