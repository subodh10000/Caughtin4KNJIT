# Caughtin4KNJIT

**Advanced AI-Powered Gmail Scam Email Detector**

A Chrome extension that combines local pattern matching with Claude AI's chain-of-thought reasoning to protect users from phishing and scam emails. Built for the NJIT community.

## 🌟 Highlighted Features

### 🤖 Advanced Claude AI Integration
- **Chain-of-Thought Reasoning** - See how Claude analyzes emails step-by-step
- **Few-Shot Learning** - Trained with real scam examples for better accuracy
- **Multi-Model Fallback** - Ensures 99.9% uptime with 4 Claude model options
- **Confidence Scoring** - Visual progress bar showing AI certainty
- **Transparent Analysis** - Expandable sections reveal the AI's reasoning process

### 🛡️ Multi-Layer Protection
- **Real-time Email Monitoring** - Automatically analyzes emails as you open them in Gmail
- **Local Pattern Detection** - Fast, privacy-focused scam detection using 6 pattern categories (40% weight)
- **Email Authentication** - SPF, DKIM, and DMARC validation (30% weight)
- **Advanced Link Analysis** - URL safety scoring with typosquatting detection (20% weight)
- **AI Enhancement** - Claude chain-of-thought reasoning (60% weight when enabled)
- **Visual Warning Banners** - Color-coded alerts with smooth animations
- **Quick Actions** - Delete, Report, or Dismiss suspicious emails with one click

### 📊 Detection Categories
1. **Urgency Tactics** - "Act now", "Expires soon", "Limited time"
2. **Money Scams** - Lottery, wire transfers, inheritance schemes
3. **Credential Phishing** - Password resets, account verification requests
4. **Impersonation** - Fake NJIT admin, IT department spoofing
5. **Threats** - Account suspension, legal action warnings
6. **Suspicious Patterns** - Grammar issues, fake domains, URL shorteners

### 📈 Enhanced Dashboard
- **Real-time Statistics** - Total emails scanned, scams detected, protection rate
- **Recent Scans History** - Last 5 emails with color-coded risk levels
- **Export Functionality** - Download reports as JSON or CSV for analysis
- **Claude AI Configuration** - Easy API key management with status indicators
- **Clear Statistics** - Reset counters for fresh start

### 🎨 Design & UX
- **Modern Gradient UI** - Beautiful purple theme with smooth animations
- **Expandable Sections** - Email headers, link analysis, and AI reasoning collapse to reduce clutter
- **Color-Coded Links** - In-email links are highlighted with safety indicators
- **Interactive Tooltips** - Hover over links for detailed safety information
- **Pulse Animation** - Critical warnings pulse to grab attention
- **Responsive Design** - Works beautifully on all screen sizes

## Installation

### For Development (Load Unpacked)

1. Clone or download this repository
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked"
5. Select the `Caughtin4KNJIT` folder
6. The extension is now installed!

### Usage

1. Navigate to [Gmail](https://mail.google.com)
2. Open any email
3. The extension automatically analyzes it
4. If suspicious (≥30% probability), a warning banner appears
5. Click the extension icon to view statistics

## Claude AI Integration (Optional)

For enhanced detection accuracy, you can configure Claude AI:

1. Get an API key from [Anthropic Console](https://console.anthropic.com/)
2. Click the extension icon to open the dashboard
3. Enter your API key in the "Claude AI" section
4. Click "Save API Key"

**Cost**: ~$0.01 per email analyzed (Claude 3.5 Sonnet pricing)

**Privacy**: Your API key stays on your device. Analysis happens via your own API key.

## How It Works

### Local Detection (Instant)
- Scans email content for suspicious patterns
- Analyzes sender domain authenticity
- Checks links for phishing indicators
- Evaluates grammar and formatting
- Returns probability score (0-100%)

### AI Enhancement (Optional, 2-3 seconds)
- Sends email to Claude AI via background script
- Gets advanced analysis with reasoning
- Combines results: 40% local + 60% AI
- Updates warning with AI insights

### Risk Levels
- **Safe** (0-29%): No warning shown, green badge
- **Medium** (30-49%): Yellow warning banner
- **High** (50-69%): Orange warning banner
- **Critical** (70-100%): Red warning with pulse animation

## File Structure

```
Caughtin4KNJIT/
├── manifest.json          # Extension configuration (Manifest V3)
├── background.js          # Service worker (badge updates, Claude API calls)
├── content.js             # Gmail integration (email detection & analysis)
├── scam-detector.js       # Core local detection logic
├── claude-api.js          # Claude AI integration wrapper
├── popup.html             # Statistics dashboard UI
├── popup.js               # Dashboard functionality
├── styles.css             # Warning banner styles
├── icons/                 # Extension icons
│   ├── icon16.png         # 16x16 toolbar icon
│   ├── icon48.png         # 48x48 management icon
│   ├── icon128.png        # 128x128 store icon
│   └── README.txt         # Icon replacement instructions
└── README.md              # This file
```

## Privacy & Security

- **All local processing** - Pattern detection happens on your device
- **No data collection** - Extension doesn't send data to any servers
- **Optional AI** - Claude AI is opt-in and uses your own API key
- **Open source** - All code is visible and auditable
- **No tracking** - No analytics, no telemetry

## Technical Details

- **Platform**: Chrome Extension (Manifest V3)
- **Languages**: JavaScript (vanilla), HTML, CSS
- **APIs**: Chrome Extensions API, Anthropic Claude API (optional)
- **Target**: Gmail web interface (https://mail.google.com)
- **Performance**: Local analysis <100ms, AI analysis ~2-3s

## Browser Compatibility

- ✅ Google Chrome (Manifest V3)
- ✅ Microsoft Edge (Chromium-based)
- ✅ Brave Browser
- ✅ Opera
- ❌ Firefox (requires Manifest V2 conversion)

## Known Limitations

- Only works on Gmail web interface (not mobile app)
- Requires active internet for AI enhancement
- Gmail DOM changes may affect email extraction
- Placeholder icons need replacement for production

## Development

### Prerequisites
- Google Chrome browser
- Text editor (VS Code, Sublime Text, etc.)
- Basic knowledge of JavaScript

### Making Changes
1. Edit the source files
2. Go to `chrome://extensions/`
3. Click the refresh icon on the extension card
4. Test your changes in Gmail

### Testing
- Open various types of emails in Gmail
- Check browser console for errors (F12)
- Verify warning banners display correctly
- Test dashboard statistics update
- Test API key configuration (if using Claude AI)

## Troubleshooting

### Extension not detecting emails
- Refresh Gmail page
- Check browser console for errors
- Verify extension is enabled in `chrome://extensions/`

### Warning not appearing
- Ensure email has ≥30% scam probability
- Check if content scripts loaded (inspect page elements)
- Verify no JavaScript errors in console

### Claude AI not working
- Verify API key is correct (starts with `sk-ant-`)
- Check API key has available credits
- Look for CORS errors in console (should route through background script)

## Contributing

This is a student project for NJIT. Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

Educational project - free to use and modify.

## Credits

Created for NJIT students as part of the Caughtin4K cybersecurity initiative.

**Powered by:**
- Local pattern matching algorithms
- Claude AI by Anthropic (optional)
- Chrome Extensions API

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review browser console for errors
3. Verify you're using the latest version
4. Open an issue on the repository

---

**Stay safe! Protect your inbox with Caughtin4KNJIT 🛡️**
