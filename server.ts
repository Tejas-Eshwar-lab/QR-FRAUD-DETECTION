import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '5mb' }));

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Initialize server-side credentials
const geminiApiKey = process.env.GEMINI_API_KEY || '';
const webRiskApiKey = process.env.GOOGLE_WEB_RISK_API_KEY || '';

let aiClient: GoogleGenAI | null = null;
if (geminiApiKey) {
  try {
    aiClient = new GoogleGenAI({
      apiKey: geminiApiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (err) {
    console.warn('Failed to initialize GoogleGenAI client:', err);
  }
}

// -------------------------------------------------------------
// 1. Health & Config Status Endpoint
// -------------------------------------------------------------
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'ScamTrace AI Security Server',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    capabilities: {
      webRiskApiConfigured: Boolean(webRiskApiKey),
      geminiAiConfigured: Boolean(geminiApiKey && aiClient),
      clientSideDecoding: true,
      supportedThreatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
    },
  });
});

// -------------------------------------------------------------
// 2. Google Web Risk Threat Intelligence Endpoint
// -------------------------------------------------------------
app.post('/api/threat-intel', async (req: Request, res: Response) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({
        status: 'CHECK_FAILED',
        error: 'Invalid input: URL string is required.',
      });
    }

    // Scheme validation: strictly http or https
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({
        status: 'CHECK_FAILED',
        error: 'Invalid URL format.',
      });
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return res.status(400).json({
        status: 'CHECK_FAILED',
        error: 'Unsupported scheme for Web Risk lookup. Only HTTP and HTTPS are checked.',
      });
    }

    if (url.length > 2048) {
      return res.status(400).json({
        status: 'CHECK_FAILED',
        error: 'URL exceeds maximum allowable length (2048 characters).',
      });
    }

    // Official Google Safe Browsing / Web Risk Test Fixtures (Educational & Test Verification)
    if (
      url.includes('testsafebrowsing.appspot.com/s/malware.html') ||
      url.includes('malware.testing.google.test')
    ) {
      return res.json({
        status: 'CONFIRMED_THREAT',
        provider: 'Google Web Risk Test Protocol',
        threatTypes: ['MALWARE'],
        matches: ['MALWARE'],
        message: 'Official Google Safe Browsing malware-test URL fixture verified.',
        checkTimestamp: new Date().toISOString(),
      });
    }

    if (
      url.includes('testsafebrowsing.appspot.com/s/phishing.html') ||
      url.includes('phishing.testing.google.test')
    ) {
      return res.json({
        status: 'CONFIRMED_THREAT',
        provider: 'Google Web Risk Test Protocol',
        threatTypes: ['SOCIAL_ENGINEERING'],
        matches: ['SOCIAL_ENGINEERING'],
        message: 'Official Google Safe Browsing phishing-test URL fixture verified.',
        checkTimestamp: new Date().toISOString(),
      });
    }

    // Check if Web Risk API key is configured
    if (!webRiskApiKey) {
      return res.json({
        status: 'NOT_CONFIGURED',
        provider: 'Google Web Risk Lookup API',
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        message: 'Google Web Risk API key is not configured in server environment. Offline heuristic engine active.',
        details: 'To enable live Web Risk queries, set GOOGLE_WEB_RISK_API_KEY in server secrets.',
        checkTimestamp: new Date().toISOString(),
      });
    }

    // Official Google Web Risk Lookup API endpoint
    // https://cloud.google.com/web-risk/docs/lookup-api
    const threatTypes = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'];
    const queryParams = new URLSearchParams();
    threatTypes.forEach((t) => queryParams.append('threatTypes', t));
    queryParams.set('uri', url);
    queryParams.set('key', webRiskApiKey);

    const apiUrl = `https://webrisk.googleapis.com/v1/uris:search?${queryParams.toString()}`;

    // Safe timeout controller (4 seconds)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    const apiResponse = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (apiResponse.status === 400 || apiResponse.status === 401 || apiResponse.status === 403) {
      const errBody = await apiResponse.text().catch(() => '');
      return res.json({
        status: 'NOT_CONFIGURED',
        provider: 'Google Web Risk Lookup API',
        threatTypes,
        message: 'Google Web Risk API is not configured or key is unauthorized. Offline heuristic and quishing ML engines are active.',
        details: 'To enable live cloud threat lookups, enable the Google Web Risk API in Google Cloud Console and set a valid GOOGLE_WEB_RISK_API_KEY.',
        error: `HTTP ${apiResponse.status}: ${errBody.slice(0, 150)}`,
        checkTimestamp: new Date().toISOString(),
      });
    }

    if (!apiResponse.ok) {
      const errBody = await apiResponse.text().catch(() => '');
      return res.json({
        status: 'CHECK_FAILED',
        provider: 'Google Web Risk Lookup API',
        threatTypes,
        error: `Lookup provider returned status ${apiResponse.status}`,
        details: errBody.slice(0, 200),
        checkTimestamp: new Date().toISOString(),
      });
    }

    const data = await apiResponse.json();

    // If matches found
    if (data && data.threat && Array.isArray(data.threat.threatTypes) && data.threat.threatTypes.length > 0) {
      return res.json({
        status: 'CONFIRMED_THREAT',
        provider: 'Google Web Risk Lookup API',
        threatTypes,
        matches: data.threat.threatTypes,
        expireTime: data.threat.expireTime || null,
        message: `Confirmed threat detected: ${data.threat.threatTypes.join(', ')}`,
        checkTimestamp: new Date().toISOString(),
      });
    }

    // No match found
    return res.json({
      status: 'NO_THREAT_FOUND',
      provider: 'Google Web Risk Lookup API',
      threatTypes,
      matches: [],
      message: 'No active threat match in Google Web Risk database at time of check.',
      checkTimestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    if (err?.name === 'AbortError') {
      return res.json({
        status: 'CHECK_FAILED',
        provider: 'Google Web Risk Lookup API',
        error: 'Web Risk request timed out (> 4s)',
        checkTimestamp: new Date().toISOString(),
      });
    }
    return res.json({
      status: 'CHECK_FAILED',
      provider: 'Google Web Risk Lookup API',
      error: err?.message || 'Threat intelligence lookup failed',
      checkTimestamp: new Date().toISOString(),
    });
  }
});

// -------------------------------------------------------------
// 3. Bilingual AI Risk Explanation (English & Kannada)
// -------------------------------------------------------------
app.post('/api/explain', async (req: Request, res: Response) => {
  const { payloadType, payload, indicators, overallRisk, threatIntelResult, upiData } = req.body;

  // Fallback generator if AI is not available
  const generateDeterministicExplanation = () => {
    let engSummary = '';
    let kanSummary = '';
    const engAdvice: string[] = [];
    const kanAdvice: string[] = [];

    if (overallRisk === 'CONFIRMED_THREAT') {
      engSummary = `This QR code points to a confirmed malicious threat identified by Google Web Risk. Accessing this link may download malware, compromise your personal accounts, or steal credentials.`;
      kanSummary = `ಈ QR ಕೋಡ್ ಗೂಗಲ್ ವೆಬ್ ರಿಸ್ಕ್ ಮೂಲಕ ದೃಢಪಟ್ಟ ಹಾನಿಕಾರಕ ಲಿಂಕ್ ಆಗಿದೆ. ಇದನ್ನು ತೆರೆಯುವುದರಿಂದ ನಿಮ್ಮ ಮೊಬೈಲ್/ಖಾತೆಯ ಸುರಕ್ಷತೆಗೆ ಅಪಾಯ ಉಂಟಾಗಬಹುದು.`;
      engAdvice.push('Do NOT open or proceed to this web address.');
      engAdvice.push('Delete or report the source of this QR code immediately.');
      kanAdvice.push('ಈ ವೆಬ್ ವಿಳಾಸವನ್ನು ಯಾವುದೇ ಕಾರಣಕ್ಕೂ ತೆರೆಯಬೇಡಿ.');
      kanAdvice.push('ಈ QR ಕೋಡ್ ಅನ್ನು ತಕ್ಷಣ ಅಳಿಸಿ ಅಥವಾ ವರದಿ ಮಾಡಿ.');
    } else if (payloadType === 'UPI_PAYMENT') {
      const payee = upiData?.payeeName || upiData?.payeeAddress || 'an unverified recipient';
      const amount = upiData?.amount ? `₹${upiData.amount}` : 'an unspecified amount';
      engSummary = `This QR code initiates a payment request to ${payee} for ${amount}. Remember: scanning a QR code is ONLY for sending money, never for receiving rewards or cashback.`;
      kanSummary = `ಈ QR ಕೋಡ್ ${payee} ಅವರಿಗೆ ${amount} ಹಣ ಪಾವತಿಸಲು ವಿನಂತಿಸುತ್ತದೆ. ನೆನಪಿಡಿ: ಹಣ ಪಡೆಯಲು QR ಕೋಡ್ ಸ್ಕ್ಯಾನ್ ಮಾಡುವ ಅಥವಾ UPI PIN ನಮೂದಿಸುವ ಅಗತ್ಯವಿಲ್ಲ.`;
      engAdvice.push('Verify the exact recipient name in your official UPI app before authenticating.');
      engAdvice.push('NEVER enter your UPI PIN to receive money, cashback, or prizes.');
      kanAdvice.push('ಹಣ ಕಳುಹಿಸುವ ಮುನ್ನ ನಿಮ್ಮ ಬ್ಯಾಂಕಿಂಗ್ ಆ್ಯಪ್‌ನಲ್ಲಿ ಸ್ವೀಕರಿಸುವವರ ಹೆಸರನ್ನು ದೃಢೀಕರಿಸಿ.');
      kanAdvice.push('ಹಣ ಅಥವಾ ಬಹುಮಾನ ಸ್ವೀಕರಿಸಲು ಎಂದಿಗೂ UPI PIN ನಮೂದಿಸಬೇಡಿ.');
    } else if (overallRisk === 'SUSPICIOUS') {
      engSummary = `This QR code presents suspicious indicators (${(indicators || []).map((i: any) => i.title).join(', ')}). While no confirmed blacklist match was detected, deceptive tactics are commonly used in phishing attacks.`;
      kanSummary = `ಈ QR ಕೋಡ್‌ನಲ್ಲಿ ಅನುಮಾನಾಸ್ಪದ ಅಂಶಗಳು ಕಂಡುಬಂದಿವೆ. ಅಧಿಕೃತ ಪರಿಶೀಲನೆ ಇಲ್ಲದೆ ಯಾವುದೇ ವೈಯಕ್ತಿಕ ವಿವರ ಅಥವಾ ಲಾಗಿನ್ ಮಾಹಿತಿಯನ್ನು ನಮೂದಿಸಬೇಡಿ.`;
      engAdvice.push('Inspect the root domain carefully before considering opening.');
      engAdvice.push('Do not enter passwords, OTPs, or financial information.');
      kanAdvice.push('ವೆಬ್ ವಿಳಾಸದ ಮೂಲ ಡೊಮೇನ್ ಅನ್ನು ಎಚ್ಚರಿಕೆಯಿಂದ ಪರಿಶೀಲಿಸಿ.');
      kanAdvice.push('ಯಾವುದೇ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.');
    } else {
      engSummary = `No active malicious signatures or high-risk indicators were detected. However, no scanner can guarantee absolute safety. Always confirm you trust the physical source of the QR code.`;
      kanSummary = `ಈ QR ಕೋಡ್‌ನಲ್ಲಿ ಯಾವುದೇ ಅಪಾಯಕಾರಿ ಅಂಶಗಳು ತಕ್ಷಣಕ್ಕೆ ಕಂಡುಬಂದಿಲ್ಲ. ಆದರೂ ಯಾವುದೇ ಸ್ಕ್ಯಾನರ್ 100% ಸುರಕ್ಷತೆ ನೀಡಲು ಸಾಧ್ಯವಿಲ್ಲ, ಜಾಗರೂಕರಾಗಿರಿ.`;
      engAdvice.push('Verify that you recognize the website or provider.');
      engAdvice.push('Ensure the browser displays HTTPS and the legitimate domain name.');
      kanAdvice.push('ವೆಬ್‌ಸೈಟ್ ಅಥವಾ ಸೇವಾ ಸಂಸ್ಥೆಯು ಅಧಿಕೃತವಾಗಿದೆಯೇ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.');
      kanAdvice.push('ಬ್ರೌಸರ್‌ನಲ್ಲಿ HTTPS ಮತ್ತು ಸರಿಯಾದ ಡೊಮೇನ್ ಪರಿಶೀಲಿಸಿ.');
    }

    return {
      source: 'deterministic_engine',
      englishSummary: engSummary,
      englishAdvice: engAdvice,
      kannadaSummary: kanSummary,
      kannadaAdvice: kanAdvice,
    };
  };

  if (!aiClient) {
    return res.json(generateDeterministicExplanation());
  }

  try {
    const prompt = `
Analyze the following QR code security scan and produce a clear, jargon-free security explanation in both English and Kannada (ಕನ್ನಡ).

SCAN EVIDENCE:
- Payload Type: ${payloadType}
- Decoded Payload (first 300 chars): ${String(payload || '').slice(0, 300)}
- Overall Risk: ${overallRisk}
- Observed Indicators: ${JSON.stringify(indicators || [])}
- Threat Intel Status: ${JSON.stringify(threatIntelResult || {})}
- UPI Data: ${JSON.stringify(upiData || null)}

RULES:
1. Explain in simple terms that a non-technical citizen can easily understand.
2. In Kannada, write natural, fluent, grammatically accurate Kannada script (ಕನ್ನಡ ಲಿಪಿ).
3. If this is a UPI payment QR, always emphasize: Receiving money NEVER requires entering a UPI PIN.
4. If a URL is suspicious (lookalike domain, IP host, shortener), explain why that trick is used by scammers.
5. Never promise 100% safety.
6. Provide 2-3 specific actionable advice steps in both languages.
`;

    const response = await aiClient.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction:
          'You are ScamTrace AI, an elite cybersecurity and financial fraud advisor. Provide bilingual explanations (English and Kannada) of QR code security findings. Be concise, direct, helpful, and protective.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            englishSummary: {
              type: Type.STRING,
              description: 'Clear, plain-English summary of what this QR payload is and whether it appears dangerous.',
            },
            englishAdvice: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: '2 to 3 practical next steps for the user in English.',
            },
            kannadaSummary: {
              type: Type.STRING,
              description: 'Kannada translation and localized summary of the threat analysis in natural Kannada script.',
            },
            kannadaAdvice: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: '2 to 3 practical next steps in Kannada script.',
            },
          },
          required: ['englishSummary', 'englishAdvice', 'kannadaSummary', 'kannadaAdvice'],
        },
      },
    });

    const text = response.text;
    if (text) {
      const parsed = JSON.parse(text);
      return res.json({
        source: 'gemini-3.8-flash',
        englishSummary: parsed.englishSummary,
        englishAdvice: parsed.englishAdvice,
        kannadaSummary: parsed.kannadaSummary,
        kannadaAdvice: parsed.kannadaAdvice,
      });
    }

    return res.json(generateDeterministicExplanation());
  } catch (err: any) {
    console.warn('Gemini explanation fallback to deterministic:', err?.message);
    return res.json(generateDeterministicExplanation());
  }
});

// -------------------------------------------------------------
// Vite Server Integration (Dev vs Prod)
// -------------------------------------------------------------
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        host: '0.0.0.0',
        port: 3000,
        hmr: process.env.DISABLE_HMR !== 'true',
        watch: process.env.DISABLE_HMR === 'true' ? null : {},
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  const PORT = Number(process.env.PORT) || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[ScamTrace AI] Server active on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[ScamTrace AI] Failed to start server:', err);
  process.exit(1);
});
