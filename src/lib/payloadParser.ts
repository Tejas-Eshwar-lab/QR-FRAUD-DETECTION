import {
  PayloadType,
  UpiPayload,
  WifiPayload,
  ContactPayload,
  CommunicationPayload,
  DownloadAssessment,
} from '../types/security';

const MAX_PAYLOAD_BYTES = 8192;

export interface ParsedPayload {
  type: PayloadType;
  sanitized: string;
  upiData?: UpiPayload;
  wifiData?: WifiPayload;
  contactData?: ContactPayload;
  communicationData?: CommunicationPayload;
  downloadAssessment: DownloadAssessment;
  redirectTarget?: string;
  error?: string;
}

const EXECUTABLE_EXTENSIONS = ['.apk', '.exe', '.msi', '.dmg', '.pkg', '.zip', '.rar', '.7z', '.sh', '.vbs', '.bat', '.bin', '.mobileconfig'];

export function parseAndClassifyPayload(raw: string): ParsedPayload {
  const defaultDownload: DownloadAssessment = {
    isDownload: false,
    wasAnalyzed: false,
  };

  if (!raw || typeof raw !== 'string') {
    return {
      type: 'MALFORMED',
      sanitized: '',
      downloadAssessment: defaultDownload,
      error: 'Payload is empty or non-string.',
    };
  }

  // Enforce size limit to prevent memory exhaustion / denial of service
  const truncated = raw.length > MAX_PAYLOAD_BYTES ? raw.slice(0, MAX_PAYLOAD_BYTES) : raw;
  const trimmed = truncated.trim();

  // 1. UPI Payment URIs
  // Example: upi://pay?pa=name@upi&pn=Merchant&am=100&cu=INR
  if (/^upi:\/\/pay/i.test(trimmed)) {
    const upiData = parseUpiPayload(trimmed);
    return {
      type: 'UPI_PAYMENT',
      sanitized: trimmed,
      upiData,
      downloadAssessment: defaultDownload,
    };
  }

  // 2. HTTP / HTTPS URLs
  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      const downloadAssessment = detectDownload(parsed);
      const redirectTarget = detectRedirectParam(parsed);

      return {
        type: 'HTTP_URL',
        sanitized: trimmed,
        downloadAssessment,
        redirectTarget,
      };
    } catch {
      return {
        type: 'MALFORMED',
        sanitized: trimmed,
        downloadAssessment: defaultDownload,
        error: 'Malformed HTTP/HTTPS URL format.',
      };
    }
  }

  // 3. Wi-Fi Configuration
  if (/^WIFI:/i.test(trimmed)) {
    const wifiData = parseWifiPayload(trimmed);
    return {
      type: 'WIFI_CONFIG',
      sanitized: trimmed,
      wifiData,
      downloadAssessment: defaultDownload,
    };
  }

  // 4. Contact / vCard or MeCard
  if (/^BEGIN:VCARD/i.test(trimmed) || /^MECARD:/i.test(trimmed)) {
    const contactData = parseContactPayload(trimmed);
    return {
      type: 'VCARD_CONTACT',
      sanitized: trimmed,
      contactData,
      downloadAssessment: defaultDownload,
    };
  }

  // 5. Telephone, SMS, or Email actions
  if (/^(tel:|sms:|smsto:|mailto:)/i.test(trimmed)) {
    const communicationData = parseCommunicationPayload(trimmed);
    return {
      type: 'COMMUNICATION',
      sanitized: trimmed,
      communicationData,
      downloadAssessment: defaultDownload,
    };
  }

  // 6. Generic App / Custom Deep Links
  if (/^[a-z0-9+.-]+:\/\//i.test(trimmed)) {
    return {
      type: 'CUSTOM_DEEP_LINK',
      sanitized: trimmed,
      downloadAssessment: defaultDownload,
    };
  }

  // 7. Check if it looks like a URL without protocol (e.g. www.google.com or example.com/login)
  if (/^(www\.[a-z0-9-]+\.[a-z]{2,}|[a-z0-9-]+\.(com|org|net|in|io|xyz|top|ru|cn|cc|app|dev)\/)/i.test(trimmed)) {
    const prefixed = `https://${trimmed}`;
    try {
      const parsed = new URL(prefixed);
      return {
        type: 'HTTP_URL',
        sanitized: prefixed,
        downloadAssessment: detectDownload(parsed),
        redirectTarget: detectRedirectParam(parsed),
      };
    } catch {}
  }

  // 8. Plain Text fallback
  return {
    type: 'PLAIN_TEXT',
    sanitized: trimmed,
    downloadAssessment: defaultDownload,
  };
}

function detectDownload(url: URL): DownloadAssessment {
  const pathname = url.pathname.toLowerCase();
  const search = url.search.toLowerCase();

  for (const ext of EXECUTABLE_EXTENSIONS) {
    if (pathname.endsWith(ext) || search.includes(ext)) {
      const filename = pathname.split('/').pop() || `file${ext}`;
      const isApk = ext === '.apk';

      return {
        isDownload: true,
        filename,
        extension: ext,
        fileType: isApk ? 'Android Application Package (APK)' : `${ext.slice(1).toUpperCase()} File`,
        wasAnalyzed: false,
        analysisMethod: 'Safe Static URL Lexical & Heuristic Inspection (File Not Downloaded)',
        suspectedMalwareFamily: isApk ? 'Android Banking Trojan or Sideloaded Spyware' : undefined,
        potentialCapabilities: isApk
          ? [
              'Requests install via unknown sources (sideloading)',
              'May abuse Android Accessibility Services to siphon OTPs',
              'Can intercept SMS verification codes and keystrokes',
            ]
          : ['Direct binary execution on target OS', 'Drive-by download'],
        riskSummary:
          'A QR code points to an unverified application download. The file has not been executed, so we cannot confirm that it contains malware. Installing an unsafe application may expose personal information or financial accounts.',
      };
    }
  }

  // Path indicates a download action
  if (pathname.includes('/download/') || pathname.includes('/apk/') || pathname.includes('/install/')) {
    return {
      isDownload: true,
      filename: pathname.split('/').pop() || 'unnamed_package',
      extension: '.apk',
      fileType: 'Application Package / Download Stream',
      wasAnalyzed: false,
      analysisMethod: 'Heuristic Path Analysis (File Not Downloaded)',
      riskSummary:
        'The URL path suggests a direct file download stream. Downloading and installing files from untrusted QR codes poses high risk.',
    };
  }

  return {
    isDownload: false,
    wasAnalyzed: false,
  };
}

function detectRedirectParam(url: URL): string | undefined {
  const redirectKeys = ['url', 'redirect', 'target', 'dest', 'destination', 'link', 'r', 'goto', 'u', 'next'];
  for (const key of redirectKeys) {
    const val = url.searchParams.get(key);
    if (val && (val.startsWith('http://') || val.startsWith('https://'))) {
      return val;
    }
  }
  return undefined;
}

// -------------------------------------------------------------
// UPI Parser
// -------------------------------------------------------------
function parseUpiPayload(rawUri: string): UpiPayload {
  const result: UpiPayload = {
    raw: rawUri,
    isCleanPayeeFormat: false,
    hasSuspiciousLure: false,
    unverifiedWarning:
      'UPI QR code encodes a payment recipient. Recipient identity is unverified until inspected in your official banking app.',
  };

  try {
    const queryPart = rawUri.split('?')[1] || '';
    const params = new URLSearchParams(queryPart);

    result.payeeAddress = params.get('pa') || undefined;
    result.payeeName = params.get('pn') ? decodeURIComponent(params.get('pn')!) : undefined;
    result.merchantCode = params.get('mc') || undefined;
    result.amount = params.get('am') || undefined;
    result.currency = params.get('cu') || 'INR';
    result.transactionRef = params.get('tr') || undefined;
    result.transactionNote = params.get('tn') ? decodeURIComponent(params.get('tn')!) : undefined;

    if (result.payeeAddress && /^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$/.test(result.payeeAddress)) {
      result.isCleanPayeeFormat = true;
    }

    const combinedText = `${result.payeeName || ''} ${result.transactionNote || ''} ${result.payeeAddress || ''}`.toLowerCase();
    const lureKeywords = ['cashback', 'lottery', 'reward', 'prize', 'kyc refund', 'congratulations', 'won', 'bonus'];
    result.hasSuspiciousLure = lureKeywords.some((kw) => combinedText.includes(kw));
  } catch {}

  return result;
}

// -------------------------------------------------------------
// Wi-Fi Config Parser
// -------------------------------------------------------------
function parseWifiPayload(raw: string): WifiPayload {
  const extractField = (prefix: string) => {
    const regex = new RegExp(`${prefix}:([^;]*);`, 'i');
    const match = raw.match(regex);
    return match ? match[1] : '';
  };

  const ssid = extractField('S');
  const encryption = extractField('T') || 'WPA';
  const password = extractField('P');
  const hidden = extractField('H').toLowerCase() === 'true';

  return {
    ssid: ssid || 'Unknown Network',
    encryption,
    hidden,
    passwordProvided: Boolean(password),
  };
}

// -------------------------------------------------------------
// vCard / MeCard Parser
// -------------------------------------------------------------
function parseContactPayload(raw: string): ContactPayload {
  const contact: ContactPayload = {};

  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    if (/^FN:/i.test(line)) {
      contact.name = line.replace(/^FN:/i, '').trim();
    } else if (/^TEL[^:]*:/i.test(line)) {
      contact.phone = line.replace(/^TEL[^:]*:/i, '').trim();
    } else if (/^EMAIL[^:]*:/i.test(line)) {
      contact.email = line.replace(/^EMAIL[^:]*:/i, '').trim();
    } else if (/^ORG:/i.test(line)) {
      contact.org = line.replace(/^ORG:/i, '').trim();
    }
  }

  if (!contact.name && /^MECARD:/i.test(raw)) {
    const nMatch = raw.match(/N:([^;]+);/i);
    const telMatch = raw.match(/TEL:([^;]+);/i);
    const emailMatch = raw.match(/EMAIL:([^;]+);/i);
    if (nMatch) contact.name = nMatch[1];
    if (telMatch) contact.phone = telMatch[1];
    if (emailMatch) contact.email = emailMatch[1];
  }

  return contact;
}

// -------------------------------------------------------------
// Communication Action Parser
// -------------------------------------------------------------
function parseCommunicationPayload(raw: string): CommunicationPayload {
  if (/^tel:/i.test(raw)) {
    return {
      type: 'tel',
      target: raw.replace(/^tel:/i, '').split('?')[0],
    };
  }
  if (/^sms:|^smsto:/i.test(raw)) {
    const target = raw.replace(/^(sms:|smsto:)/i, '').split('?')[0];
    const bodyMatch = raw.match(/[?&]body=([^&]*)/i);
    return {
      type: 'sms',
      target,
      bodyOrSubject: bodyMatch ? decodeURIComponent(bodyMatch[1]) : undefined,
    };
  }
  const target = raw.replace(/^mailto:/i, '').split('?')[0];
  const subjectMatch = raw.match(/[?&]subject=([^&]*)/i);
  return {
    type: 'mailto',
    target,
    bodyOrSubject: subjectMatch ? decodeURIComponent(subjectMatch[1]) : undefined,
  };
}
