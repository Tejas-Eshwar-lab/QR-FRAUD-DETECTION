import { HeuristicIndicator } from '../types/security';

// Common known URL shortener domains that obscure true landing destinations
const KNOWN_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'cutt.ly',
  'ow.ly',
  'rebrand.ly',
  'rb.gy',
  'shorturl.at',
  'buff.ly',
  'goo.gl',
  'tiny.cc',
  'lnkd.in',
  'qrco.de',
  'me-qr.com',
]);

// High-value targeted brands commonly mimicked in phishing campaigns
const HIGH_VALUE_BRANDS = [
  'paypal',
  'apple',
  'google',
  'microsoft',
  'amazon',
  'netflix',
  'chase',
  'wellsfargo',
  'bankofamerica',
  'citibank',
  'sbi',
  'hdfc',
  'icici',
  'paytm',
  'phonepe',
  'binance',
  'coinbase',
  'metamask',
  'steam',
  'facebook',
  'instagram',
  'whatsapp',
];

// Suspicious security / credential-harvesting tokens
const CREDENTIAL_KEYWORDS = [
  'login',
  'signin',
  'verify',
  'verification',
  'account-update',
  'billing-update',
  'suspended',
  'reactivate',
  'kyc-update',
  'claim-reward',
  'security-alert',
  'urgent',
  'password-reset',
  'auth-token',
  'session-expired',
];

// Suspicious or non-standard web ports
const NON_STANDARD_PORTS = new Set(['8080', '8443', '8888', '4444', '1337', '3128', '8000', '9000', '5000', '2222']);

export function analyzeUrlHeuristics(urlStr: string): HeuristicIndicator[] {
  const indicators: HeuristicIndicator[] = [];

  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    indicators.push({
      id: 'MALFORMED_URL',
      category: 'Syntax',
      severity: 'HIGH',
      title: 'Malformed URL Structure',
      description: 'The URL failed RFC syntax parsing and cannot be processed securely.',
    });
    return indicators;
  }

  const hostname = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol.toLowerCase();
  const port = parsed.port;
  const pathname = parsed.pathname.toLowerCase();
  const fullSearch = parsed.search.toLowerCase();
  const fullHref = parsed.href.toLowerCase();

  // 1. Insecure Transport (HTTP vs HTTPS)
  if (protocol === 'http:') {
    indicators.push({
      id: 'INSECURE_TRANSPORT',
      category: 'Transport Security',
      severity: 'MEDIUM',
      title: 'Unencrypted HTTP Connection',
      description: 'Traffic to this address is not encrypted with SSL/TLS and can be intercepted or tampered with on open Wi-Fi.',
      evidence: `Protocol: ${protocol}`,
    });
  }

  // 2. IP-Address Hostname
  // Detects IPv4: e.g. 192.168.1.1 or IPv6
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
  if (isIpv4 || isIpv6) {
    indicators.push({
      id: 'IP_ADDRESS_HOST',
      category: 'Domain Reputation',
      severity: 'HIGH',
      title: 'Direct IP-Address Hostname',
      description: 'Legitimate services use registered domain names. Direct IP addresses are frequently used in cyber attacks to bypass DNS threat lists.',
      evidence: `Hostname: ${hostname}`,
    });
  }

  // 3. Punycode / Internationalized Domain Name (IDN) Homograph Attack
  // Detects xn-- prefix or non-ASCII characters in hostname
  const isPunycode = hostname.includes('xn--');
  const hasNonAscii = /[^\u0000-\u007F]/.test(hostname);
  if (isPunycode || hasNonAscii) {
    indicators.push({
      id: 'PUNYCODE_HOMOGRAPH',
      category: 'Domain Deception',
      severity: 'CRITICAL',
      title: 'Deceptive Punycode / Homograph Domain',
      description: 'The domain contains non-standard Unicode or Punycode characters (e.g. Cyrillic letters that visually mimic Latin letters). This is a hallmark of lookalike phishing.',
      evidence: `Hostname: ${hostname}`,
    });
  }

  // 4. Known URL Shortener
  if (KNOWN_SHORTENERS.has(hostname) || hostname.endsWith('.bit.ly')) {
    indicators.push({
      id: 'URL_SHORTENER',
      category: 'Cloaking',
      severity: 'MEDIUM',
      title: 'URL Shortener Detected',
      description: 'This QR code uses a link shortening service that conceals the ultimate landing destination from immediate visual inspection.',
      evidence: `Shortener host: ${hostname}`,
    });
  }

  // 5. Non-Standard Port
  if (port && NON_STANDARD_PORTS.has(port)) {
    indicators.push({
      id: 'UNUSUAL_PORT',
      category: 'Transport Security',
      severity: 'MEDIUM',
      title: `Non-Standard Web Port (:${port})`,
      description: `Standard web traffic uses ports 80 (HTTP) or 443 (HTTPS). Port :${port} often points to transient proxy servers or unmonitored backdoors.`,
      evidence: `Port: ${port}`,
    });
  }

  // 6. Excessive Subdomain Depth
  const domainParts = hostname.split('.');
  if (domainParts.length >= 4 && !isIpv4) {
    indicators.push({
      id: 'EXCESSIVE_SUBDOMAINS',
      category: 'Domain Structure',
      severity: 'LOW',
      title: 'Excessive Subdomain Stacking',
      description: 'The hostname has 4 or more label levels, a common technique to make malicious hosts resemble complex legitimate portals.',
      evidence: `${domainParts.length} domain levels: ${hostname}`,
    });
  }

  // 7. Brand Impersonation / Lookalike in Subdomains or Path
  // Check if a major brand is embedded in the subdomain or path, but the root domain does NOT belong to that brand
  for (const brand of HIGH_VALUE_BRANDS) {
    const brandInSubdomain = hostname.includes(brand);
    // Is the root domain exactly that brand? e.g. paypal.com
    const isAuthenticBrandDomain =
      hostname === `${brand}.com` ||
      hostname.endsWith(`.${brand}.com`) ||
      hostname === `${brand}.in` ||
      hostname.endsWith(`.${brand}.in`) ||
      hostname === `${brand}.org` ||
      hostname.endsWith(`.${brand}.org`) ||
      hostname === `${brand}.net` ||
      hostname.endsWith(`.${brand}.net`);

    if (brandInSubdomain && !isAuthenticBrandDomain && !isIpv4) {
      indicators.push({
        id: `BRAND_MIMIC_${brand.toUpperCase()}`,
        category: 'Brand Impersonation',
        severity: 'HIGH',
        title: `Possible ${brand.toUpperCase()} Impersonation`,
        description: `The URL contains the brand name "${brand}", but the root domain is not the official authentic ${brand} domain.`,
        evidence: `Hostname: ${hostname}`,
      });
      break;
    }
  }

  // 8. Credential Harvesting / Urgency Keywords in Path or Search
  const matchedKeywords = CREDENTIAL_KEYWORDS.filter(
    (kw) => pathname.includes(kw) || fullSearch.includes(kw)
  );
  if (matchedKeywords.length > 0) {
    indicators.push({
      id: 'CREDENTIAL_HARVESTING_TOKENS',
      category: 'Phishing Pattern',
      severity: 'HIGH',
      title: 'Credential / Urgency Keywords Present',
      description: 'The URL path or query contains sensitive account keywords that strongly correlate with phishing lures and fake authentication pages.',
      evidence: `Keywords detected: ${matchedKeywords.join(', ')}`,
    });
  }

  // 9. Basic Auth / Embedded Credentials in URL (e.g. http://victim:pass@malicious.com)
  if (parsed.username || parsed.password) {
    indicators.push({
      id: 'EMBEDDED_CREDENTIALS',
      category: 'Deception',
      severity: 'CRITICAL',
      title: 'Embedded Credentials in URL Authority',
      description: 'The URL uses username:password syntax in the authority section, often used to fool users into thinking they are visiting a trusted domain.',
      evidence: `User: ${parsed.username}`,
    });
  }

  // 10. Suspicious Top-Level Domains (TLDs often exploited in spam)
  const suspiciousTlds = ['.xyz', '.top', '.work', '.click', '.buzz', '.country', '.monster', '.rest', '.cam', '.cfd', '.sbs'];
  const hasSuspiciousTld = suspiciousTlds.some((tld) => hostname.endsWith(tld));
  if (hasSuspiciousTld && (matchedKeywords.length > 0 || indicators.length > 0)) {
    indicators.push({
      id: 'HIGH_RISK_TLD',
      category: 'Domain Reputation',
      severity: 'MEDIUM',
      title: 'High-Abuse Top Level Domain',
      description: 'The domain uses a TLD with statistically elevated phishing rates combined with other risk indicators.',
      evidence: `Hostname ends with known high-abuse TLD: ${hostname}`,
    });
  }

  // Sort indicators by severity priority (CRITICAL > HIGH > MEDIUM > LOW > INFO)
  const SEVERITY_ORDER: Record<string, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
  };
  return indicators.sort(
    (a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0)
  );
}
