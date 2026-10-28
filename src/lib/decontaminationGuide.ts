export interface RemediationStep {
  id: string;
  category: 'IMMEDIATE_ACTION' | 'DEVICE_CLEANUP' | 'ACCOUNT_SECURITY' | 'TAKEDOWN_REPORT';
  title: string;
  instructions: string;
  critical: boolean;
  platform?: 'Android' | 'iOS' | 'Desktop' | 'All';
}

/**
 * Defangs a malicious URL or payload to render it inert and safe for documentation,
 * logging, and email sharing without risking accidental clicks.
 * Replaces http with hxxp and domain dots with [.]
 */
export function defangPayload(rawPayload: string): string {
  if (!rawPayload) return '';
  return rawPayload
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^ftp:\/\//i, 'fxp://')
    .replace(/\./g, '[.]')
    .replace(/:/g, '[:]');
}

/**
 * Strips aggressive tracking parameters (UTMs, click IDs, session tokens)
 * from a URL to isolate the root destination.
 */
export function sanitizeAndStripUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const trackingKeys = [
      'utm_source',
      'utm_medium',
      'utm_campaign',
      'utm_term',
      'utm_content',
      'fbclid',
      'gclid',
      'token',
      'session',
      'affiliate',
      'ref',
    ];
    trackingKeys.forEach((k) => parsed.searchParams.delete(k));
    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

/**
 * Returns a prioritized incident-response and decontamination checklist
 * tailored to the device platform and threat category.
 */
export function getDecontaminationChecklist(
  payloadType: string,
  malwareType: string,
  targetPlatform: string
): RemediationStep[] {
  const steps: RemediationStep[] = [];

  // Step 1: Immediate Payload Isolation
  steps.push({
    id: 'ISOLATE_TABS',
    category: 'IMMEDIATE_ACTION',
    title: 'Close Active Browser Tabs & Cancel Downloads',
    instructions:
      'Immediately close any browser tabs opened by this QR code. If your browser prompted to download a file, tap Cancel or dismiss the notification immediately.',
    critical: true,
    platform: 'All',
  });

  // Android Specific Decontamination (APKs, Banking Trojans, Accessibility abuse)
  if (targetPlatform === 'Android' || malwareType.includes('Android') || malwareType.includes('APK') || malwareType.includes('UPI')) {
    steps.push({
      id: 'DELETE_DOWNLOADED_APK',
      category: 'DEVICE_CLEANUP',
      title: 'Quarantine & Delete Downloaded APK Files',
      instructions:
        'Open your device Files or My Files app > navigate to "Downloads". Look for any files ending in .apk downloaded today. Delete them permanently before they are launched.',
      critical: true,
      platform: 'Android',
    });

    steps.push({
      id: 'REVOKE_INSTALL_PERMISSIONS',
      category: 'DEVICE_CLEANUP',
      title: 'Revoke "Install Unknown Apps" Permissions',
      instructions:
        'Go to Android Settings > Apps > Special App Access > "Install unknown apps". Ensure that Chrome, Samsung Internet, Drive, and Messengers are strictly set to "Not Allowed".',
      critical: true,
      platform: 'Android',
    });

    steps.push({
      id: 'RUN_PLAY_PROTECT',
      category: 'DEVICE_CLEANUP',
      title: 'Execute Google Play Protect Deep Scan',
      instructions:
        'Open Google Play Store > tap your profile icon (top right) > "Play Protect" > tap the "Scan" button. Google Play Protect scans installed device packages for known banking trojans (e.g. SharkBot, TeaBot).',
      critical: true,
      platform: 'Android',
    });

    steps.push({
      id: 'AUDIT_ACCESSIBILITY_SERVICES',
      category: 'DEVICE_CLEANUP',
      title: 'Audit Accessibility Services Permissions',
      instructions:
        'Go to Android Settings > Accessibility > Downloaded Apps / Installed Services. Verify that no unfamiliar or suspicious app has been granted Accessibility access (which trojans abuse to click and steal OTPs).',
      critical: true,
      platform: 'Android',
    });
  }

  // iOS Specific Decontamination
  if (targetPlatform === 'iOS' || malwareType.includes('iOS') || malwareType.includes('Profile')) {
    steps.push({
      id: 'AUDIT_IOS_PROFILES',
      category: 'DEVICE_CLEANUP',
      title: 'Inspect & Remove Rogue Configuration Profiles',
      instructions:
        'Go to iPhone Settings > General > VPN & Device Management. If you see any unverified Configuration Profile that you did not install through your IT department, tap it and select "Remove Profile".',
      critical: true,
      platform: 'iOS',
    });

    steps.push({
      id: 'CLEAR_SAFARI_DATA',
      category: 'DEVICE_CLEANUP',
      title: 'Purge Browser Cache & Session Cookies',
      instructions:
        'Go to Settings > Safari > tap "Clear History and Website Data". This severs any hijacked session tokens or persistent tracking scripts.',
      critical: false,
      platform: 'iOS',
    });
  }

  // Phishing & Credential Compromise Response
  if (malwareType.includes('Phishing') || malwareType.includes('Credential') || malwareType.includes('Harvester')) {
    steps.push({
      id: 'ROTATE_PASSWORD_SEPARATE_DEVICE',
      category: 'ACCOUNT_SECURITY',
      title: 'Rotate Compromised Passwords from a Clean Device',
      instructions:
        'If you entered your password, PIN, or OTP on the destination page, assume the credentials are compromised. Using a separate, clean phone or PC, log in and change the password immediately.',
      critical: true,
      platform: 'All',
    });

    steps.push({
      id: 'TERMINATE_ACTIVE_SESSIONS',
      category: 'ACCOUNT_SECURITY',
      title: 'Revoke Active Account Sessions & Tokens',
      instructions:
        'In the affected account security settings (Google, Microsoft, Banking), click "Log out of all other sessions" or "Sign out everywhere" to invalidate stolen AiTM session tokens.',
      critical: true,
      platform: 'All',
    });
  }

  // UPI / Banking Specific Response
  if (payloadType === 'UPI_PAYMENT') {
    steps.push({
      id: 'UPI_ALERT_BANK',
      category: 'ACCOUNT_SECURITY',
      title: 'Verify Bank Statement & Report Unauthorized Debits',
      instructions:
        'If you inadvertently entered your UPI PIN and money was debited, call your bank customer helpline immediately to freeze UPI services, and register an official complaint at cybercrime.gov.in (National Cyber Crime Reporting Portal or call 1930 in India).',
      critical: true,
      platform: 'Android',
    });
  }

  // Takedown & Ecosystem Removal
  steps.push({
    id: 'SUBMIT_TAKEDOWN_REPORT',
    category: 'TAKEDOWN_REPORT',
    title: 'Report Malicious Host for Global Ecosystem Takedown',
    instructions:
      'Report this URL to Google Safe Browsing and URLhaus. Once verified, browsers worldwide (Chrome, Safari, Firefox, Edge) will block the destination with red warning screens.',
    critical: false,
    platform: 'All',
  });

  return steps;
}

/**
 * Pre-formats an RFC-style takedown report to submit to security providers and abuse desks.
 */
export function generateAbuseReport(
  url: string,
  malwareType: string,
  observedIndicators: string[]
): string {
  const defanged = defangPayload(url);
  const timestamp = new Date().toISOString();

  return `=== SCAMTRACE AI INCIDENT TAKEDOWN REPORT ===
Incident Timestamp: ${timestamp}
Threat Classification: ${malwareType}
Target Destination (Defanged): ${defanged}
Original Scheme: ${url.startsWith('https') ? 'HTTPS' : url.startsWith('http') ? 'HTTP' : 'Custom'}

OBSERVED THREAT INDICATORS:
${observedIndicators.map((ind) => `- ${ind}`).join('\n')}

TECHNICAL EVIDENCE:
- Optical vector: Physical QR code quishing campaign
- Host analysis: High-risk indicators identified during automated lexical/heuristic inspection
- Risk: Drive-by payload delivery / Credential harvesting

RECOMMENDED ACTION:
1. Block domain/URL in DNS resolvers and browser threat intelligence feeds (Google Web Risk, PhishTank, URLhaus).
2. Domain registrar: Suspend hostname for violation of Acceptable Use Policy regarding phishing/malware.
3. Hosting provider: Disconnect target server from origin network.

Report generated by ScamTrace AI Zero-Trust Defense.`;
}
