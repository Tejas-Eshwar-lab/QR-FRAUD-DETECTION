import {
  PayloadType,
  RiskVerdict,
  HeuristicIndicator,
  ThreatIntelResult,
  UpiPayload,
  WifiPayload,
  DownloadAssessment,
  DetectionStage,
  UnknownSignatureFallback,
} from '../types/security';

export interface RiskEvaluationInput {
  rawPayload: string;
  payloadType: PayloadType;
  indicators: HeuristicIndicator[];
  downloadAssessment?: DownloadAssessment;
  redirectTarget?: string;
  threatIntelResult?: ThreatIntelResult;
  upiData?: UpiPayload;
  wifiData?: WifiPayload;
}

export function evaluateRisk(input: RiskEvaluationInput): {
  overallRisk: RiskVerdict;
  riskScore: number;
  checksRun: string[];
  checksSkippedOrFailed: string[];
  stages: DetectionStage[];
  unknownSignatureFallback: UnknownSignatureFallback;
  plainLanguageConsequences: string;
  safeNextSteps: string[];
} {
  const {
    payloadType,
    indicators,
    downloadAssessment,
    redirectTarget,
    threatIntelResult,
    upiData,
    wifiData,
  } = input;

  const checksRun: string[] = ['Payload RFC & Structure Parsing'];
  const checksSkippedOrFailed: string[] = [];
  const safeNextSteps: string[] = [];
  let score = 0;

  // 1. Calculate base score from heuristic indicators
  for (const ind of indicators) {
    switch (ind.severity) {
      case 'CRITICAL':
        score += 40;
        break;
      case 'HIGH':
        score += 25;
        break;
      case 'MEDIUM':
        score += 15;
        break;
      case 'LOW':
        score += 5;
        break;
      default:
        break;
    }
  }

  // If download is detected, raise attention
  if (downloadAssessment?.isDownload) {
    if (downloadAssessment.extension === '.apk') {
      score += 25;
    } else {
      score += 15;
    }
  }

  // If open redirect is detected
  if (redirectTarget) {
    score += 15;
  }

  // Record Threat Intelligence
  let isConfirmedThreat = false;
  let isThreatIntelConfigured = false;
  let threatIntelFoundClean = false;

  if (threatIntelResult) {
    if (threatIntelResult.status === 'CONFIRMED_THREAT') {
      checksRun.push(`Threat Intelligence (${threatIntelResult.provider}) [MATCH FOUND]`);
      score = 100;
      isConfirmedThreat = true;
      isThreatIntelConfigured = true;
    } else if (threatIntelResult.status === 'NO_THREAT_FOUND') {
      checksRun.push(`Threat Intelligence (${threatIntelResult.provider}) [NO MATCH]`);
      threatIntelFoundClean = true;
      isThreatIntelConfigured = true;
    } else if (threatIntelResult.status === 'NOT_CONFIGURED') {
      checksSkippedOrFailed.push(`Threat Intelligence (${threatIntelResult.provider}) [NOT CONFIGURED]`);
    } else if (threatIntelResult.status === 'CHECK_FAILED') {
      checksSkippedOrFailed.push(`Threat Intelligence (${threatIntelResult.provider}) [QUERY FAILED]`);
    }
  }

  // Check if we have an UNKNOWN threat status:
  // "If the application cannot find a matching malware signature, threat-intelligence record, or reliable detection result, it must NOT automatically mark the QR code safe."
  const isUnknownSignature =
    payloadType === 'HTTP_URL' &&
    (!isThreatIntelConfigured || threatIntelResult?.status === 'CHECK_FAILED') &&
    score < 25;

  // Determine overall risk verdict
  let overallRisk: RiskVerdict;
  if (isConfirmedThreat || score >= 60) {
    overallRisk = 'CONFIRMED_THREAT';
  } else if (score >= 25 || (upiData && upiData.hasSuspiciousLure) || downloadAssessment?.isDownload) {
    overallRisk = 'SUSPICIOUS';
  } else if (isUnknownSignature || payloadType === 'PLAIN_TEXT' || payloadType === 'VCARD_CONTACT' || payloadType === 'CUSTOM_DEEP_LINK' || payloadType === 'COMMUNICATION') {
    overallRisk = 'UNVERIFIED';
  } else {
    // When checks ran cleanly with configured feeds
    overallRisk = 'NO_KNOWN_THREAT';
  }

  const finalScore = Math.min(100, Math.max(0, score));

  // Build the 5 Detection Stages (A to E)
  const stages: DetectionStage[] = [
    {
      stage: 'A',
      name: 'QR Payload Decoding',
      status: payloadType === 'MALFORMED' ? 'ALERT' : 'PASSED',
      summary: `Decoded as ${payloadType.replace('_', ' ')} format.`,
      details: [
        `Encoding Scheme: ${payloadType}`,
        `Payload Length: ${input.rawPayload.length} bytes`,
        `Safety Constraint: Zero automatic browser redirection or execution.`,
      ],
    },
    {
      stage: 'B',
      name: 'Destination & Domain Inspection',
      status:
        overallRisk === 'CONFIRMED_THREAT'
          ? 'ALERT'
          : indicators.length > 0
          ? 'WARNING'
          : isUnknownSignature
          ? 'UNKNOWN'
          : 'PASSED',
      summary:
        payloadType === 'HTTP_URL'
          ? redirectTarget
            ? `URL redirects to secondary destination: ${redirectTarget}`
            : `Domain inspected for homographs, IP hosts, and cloaking.`
          : 'Non-URL destination evaluated via type-specific security rules.',
      details:
        indicators.length > 0
          ? indicators.map((i) => `${i.title} (${i.severity}): ${i.description}`)
          : ['No structural deception signatures detected in domain format.'],
    },
    {
      stage: 'C',
      name: 'Download Assessment',
      status: downloadAssessment?.isDownload ? 'WARNING' : 'PASSED',
      summary: downloadAssessment?.isDownload
        ? `Identified downloadable package: ${downloadAssessment.filename || downloadAssessment.fileType}`
        : 'No direct executable or package download detected in URL stream.',
      details: downloadAssessment?.isDownload
        ? [
            `Detected File Type: ${downloadAssessment.fileType}`,
            `Extension: ${downloadAssessment.extension}`,
            'Safe Inspection Policy: File was NOT downloaded to user device.',
          ]
        : ['URL does not link to .apk, .exe, or binary package archives.'],
    },
    {
      stage: 'D',
      name: 'Malware & File Analysis',
      status: isConfirmedThreat ? 'ALERT' : isUnknownSignature ? 'UNKNOWN' : 'PASSED',
      summary: isConfirmedThreat
        ? 'Verified malware or phishing threat match in threat intelligence database.'
        : isUnknownSignature
        ? 'No threat intelligence signature match available in current database.'
        : 'Reputation query completed without threat matches.',
      details: [
        `Provider: ${threatIntelResult?.provider || 'Offline Static Engine'}`,
        `Status: ${threatIntelResult?.status || 'OFFLINE_ONLY'}`,
        `Analysis Method: Controlled server-side safe lookup (Never executes payload).`,
      ],
    },
    {
      stage: 'E',
      name: 'Explainable Report & Synthesis',
      status:
        overallRisk === 'CONFIRMED_THREAT'
          ? 'ALERT'
          : overallRisk === 'SUSPICIOUS'
          ? 'WARNING'
          : overallRisk === 'UNVERIFIED'
          ? 'UNKNOWN'
          : 'PASSED',
      summary: `Synthesized findings into evidence-based risk assessment (${overallRisk}).`,
      details: [
        `Deterministic Risk Score: ${finalScore}/100`,
        `Primary Verdict: ${overallRisk}`,
        'Distinguishes confirmed threats from unverified or heuristic signals.',
      ],
    },
  ];

  // Critical unknown-signature behavior configuration
  const unknownSignatureFallback: UnknownSignatureFallback = {
    isTriggered: isUnknownSignature,
    messageTitle: 'Unable to confirm the threat status of this QR code.',
    messageBody:
      'No matching threat signature was found in the available security sources. This does not guarantee that the QR code is safe.',
    options: [
      'Scan another QR code.',
      'Upload a clearer QR-code image.',
      'Retry the analysis.',
      'View the decoded content without opening the destination.',
    ],
  };

  // Plain-Language Explanation of Consequences
  let plainLanguageConsequences = '';
  if (overallRisk === 'CONFIRMED_THREAT') {
    plainLanguageConsequences =
      'This QR code points to a confirmed malicious threat identified by threat intelligence. Following this link may download malware, compromise personal accounts, or capture passwords.';
    safeNextSteps.push('DO NOT open or proceed to this web address.');
    safeNextSteps.push('Do not download files or enter login credentials.');
    safeNextSteps.push('Report this QR code to the property owner or security team.');
  } else if (downloadAssessment?.isDownload) {
    plainLanguageConsequences =
      'A QR code points to an unverified application download. The file has not been executed, so we cannot confirm that it contains malware. Installing an unsafe application may expose personal information or financial accounts, depending on its behavior and permissions. Do not install it until it has been verified.';
    safeNextSteps.push('Do not install or download this APK/file.');
    safeNextSteps.push('Search for the official app directly in the Google Play Store or Apple App Store.');
    safeNextSteps.push('Ensure "Install unknown apps" is disabled in your phone settings.');
  } else if (overallRisk === 'SUSPICIOUS') {
    plainLanguageConsequences =
      'This QR code exhibits suspicious indicators (such as lookalike characters, IP hostnames, or deceptive paths). Deceptive tactics are commonly used in phishing campaigns to steal credentials or sensitive data.';
    safeNextSteps.push('Exercise extreme caution. Do not enter passwords, OTPs, or financial details.');
    safeNextSteps.push('Manually verify the intended website by typing the official address directly.');
    if (payloadType === 'UPI_PAYMENT') {
      safeNextSteps.push('NEVER enter your UPI PIN to claim prizes or receive cashback.');
    }
  } else if (overallRisk === 'UNVERIFIED' || isUnknownSignature) {
    plainLanguageConsequences =
      'Unable to confirm the threat status of this QR code. No matching threat signature was found in available security sources. This does not guarantee that the QR code is safe.';
    safeNextSteps.push('Verify the physical authenticity of the QR code sticker or poster.');
    safeNextSteps.push('Do not proceed if you received this QR code from an unsolicited message or email.');
  } else {
    plainLanguageConsequences =
      'No threat was detected by the checks performed. This is not a guarantee of safety. New zero-day phishing or malicious sites may not appear on blocklists yet.';
    safeNextSteps.push('Verify that you recognize the website or provider.');
    safeNextSteps.push('Ensure the browser displays HTTPS and the legitimate domain name.');
  }

  return {
    overallRisk,
    riskScore: finalScore,
    checksRun,
    checksSkippedOrFailed,
    stages,
    unknownSignatureFallback,
    plainLanguageConsequences,
    safeNextSteps,
  };
}
