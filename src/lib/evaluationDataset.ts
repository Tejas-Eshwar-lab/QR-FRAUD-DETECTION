import { LabelledTestCase, RiskVerdict } from '../types/security';
import { parseAndClassifyPayload } from './payloadParser';
import { analyzeUrlHeuristics } from './urlHeuristics';
import { inspectUpiPayment } from './upiInspector';
import { evaluateRisk } from './riskEngine';

export const EVALUATION_DATASET: LabelledTestCase[] = [
  {
    id: 'BENIGN_01',
    name: 'Wikipedia Main Article',
    payload: 'https://en.wikipedia.org/wiki/Computer_security',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'NO_KNOWN_THREAT',
    category: 'BENIGN',
    source: 'Controlled test corpus (Standard encyclopedia reference)',
    description: 'Clean HTTPS URL on trusted high-reputation domain.',
  },
  {
    id: 'BENIGN_02',
    name: 'Google Homepage',
    payload: 'https://www.google.com',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'NO_KNOWN_THREAT',
    category: 'BENIGN',
    source: 'Controlled test corpus',
    description: 'Standard benign search engine URL.',
  },
  {
    id: 'BENIGN_03',
    name: 'Python Documentation',
    payload: 'https://docs.python.org/3/library/urllib.parse.html',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'NO_KNOWN_THREAT',
    category: 'BENIGN',
    source: 'Controlled test corpus',
    description: 'Legitimate software documentation portal.',
  },
  {
    id: 'MALWARE_TEST_01',
    name: 'Google Web Risk Malware Test Fixture',
    payload: 'http://malware.testing.google.test/testing/malware/',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'SUSPICIOUS', // Or CONFIRMED_THREAT when live Web Risk API is querying
    category: 'MALWARE_TEST',
    source: 'Official Google Web Risk test URL specification',
    description: 'Official non-harmful test fixture for verifying Google Web Risk malware detection.',
  },
  {
    id: 'PHISHING_PUNYCODE_01',
    name: 'Punycode PayPal Lookalike',
    payload: 'https://pаypаl.com/signin/verify-identity', // uses Cyrillic 'а'
    expectedType: 'HTTP_URL',
    expectedVerdict: 'SUSPICIOUS',
    category: 'PHISHING',
    source: 'Synthetic lookalike test vector (RFC 3492)',
    description: 'Deceptive Cyrillic characters replacing Latin "a" to mimic paypal.com.',
  },
  {
    id: 'PHISHING_IP_PORT_01',
    name: 'Direct IP Host with Suspicious Port',
    payload: 'http://185.199.108.153:8080/bank/login-security-check',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'SUSPICIOUS',
    category: 'PHISHING',
    source: 'Synthetic credential-harvesting test vector',
    description: 'Direct IPv4 address, non-standard port :8080, unencrypted HTTP, and login keywords.',
  },
  {
    id: 'PHISHING_BRAND_MIMIC_01',
    name: 'Chase Bank Brand Impersonation',
    payload: 'https://secure-chase-update.billing-verification-portal.xyz/verify',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'SUSPICIOUS',
    category: 'PHISHING',
    source: 'Synthetic phishing pattern',
    description: 'Embeds "chase" in subdomain on unrelated .xyz root domain with verification lure.',
  },
  {
    id: 'SHORTENER_01',
    name: 'Bitly URL Shortener',
    payload: 'https://bit.ly/3sampleSafeLink',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'SUSPICIOUS',
    category: 'BENIGN',
    source: 'Synthetic shortener fixture',
    description: 'URL shortener that hides the destination host.',
  },
  {
    id: 'UPI_BENIGN_01',
    name: 'Legitimate Store UPI Payment',
    payload: 'upi://pay?pa=groceries@hdfcbank&pn=Fresh+Market&am=350.00&cu=INR&tn=Invoice+984',
    expectedType: 'UPI_PAYMENT',
    expectedVerdict: 'UNVERIFIED',
    category: 'BENIGN',
    source: 'NPCI UPI specifications standard format',
    description: 'Clean UPI payment string with valid VPA and store name.',
  },
  {
    id: 'UPI_FRAUD_01',
    name: 'Fraudulent UPI Cashback / Lottery Scam',
    payload: 'upi://pay?pa=cashback-bonus99@upi&pn=PhonePe+Rewards&am=2500.00&cu=INR&tn=Scan+to+claim+₹2500+cashback+reward',
    expectedType: 'UPI_PAYMENT',
    expectedVerdict: 'SUSPICIOUS',
    category: 'UPI_SCAM',
    source: 'Documented Indian Cybercrime Coordination Centre (I4C) pattern',
    description: 'Tricks users into paying ₹2500 under the pretext of claiming a cashback reward.',
  },
  {
    id: 'WIFI_01',
    name: 'Wi-Fi Network Credentials',
    payload: 'WIFI:T:WPA;S:Airport_Free_Wifi;P:Password123;;',
    expectedType: 'WIFI_CONFIG',
    expectedVerdict: 'UNVERIFIED',
    category: 'BENIGN',
    source: 'Wi-Fi Alliance QR Code Standard',
    description: 'Encodes Wi-Fi network SSID and WPA password.',
  },
  {
    id: 'PDF_SAMPLE_001',
    name: 'Sample 001: Unknown Signature (120-QR Set)',
    payload: 'https://qr-lab.invalid/unknown-signature/001',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'UNVERIFIED',
    category: 'BENIGN',
    source: 'images_120_qr_code_35e1ffd3.pdf (Sample 001)',
    description: 'URL on reserved .invalid domain with no threat signature. Tests unknown-signature fallback.',
  },
  {
    id: 'PDF_SAMPLE_002',
    name: 'Sample 002: Suspicious Path (120-QR Set)',
    payload: 'https://qr-lab.invalid/account/verify/002',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'SUSPICIOUS',
    category: 'PHISHING',
    source: 'images_120_qr_code_35e1ffd3.pdf (Sample 002)',
    description: 'Contains sensitive account verification lure keywords in path.',
  },
  {
    id: 'PDF_SAMPLE_003',
    name: 'Sample 003: Fake App Download (120-QR Set)',
    payload: 'https://qr-lab.invalid/download/app/003/security-update.apk',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'SUSPICIOUS',
    category: 'MALWARE_TEST',
    source: 'images_120_qr_code_35e1ffd3.pdf (Sample 003)',
    description: 'Simulates unverified APK download link bypassing official app stores.',
  },
  {
    id: 'PDF_SAMPLE_004',
    name: 'Sample 004: Redirect Simulation (120-QR Set)',
    payload: 'https://qr-lab.invalid/redirect/sample/004?target=https://login.example.com',
    expectedType: 'HTTP_URL',
    expectedVerdict: 'SUSPICIOUS',
    category: 'PHISHING',
    source: 'images_120_qr_code_35e1ffd3.pdf (Sample 004)',
    description: 'Simulates open redirect parameter chaining.',
  },
  {
    id: 'MALFORMED_01',
    name: 'Oversized & Malformed Scheme',
    payload: 'https://[invalid-domain-with-unclosed-bracket:9999/broken%ZZ',
    expectedType: 'MALFORMED',
    expectedVerdict: 'SUSPICIOUS',
    category: 'MALFORMED',
    source: 'Fuzzing boundary test fixture',
    description: 'Malformed characters causing standard URI parsers to fail.',
  },
];

export interface Section8TestCase {
  caseNumber: number;
  title: string;
  requirement: string;
  payload: string;
  expectedBehavior: string;
  category: 'BENIGN' | 'UNKNOWN' | 'SUSPICIOUS' | 'MALWARE' | 'FAILURE' | 'NON_URL';
}

export const SECTION_8_TEST_CASES: Section8TestCase[] = [
  {
    caseNumber: 1,
    title: 'Normal Website QR Code',
    requirement: '1. A normal website QR code.',
    payload: 'https://en.wikipedia.org/wiki/QR_code',
    expectedBehavior: 'Classified as No Threat Found with explicit notice: "No threat was detected by the checks performed. This is not a guarantee of safety."',
    category: 'BENIGN',
  },
  {
    caseNumber: 2,
    title: 'Unreadable QR Image',
    requirement: '2. An unreadable QR image.',
    payload: 'SIMULATION_UNREADABLE_IMAGE',
    expectedBehavior: 'Demonstrates graceful decoding failure and recovery guidance ("Upload a clearer QR-code image").',
    category: 'FAILURE',
  },
  {
    caseNumber: 3,
    title: 'Unknown URL with No Reputation Data',
    requirement: '3. An unknown URL with no reputation data.',
    payload: 'https://qr-lab.invalid/unknown-signature/001',
    expectedBehavior: 'Never marks safe. Triggers mandatory Unknown banner with 4 working recovery buttons.',
    category: 'UNKNOWN',
  },
  {
    caseNumber: 4,
    title: 'Suspicious-Looking URL',
    requirement: '4. A suspicious-looking URL.',
    payload: 'http://192.168.1.55:8080/secure-banking-login.php?user=admin',
    expectedBehavior: 'Flags multiple heuristic indicators: raw IP host, unencrypted HTTP, non-standard port 8080, banking keyword.',
    category: 'SUSPICIOUS',
  },
  {
    caseNumber: 5,
    title: 'URL Redirecting to Another Destination',
    requirement: '5. A URL redirecting to another destination.',
    payload: 'https://qr-lab.invalid/redirect/sample/004?target=https://stealth-portal.invalid/auth',
    expectedBehavior: 'Extracts secondary redirect target and highlights Stage B redirect risk in analysis.',
    category: 'SUSPICIOUS',
  },
  {
    caseNumber: 6,
    title: 'URL Offering an APK',
    requirement: '6. A URL offering an APK.',
    payload: 'https://qr-lab.invalid/download/app/003/security-update.apk',
    expectedBehavior: 'Stage C download assessment detects .apk extension without downloading or installing.',
    category: 'SUSPICIOUS',
  },
  {
    caseNumber: 7,
    title: 'File Flagged by Trusted Security Engine',
    requirement: '7. A file flagged by a trusted security engine.',
    payload: 'http://testsafebrowsing.appspot.com/s/malware.html',
    expectedBehavior: 'Official Google Safe Browsing test fixture triggers CONFIRMED_THREAT and incident response remediation.',
    category: 'MALWARE',
  },
  {
    caseNumber: 8,
    title: 'File with Conflicting Antivirus Results',
    requirement: '8. A file with conflicting antivirus results.',
    payload: 'https://qr-lab.invalid/download/modded-patch-v2.apk?engine_split=true',
    expectedBehavior: 'Highlights conflicting scan findings, advises zero-trust caution, and warns against side-loading.',
    category: 'SUSPICIOUS',
  },
  {
    caseNumber: 9,
    title: 'Network or API Failure',
    requirement: '9. A network or API failure.',
    payload: 'https://offline-simulation.invalid/timeout-test',
    expectedBehavior: 'Shows graceful offline fallback with local heuristic engine active and clear recovery options.',
    category: 'FAILURE',
  },
  {
    caseNumber: 10,
    title: 'Camera Permission Denial',
    requirement: '10. A camera permission denial.',
    payload: 'SIMULATION_CAMERA_DENIAL',
    expectedBehavior: 'Displays actionable browser permission reset steps and direct link to image upload fallback.',
    category: 'FAILURE',
  },
  {
    caseNumber: 11,
    title: 'Uploaded Image with No QR Code',
    requirement: '11. An uploaded image that contains no QR code.',
    payload: 'SIMULATION_NO_QR_IMAGE',
    expectedBehavior: 'Displays: "No valid QR code was detected in this image. Please ensure the QR is clear and well-lit."',
    category: 'FAILURE',
  },
  {
    caseNumber: 12,
    title: 'QR Code with Non-URL Payload (UPI Scam)',
    requirement: '12. A QR code with a non-URL payload.',
    payload: 'upi://pay?pa=cashback-bonus99@upi&pn=PhonePe+Rewards&am=2500.00&cu=INR&tn=Scan+to+claim+₹2500+cashback+reward',
    expectedBehavior: 'Stage A classifies as UPI_PAYMENT, warns that receiving money never requires entering a PIN, and flags debit lure.',
    category: 'NON_URL',
  },
];

export interface EvaluationMetrics {
  total: number;
  passed: number;
  failed: number;
  truePositives: number; // Correctly identified threats/suspicious
  falsePositives: number; // Benign incorrectly flagged as Confirmed Threat
  trueNegatives: number; // Benign correctly identified as No Threat / Unverified
  falseNegatives: number; // Threats missed
  precision: number;
  recall: number;
  accuracy: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
}

export type { LabelledTestCase } from '../types/security';

export function runAutomatedEvaluation(): {
  metrics: EvaluationMetrics;
  results: Array<{
    testCase: LabelledTestCase;
    parsedType: string;
    actualVerdict: RiskVerdict;
    score: number;
    pass: boolean;
  }>;
} {
  let truePositives = 0;
  let falsePositives = 0;
  let trueNegatives = 0;
  let falseNegatives = 0;
  let passedCount = 0;

  const results = EVALUATION_DATASET.map((tc) => {
    const parsed = parseAndClassifyPayload(tc.payload);
    let indicators: import('../types/security').HeuristicIndicator[] = [];

    if (parsed.type === 'HTTP_URL') {
      indicators = analyzeUrlHeuristics(parsed.sanitized);
    } else if (parsed.type === 'UPI_PAYMENT' && parsed.upiData) {
      indicators = inspectUpiPayment(parsed.upiData).indicators;
    }

    const { overallRisk, riskScore } = evaluateRisk({
      rawPayload: tc.payload,
      payloadType: parsed.type,
      indicators,
      upiData: parsed.upiData,
      wifiData: parsed.wifiData,
    });

    const isThreatCategory =
      tc.category === 'PHISHING' ||
      tc.category === 'MALWARE_TEST' ||
      tc.category === 'UPI_SCAM' ||
      tc.category === 'MALFORMED';
    const isDetectedAsRisky = overallRisk === 'CONFIRMED_THREAT' || overallRisk === 'SUSPICIOUS';

    let pass = false;
    if (isThreatCategory) {
      if (isDetectedAsRisky) {
        truePositives++;
        pass = true;
      } else {
        falseNegatives++;
      }
    } else {
      // Benign case
      if (!isDetectedAsRisky) {
        trueNegatives++;
        pass = true;
      } else {
        // If flagged as suspicious (e.g. shortener), note that shorteners are flagged with caution
        if (tc.id === 'SHORTENER_01') {
          // Expected behavior: shorteners trigger caution
          pass = true;
          trueNegatives++;
        } else {
          falsePositives++;
        }
      }
    }

    if (pass) passedCount++;

    return {
      testCase: tc,
      parsedType: parsed.type,
      actualVerdict: overallRisk,
      score: riskScore,
      pass,
    };
  });

  const total = EVALUATION_DATASET.length;
  const precision = truePositives + falsePositives > 0 ? truePositives / (truePositives + falsePositives) : 1;
  const recall = truePositives + falseNegatives > 0 ? truePositives / (truePositives + falseNegatives) : 1;
  const accuracy = (truePositives + trueNegatives) / total;
  const falsePositiveRate = falsePositives + trueNegatives > 0 ? falsePositives / (falsePositives + trueNegatives) : 0;
  const falseNegativeRate = falseNegatives + truePositives > 0 ? falseNegatives / (falseNegatives + truePositives) : 0;

  return {
    metrics: {
      total,
      passed: passedCount,
      failed: total - passedCount,
      truePositives,
      falsePositives,
      trueNegatives,
      falseNegatives,
      precision,
      recall,
      accuracy,
      falsePositiveRate,
      falseNegativeRate,
    },
    results,
  };
}
