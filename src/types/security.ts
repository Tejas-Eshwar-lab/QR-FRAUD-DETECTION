export type PayloadType =
  | 'HTTP_URL'
  | 'UPI_PAYMENT'
  | 'WIFI_CONFIG'
  | 'VCARD_CONTACT'
  | 'COMMUNICATION'
  | 'PLAIN_TEXT'
  | 'CUSTOM_DEEP_LINK'
  | 'MALFORMED';

export type RiskVerdict =
  | 'CONFIRMED_THREAT'
  | 'SUSPICIOUS'
  | 'UNVERIFIED'
  | 'NO_KNOWN_THREAT';

export type IndicatorSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface HeuristicIndicator {
  id: string;
  category: string;
  severity: IndicatorSeverity;
  title: string;
  description: string;
  evidence?: string;
}

export interface ThreatIntelResult {
  status: 'CONFIRMED_THREAT' | 'NO_THREAT_FOUND' | 'NOT_CONFIGURED' | 'CHECK_FAILED';
  provider: string;
  matches?: string[];
  threatTypes?: string[];
  message?: string;
  details?: string;
  checkTimestamp: string;
  error?: string;
}

export interface UpiPayload {
  raw: string;
  payeeAddress?: string;
  payeeName?: string;
  merchantCode?: string;
  amount?: string;
  currency?: string;
  transactionRef?: string;
  transactionNote?: string;
  isCleanPayeeFormat: boolean;
  hasSuspiciousLure: boolean;
  unverifiedWarning: string;
}

export interface WifiPayload {
  ssid: string;
  encryption: string;
  hidden: boolean;
  passwordProvided: boolean;
}

export interface ContactPayload {
  name?: string;
  phone?: string;
  email?: string;
  org?: string;
}

export interface CommunicationPayload {
  type: 'tel' | 'sms' | 'mailto';
  target: string;
  bodyOrSubject?: string;
}

export interface BilingualExplanation {
  source: 'gemini-3.8-flash' | 'deterministic_engine';
  englishSummary: string;
  englishAdvice: string[];
  kannadaSummary: string;
  kannadaAdvice: string[];
}

export interface DownloadAssessment {
  isDownload: boolean;
  filename?: string;
  extension?: string;
  fileType?: string;
  wasAnalyzed: boolean;
  analysisMethod?: string;
  suspectedMalwareFamily?: string;
  potentialCapabilities?: string[];
  riskSummary?: string;
}

export interface DetectionStage {
  stage: 'A' | 'B' | 'C' | 'D' | 'E';
  name: string;
  status: 'PASSED' | 'WARNING' | 'ALERT' | 'SKIPPED' | 'UNKNOWN';
  summary: string;
  details?: string[];
}

export interface UnknownSignatureFallback {
  isTriggered: boolean;
  messageTitle: string;
  messageBody: string;
  options: string[];
}

export interface ThreatSignatureMatch {
  id: string;
  category: string;
  name: string;
  severity: IndicatorSeverity;
  pdfSection: string;
  evidence: string;
  confidence: 'confirmed' | 'high' | 'medium';
  consequence: string;
  defensiveAction: string;
}

export interface ScanResult {
  id: string;
  timestamp: string;
  rawPayload: string;
  payloadType: PayloadType;
  overallRisk: RiskVerdict;
  riskScore: number; // 0 to 100
  indicators: HeuristicIndicator[];
  stages: DetectionStage[];
  checksRun: string[];
  checksSkippedOrFailed: string[];
  downloadAssessment: DownloadAssessment;
  unknownSignatureFallback: UnknownSignatureFallback;
  threatSignatureMatches?: ThreatSignatureMatch[];
  threatIntelResult?: ThreatIntelResult;
  upiData?: UpiPayload;
  wifiData?: WifiPayload;
  contactData?: ContactPayload;
  communicationData?: CommunicationPayload;
  explanation?: BilingualExplanation;
  malwareAnalysis?: import('../lib/malwareAnalyzer').MalwareAnalysisResult;
  quishingMl?: import('../lib/quishingML').QuishingPrediction;
  safeNextSteps: string[];
  plainLanguageConsequences: string;
  isLoadingExplanation?: boolean;
  scanDurationMs?: number;
}

export interface LabelledTestCase {
  id: string;
  name: string;
  payload: string;
  expectedType: PayloadType;
  expectedVerdict: RiskVerdict;
  category: 'BENIGN' | 'PHISHING' | 'UPI_SCAM' | 'MALWARE_TEST' | 'MALFORMED';
  source: string;
  description: string;
}
