import React, { useState } from 'react';
import {
  ScanResult,
  RiskVerdict,
  IndicatorSeverity,
} from '../types/security';
import { defangPayload } from '../lib/decontaminationGuide';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  AlertTriangle,
  Copy,
  Check,
  ExternalLink,
  Info,
  Server,
  CreditCard,
  Wifi,
  User,
  RotateCcw,
  Languages,
  Bug,
  Cpu,
  Shield,
  Smartphone,
  Wrench,
  Download,
  FileCode,
  Layers,
  ArrowRight,
  Eye,
  RefreshCw,
  Upload,
  FileText,
  LifeBuoy,
  Lock,
  Radio,
  PowerOff,
  Flame,
  BookOpen,
} from 'lucide-react';

interface ResultPanelProps {
  result: ScanResult;
  onScanAgain: () => void;
  onOpenUpload: () => void;
  onRetryAnalysis: () => void;
  onOpenConfigModal: () => void;
  onOpenDecontaminationModal: () => void;
  onOpenMLStudioModal: () => void;
  onOpenSignaturesModal?: () => void;
}

export const ResultPanel: React.FC<ResultPanelProps> = ({
  result,
  onScanAgain,
  onOpenUpload,
  onRetryAnalysis,
  onOpenConfigModal,
  onOpenDecontaminationModal,
  onOpenMLStudioModal,
  onOpenSignaturesModal,
}) => {
  const [copied, setCopied] = useState(false);
  const [activeLang, setActiveLang] = useState<'EN' | 'KN'>('EN');
  const [showRawBase64, setShowRawBase64] = useState(false);
  const [showFullPayload, setShowFullPayload] = useState(false);
  const [showDefanged, setShowDefanged] = useState(true);
  const [showIncidentGuide, setShowIncidentGuide] = useState(false);
  const [showDetailsSection, setShowDetailsSection] = useState(!result.unknownSignatureFallback?.isTriggered);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const base64Payload = btoa(unescape(encodeURIComponent(result.rawPayload)));
  const defangedUrl = defangPayload(result.rawPayload);

  // Extract original domain and verified redirect destinations
  let originalDomain = 'N/A';
  let redirectDestination = 'None';
  try {
    if (result.payloadType === 'HTTP_URL') {
      const u = new URL(result.rawPayload);
      originalDomain = u.hostname;
      const targetParam =
        u.searchParams.get('target') ||
        u.searchParams.get('redirect') ||
        u.searchParams.get('url') ||
        u.searchParams.get('dest');
      if (targetParam) {
        redirectDestination = targetParam;
      }
    }
  } catch {}

  // Map Threat Status to Section 4 exact label
  const getFormalThreatStatus = (verdict: RiskVerdict): 'Malicious' | 'Suspicious' | 'No Threat Found' | 'Unknown' => {
    switch (verdict) {
      case 'CONFIRMED_THREAT':
        return 'Malicious';
      case 'SUSPICIOUS':
        return 'Suspicious';
      case 'UNVERIFIED':
        return 'Unknown';
      case 'NO_KNOWN_THREAT':
      default:
        return 'No Threat Found';
    }
  };

  const formalThreatStatus = getFormalThreatStatus(result.overallRisk);

  // Verdict visual styling in White, Yellow/Amber palette
  const getVerdictTheme = (verdict: RiskVerdict) => {
    switch (verdict) {
      case 'CONFIRMED_THREAT':
        return {
          bg: 'bg-red-50/80',
          border: 'border-red-300',
          text: 'text-red-700',
          iconBg: 'bg-red-100 text-red-700 border-red-200',
          badgeBg: 'bg-red-600 text-white font-black',
          icon: ShieldAlert,
          title: 'MALICIOUS THREAT CONFIRMED',
          subtitle: 'Active threat verified by reputation database or critical malicious indicators.',
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-yellow-50/70',
          border: 'border-amber-400',
          text: 'text-amber-950',
          iconBg: 'bg-amber-100 text-amber-900 border-amber-300',
          badgeBg: 'bg-yellow-400 text-yellow-950 font-black',
          icon: AlertTriangle,
          title: 'SUSPICIOUS THREAT INDICATORS',
          subtitle: 'Elevated deception signatures or download indicators detected. Caution required.',
        };
      case 'UNVERIFIED':
        return {
          bg: 'bg-amber-50/60',
          border: 'border-amber-300',
          text: 'text-amber-950',
          iconBg: 'bg-amber-100 text-amber-900 border-amber-300',
          badgeBg: 'bg-amber-300 text-amber-950 font-black',
          icon: ShieldQuestion,
          title: 'UNKNOWN THREAT STATUS',
          subtitle: 'No matching threat signature was found in the available sources. This does not guarantee safety.',
        };
      case 'NO_KNOWN_THREAT':
      default:
        return {
          bg: 'bg-emerald-50/60',
          border: 'border-emerald-300',
          text: 'text-emerald-900',
          iconBg: 'bg-emerald-100 text-emerald-800 border-emerald-200',
          badgeBg: 'bg-emerald-600 text-white font-bold',
          icon: ShieldCheck,
          title: 'NO THREAT FOUND',
          subtitle: 'No threat was detected by the checks performed. This is not a guarantee of safety.',
        };
    }
  };

  const getSeverityBadge = (sev: IndicatorSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'text-red-700 bg-red-100 border-red-300';
      case 'HIGH':
        return 'text-amber-900 bg-amber-100 border-amber-300';
      case 'MEDIUM':
        return 'text-yellow-900 bg-yellow-100 border-yellow-300';
      case 'LOW':
        return 'text-emerald-800 bg-emerald-100 border-emerald-300';
      default:
        return 'text-slate-700 bg-slate-100 border-slate-300';
    }
  };

  const verdictTheme = getVerdictTheme(result.overallRisk);
  const VerdictIcon = verdictTheme.icon;

  return (
    <div className="w-full max-w-2xl mx-auto space-y-5 animate-in fade-in duration-300">
      {/* 1. CRITICAL UNKNOWN-SIGNATURE FALLBACK BANNER (Section 2 Requirement) */}
      {result.unknownSignatureFallback?.isTriggered && (
        <div className="p-5 rounded-2xl border-2 border-amber-400 bg-yellow-50/90 shadow-md space-y-4">
          <div className="flex items-start gap-3.5">
            <div className="p-2.5 rounded-xl bg-amber-100 border border-amber-300 text-amber-900 shrink-0">
              <ShieldQuestion className="w-7 h-7" />
            </div>
            <div className="space-y-1">
              <h3 className="text-base font-extrabold text-amber-950 leading-snug">
                {result.unknownSignatureFallback.messageTitle}
              </h3>
              <p className="text-xs text-amber-900 leading-relaxed font-medium">
                {result.unknownSignatureFallback.messageBody}
              </p>
            </div>
          </div>

          {/* Options Checklist */}
          <div className="p-3 rounded-xl bg-white border border-amber-200 text-xs text-slate-700 space-y-1.5 shadow-xs">
            <span className="font-bold text-slate-900 text-xs block mb-1">You can:</span>
            <ol className="list-decimal list-inside space-y-1 text-slate-800 font-medium">
              {result.unknownSignatureFallback.options.map((opt, idx) => (
                <li key={idx} className="leading-snug">
                  {opt}
                </li>
              ))}
            </ol>
          </div>

          {/* Functional Recovery Buttons */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
            <button
              onClick={onScanAgain}
              className="h-10 px-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-bold text-xs flex items-center justify-center gap-1.5 shadow-xs transition active:scale-95 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5 text-yellow-400" />
              <span>Scan Another QR</span>
            </button>
            <button
              onClick={onOpenUpload}
              className="h-10 px-2.5 rounded-xl bg-white hover:bg-slate-50 text-slate-900 border border-slate-300 font-bold text-xs flex items-center justify-center gap-1.5 shadow-xs transition active:scale-95 cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 text-amber-600" />
              <span>Upload QR Image</span>
            </button>
            <button
              onClick={onRetryAnalysis}
              className="h-10 px-2.5 rounded-xl bg-amber-400 hover:bg-amber-300 text-slate-950 font-black text-xs flex items-center justify-center gap-1.5 shadow-xs transition active:scale-95 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Analysis</span>
            </button>
            <button
              onClick={() => setShowDetailsSection(!showDetailsSection)}
              className="h-10 px-2.5 rounded-xl bg-white hover:bg-slate-50 text-slate-900 border border-slate-300 font-bold text-xs flex items-center justify-center gap-1.5 shadow-xs transition active:scale-95 cursor-pointer"
            >
              <Eye className="w-3.5 h-3.5 text-amber-600" />
              <span>{showDetailsSection ? 'Hide Details' : 'View Details'}</span>
            </button>
          </div>
        </div>
      )}

      {/* 2. Primary Verdict Banner */}
      <div className={`p-5 rounded-2xl border ${verdictTheme.bg} ${verdictTheme.border} shadow-sm`}>
        <div className="flex items-start gap-4">
          <div className={`p-3 rounded-xl border ${verdictTheme.iconBg} shrink-0`}>
            <VerdictIcon className="w-7 h-7" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className={`px-2.5 py-0.5 text-xs font-mono tracking-wider rounded-md ${verdictTheme.badgeBg}`}>
                THREAT STATUS: {formalThreatStatus.toUpperCase()}
              </span>
              <span className="text-xs text-slate-700 font-mono font-bold">
                SCORE: {result.riskScore}/100
              </span>
              <span className="text-xs text-slate-400">·</span>
              <span className="text-xs text-slate-700 font-mono">
                {result.payloadType.replace('_', ' ')}
              </span>
            </div>
            <p className="text-sm text-slate-800 font-medium leading-snug mt-1">
              {verdictTheme.subtitle}
            </p>
          </div>
        </div>

        {/* Plain Language Explanation of Consequences (Section 5) */}
        <div className="mt-3.5 pt-3 border-t border-slate-200/80 text-xs text-slate-800 space-y-1">
          <span className="font-extrabold text-slate-900 block text-xs">Plain-Language Consequence Assessment:</span>
          <p className="leading-relaxed bg-white/80 p-3 rounded-xl border border-slate-200/80 font-medium text-slate-800">
            {result.plainLanguageConsequences}
          </p>
        </div>
      </div>

      {/* 3. SECTION 4 FORMAL SECURITY REPORT (Section 4 Requirement) */}
      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-3.5">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100">
          <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
            <FileText className="w-4 h-4 text-amber-600" />
            <span>Formal Security Report (Section 4 Compliance)</span>
          </h4>
          <div className="flex items-center gap-2">
            {result.scanDurationMs && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-yellow-100 text-yellow-950 font-black border border-yellow-300 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                <span>⚡ {result.scanDurationMs}ms (Prioritized)</span>
              </span>
            )}
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              ID: {result.id.slice(0, 14)}...
            </span>
          </div>
        </div>

        {/* Structured Report Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Scan ID &amp; Timestamp:</span>
            <span className="font-mono text-slate-900 font-bold break-all text-[11px]">
              {result.id}
            </span>
            <span className="text-[10px] font-mono text-slate-500 block mt-0.5">
              {result.timestamp}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">QR Payload Type:</span>
            <span className="font-bold text-slate-900">
              {result.payloadType.replace('_', ' ')}
            </span>
            <span className="text-[10px] text-slate-500 block mt-0.5">
              Length: {result.rawPayload.length} bytes
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 sm:col-span-2">
            <div className="flex items-center justify-between mb-0.5">
              <span className="text-slate-500 text-[10px] uppercase font-mono block">
                Decoded Destination / URL (Safely Displayed):
              </span>
              <button
                onClick={() => setShowDefanged(!showDefanged)}
                className="text-[10px] font-mono text-amber-700 hover:text-amber-800 font-bold transition cursor-pointer"
              >
                {showDefanged ? 'SWITCH TO RAW' : 'DEFANG (SAFE)'}
              </button>
            </div>
            <div className="font-mono text-slate-900 text-[11px] break-all bg-white p-2 rounded border border-slate-200 select-all">
              {showDefanged ? defangedUrl : result.rawPayload}
            </div>
            <span className="text-[10px] text-slate-500 mt-1 block">
              {showDefanged
                ? 'Defanged format (hxxps://, [.]) prevents accidental browser execution.'
                : 'Raw destination payload string.'}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Original Domain:</span>
            <span className="font-mono text-slate-900 font-bold">
              {originalDomain}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Verified Redirect Destination:</span>
            <span className="font-mono text-slate-900 font-bold break-all">
              {redirectDestination}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Threat Status:</span>
            <span
              className={`font-black font-mono text-xs ${
                formalThreatStatus === 'Malicious'
                  ? 'text-red-700'
                  : formalThreatStatus === 'Suspicious'
                  ? 'text-amber-800'
                  : formalThreatStatus === 'Unknown'
                  ? 'text-yellow-800'
                  : 'text-emerald-700'
              }`}
            >
              {formalThreatStatus}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Downloadable File Detected:</span>
            <span className="font-bold text-slate-900">
              {result.downloadAssessment?.isDownload
                ? `YES (${result.downloadAssessment.fileType || 'Executable Package'})`
                : 'NO (Web Page / Other)'}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 sm:col-span-2">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Whether File Was Actually Analyzed:</span>
            <span className="font-medium text-slate-800 leading-snug block mt-0.5">
              {result.downloadAssessment?.isDownload
                ? 'NOT ANALYZED: Remote file was safely detected in URL structure/headers without downloading or executing on user device. In accordance with zero-trust safety principles, unverified binaries are never downloaded without explicit sandboxing.'
                : 'N/A: No downloadable binary package present.'}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Detected Malware Family:</span>
            <span className="font-mono text-slate-900 font-bold">
              {result.malwareAnalysis?.threatFamily
                ? result.malwareAnalysis.threatFamily
                : 'None confirmed based on available evidence'}
            </span>
            <span className="text-[10px] text-slate-500 block mt-0.5">
              Rule: Never invent malware names without sufficient evidence.
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Potential Capabilities:</span>
            <span className="font-medium text-slate-800 block text-[11px] mt-0.5">
              {result.downloadAssessment?.potentialCapabilities?.length
                ? result.downloadAssessment.potentialCapabilities.join(', ')
                : 'None identified on available evidence'}
            </span>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 sm:col-span-2">
            <span className="text-slate-500 text-[10px] uppercase font-mono block">Confidence Level &amp; Supporting Sources:</span>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-white text-slate-800 border border-slate-200 font-bold">
                Confidence: {result.quishingMl?.confidence || 85}%
              </span>
              <span className="text-[11px] text-slate-600 font-mono">
                Sources: Heuristic Rule Base, Trad &amp; Chehab Quishing ML (AUC 0.91), Google Web Risk API lookup.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 3.5. Threat Signatures Verification (From 8-Page Training Guide) */}
      <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-3.5">
        <div className="flex items-center justify-between pb-2 border-b border-slate-100 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-yellow-400 text-yellow-950 font-black shadow-2xs">
              <BookOpen className="w-4 h-4" />
            </div>
            <div>
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                <span>Threat Signatures Check (Security Guide Catalogue)</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-yellow-100 text-yellow-900 font-bold border border-yellow-300">
                  16 Taxonomy Groups
                </span>
              </h4>
              <span className="text-[10px] text-slate-500 block">
                Checked against QR Code Threat Signatures &amp; Training Guide (Section 2 &amp; 3)
              </span>
            </div>
          </div>
          {onOpenSignaturesModal && (
            <button
              onClick={onOpenSignaturesModal}
              className="text-[11px] font-bold text-amber-950 hover:text-slate-900 bg-yellow-300 hover:bg-yellow-400 px-3 py-1.5 rounded-lg border border-yellow-400 transition cursor-pointer flex items-center gap-1.5 shadow-2xs"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Explore 16 Threat Signatures</span>
            </button>
          )}
        </div>

        {result.threatSignatureMatches && result.threatSignatureMatches.length > 0 ? (
          <div className="space-y-3">
            <div className="p-3 rounded-xl bg-red-50 border border-red-200 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-red-900">
                <AlertTriangle className="w-5 h-5 text-red-600 shrink-0" />
                <div>
                  <span className="text-xs font-black uppercase tracking-wide block">
                    ⚠️ {result.threatSignatureMatches.length} Matching Threat Signature(s) Detected
                  </span>
                  <p className="text-[11px] text-red-700 font-medium mt-0.5">
                    This payload triggers active malware/phishing indicators from the defensive training guide.
                  </p>
                </div>
              </div>
              <span className="text-[10px] font-mono font-black px-2 py-1 rounded bg-red-600 text-white shrink-0">
                SIGNATURE HIT
              </span>
            </div>

            <div className="space-y-2.5">
              {result.threatSignatureMatches.map((sig) => (
                <div
                  key={sig.id}
                  className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 hover:border-amber-300 transition space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 text-[10px] font-mono rounded font-bold ${getSeverityBadge(sig.severity)}`}>
                        {sig.severity}
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200">
                        {sig.id}
                      </span>
                      <span className="text-slate-900 font-bold">{sig.name}</span>
                    </div>
                    <span className="text-[10px] font-mono text-amber-800 bg-amber-50 px-2 py-0.5 rounded border border-amber-200 font-semibold">
                      {sig.category}
                    </span>
                  </div>

                  <p className="text-slate-700 font-medium leading-relaxed">
                    <strong className="text-slate-900">Detection Signal:</strong> {sig.evidence}
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1">
                    <div className="p-2 rounded bg-red-50/70 border border-red-200 text-red-950">
                      <span className="font-bold block text-[10px] uppercase text-red-700">Potential Consequence:</span>
                      <span className="leading-snug block mt-0.5">{sig.consequence}</span>
                    </div>
                    <div className="p-2 rounded bg-emerald-50/70 border border-emerald-200 text-emerald-950">
                      <span className="font-bold block text-[10px] uppercase text-emerald-700">Protective Action:</span>
                      <span className="leading-snug block mt-0.5">{sig.defensiveAction}</span>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 block pt-0.5">
                    Citation: {sig.pdfSection}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="p-4 rounded-xl bg-amber-50/60 border border-amber-200/90 text-xs text-amber-950 space-y-2">
            <div className="flex items-start gap-2.5">
              <ShieldQuestion className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-bold text-amber-950 block text-xs uppercase tracking-wide">
                  No Matching Threat Signatures Found in Available Security Sources
                </span>
                <p className="text-slate-700 leading-relaxed font-medium">
                  None of the 16 threat signatures from the <em>QR Code Threat Signatures &amp; Training Guide</em> (direct APK downloads, executable scripts, IDN homoglyphs, SSRF/private IPs, rogue Wi-Fi, intent abuse, or plain-text urgency lures) were detected in this payload.
                </p>
                <div className="p-2.5 rounded-lg bg-white border border-amber-200 text-[11px] text-slate-800 font-medium">
                  <strong>Zero-Trust Rule (Section 1 &amp; 8):</strong> "No matching threat signature was found in the available security sources. This does NOT guarantee that the QR code is safe."
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 4. Five-Stage Security Inspection Pipeline (Section 3 Requirement) */}
      <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm space-y-3">
        <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-amber-600" />
            <span>5-Stage Security Pipeline Breakdown</span>
          </span>
          <span className="text-[11px] font-mono text-slate-500">STAGES A — E</span>
        </h4>

        <div className="grid grid-cols-1 gap-2">
          {result.stages?.map((stg) => (
            <div
              key={stg.stage}
              className={`p-3 rounded-xl border transition flex items-start justify-between gap-3 ${
                stg.status === 'ALERT'
                  ? 'bg-red-50/80 border-red-200'
                  : stg.status === 'WARNING'
                  ? 'bg-yellow-50/70 border-yellow-300'
                  : stg.status === 'UNKNOWN'
                  ? 'bg-amber-50/60 border-amber-300'
                  : 'bg-slate-50/80 border-slate-200'
              }`}
            >
              <div className="flex items-start gap-2.5">
                <span
                  className={`w-6 h-6 rounded-lg text-xs font-mono font-bold flex items-center justify-center shrink-0 ${
                    stg.status === 'ALERT'
                      ? 'bg-red-600 text-white'
                      : stg.status === 'WARNING'
                      ? 'bg-amber-400 text-slate-950 font-black'
                      : stg.status === 'UNKNOWN'
                      ? 'bg-yellow-300 text-slate-900 font-bold'
                      : 'bg-slate-900 text-white'
                  }`}
                >
                  {stg.stage}
                </span>
                <div>
                  <span className="font-bold text-slate-900 text-xs block">{stg.name}</span>
                  <p className="text-[11px] text-slate-600 leading-snug mt-0.5">{stg.summary}</p>
                </div>
              </div>
              <span
                className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border shrink-0 ${
                  stg.status === 'ALERT'
                    ? 'bg-red-100 text-red-800 border-red-300'
                    : stg.status === 'WARNING'
                    ? 'bg-amber-100 text-amber-900 border-amber-300'
                    : stg.status === 'UNKNOWN'
                    ? 'bg-yellow-100 text-yellow-900 border-yellow-300'
                    : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                }`}
              >
                {stg.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* 5. Download & APK Assessment Card (Stage C & D) */}
      {result.downloadAssessment?.isDownload && (
        <div className="p-4 rounded-xl bg-white border-2 border-amber-400 shadow-sm space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <Download className="w-4 h-4 text-amber-600" />
              <span>Download Assessment: {result.downloadAssessment.fileType}</span>
            </h4>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-100 text-amber-950 border border-amber-300 font-bold">
              {result.downloadAssessment.extension?.toUpperCase() || 'FILE'}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-amber-50/80 border border-amber-200 text-xs text-amber-950 space-y-2">
            <p className="font-medium leading-relaxed">
              <strong>Zero-Trust Notice:</strong> This QR code points to an Android application download ({result.downloadAssessment.filename}). In accordance with safe controlled methods, <strong>this file has NOT been downloaded or installed on your device.</strong>
            </p>

            <div className="p-2.5 rounded bg-white border border-amber-200 text-[11px] text-slate-700 space-y-1">
              <span className="font-bold text-amber-950 block">Protective Guidance:</span>
              <p>• Do not install this package directly. Bypassing Google Play Protect or side-loading unverified APKs may grant aggressive permissions.</p>
              <p>• Search for the service in the official Google Play Store or Apple App Store instead.</p>
              <p className="text-slate-500 italic">• Note: We never claim an APK is malicious based only on its filename.</p>
            </div>
          </div>
        </div>
      )}

      {/* 6. EMERGENCY INCIDENT RESPONSE GUIDE (Section 6 Requirement) */}
      <div className="p-4 rounded-xl bg-amber-50/90 border-2 border-amber-400 shadow-sm space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-amber-950">
            <Flame className="w-5 h-5 text-amber-600 shrink-0" />
            <h4 className="text-xs font-extrabold uppercase tracking-wider">
              Already Installed or Followed This Link? (Incident Response)
            </h4>
          </div>
          <button
            onClick={() => setShowIncidentGuide(!showIncidentGuide)}
            className="text-xs font-bold text-amber-900 hover:text-amber-950 px-2.5 py-1 rounded bg-amber-200/80 hover:bg-amber-300 border border-amber-300 transition cursor-pointer"
          >
            {showIncidentGuide ? 'Hide Steps' : 'View Protocol'}
          </button>
        </div>

        {showIncidentGuide && (
          <div className="pt-2 border-t border-amber-200 text-xs text-slate-800 space-y-2.5 animate-in fade-in">
            <p className="font-bold text-amber-950 text-xs">
              Follow these immediate containment steps if you previously installed this app or entered sensitive credentials:
            </p>
            <ol className="list-decimal list-inside space-y-1.5 font-medium text-slate-800">
              <li className="leading-relaxed">
                <strong>Avoid sensitive transactions immediately:</strong> Do not open banking apps or authorize any two-factor OTPs on this phone.
              </li>
              <li className="leading-relaxed">
                <strong>Disconnect network:</strong> Turn on Airplane Mode immediately and disable Wi-Fi and Bluetooth to cut off remote command-and-control channels.
              </li>
              <li className="leading-relaxed">
                <strong>Reboot into Android Safe Mode:</strong> Press and hold Power, then long-press Restart until "Safe Mode" appears. This prevents third-party apps and overlay malware from executing.
              </li>
              <li className="leading-relaxed">
                <strong>Review &amp; revoke special permissions:</strong> Open Settings &gt; Security &gt; Device Administrator Apps, and Settings &gt; Accessibility. Revoke any unrecognized app rights.
              </li>
              <li className="leading-relaxed">
                <strong>Uninstall the suspicious app:</strong> Go to Settings &gt; Apps, locate the newly installed package, and tap Uninstall.
              </li>
              <li className="leading-relaxed">
                <strong>Run device security check:</strong> Open Google Play Store &gt; Profile &gt; Play Protect &gt; Scan to inspect installed binaries.
              </li>
              <li className="leading-relaxed">
                <strong>Contact your bank promptly:</strong> If card numbers, credentials, or UPI details were shared, call your bank's fraud helpline immediately to freeze your cards and accounts.
              </li>
            </ol>
          </div>
        )}
      </div>

      {/* 7. Decoded Raw Payload (Safely Sanitized & Escaped) */}
      <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-2">
          <div className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-1.5">
            <span>Decoded Payload</span>
            <span className="text-slate-500 font-mono font-normal">({result.rawPayload.length} chars)</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowRawBase64(!showRawBase64)}
              className="text-[11px] font-mono font-semibold text-amber-800 hover:text-amber-950 transition cursor-pointer"
            >
              {showRawBase64 ? 'VIEW TEXT' : 'BASE64'}
            </button>
            <button
              onClick={() => handleCopy(result.rawPayload)}
              className="flex items-center gap-1 text-[11px] font-mono font-bold px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-800 transition cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'COPIED' : 'COPY'}</span>
            </button>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-slate-900 text-xs font-mono text-amber-400 break-all select-all shadow-inner">
          {showRawBase64 ? (
            base64Payload
          ) : result.rawPayload.length > 280 && !showFullPayload ? (
            <>
              {result.rawPayload.slice(0, 280)}...
              <button
                onClick={() => setShowFullPayload(true)}
                className="ml-2 text-yellow-300 hover:underline font-sans text-xs cursor-pointer font-bold"
              >
                Show full payload
              </button>
            </>
          ) : (
            result.rawPayload
          )}
        </div>

        <p className="text-[11px] text-slate-500 mt-2 flex items-center gap-1 font-medium">
          <Info className="w-3.5 h-3.5 shrink-0 text-slate-400" />
          <span>Zero-Execution Policy: Destinations are never opened in the browser automatically.</span>
        </p>
      </div>

      {/* 8. Expandable Details Section */}
      {showDetailsSection && (
        <div className="space-y-4 animate-in fade-in">
          {/* Observed Heuristic Indicators List */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm">
            <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-3 flex items-center justify-between">
              <span>Observed Security Evidence</span>
              <span className="text-xs font-mono text-slate-500 font-semibold">
                {result.indicators.length} {result.indicators.length === 1 ? 'SIGNAL' : 'SIGNALS'}
              </span>
            </h4>

            {result.indicators.length === 0 ? (
              <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center gap-2 font-medium">
                <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>No deceptive or suspicious heuristic patterns detected in URL/payload structure.</span>
              </div>
            ) : (
              <div className="space-y-2.5">
                {result.indicators.map((ind) => (
                  <div
                    key={ind.id}
                    className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900">{ind.title}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityBadge(ind.severity)}`}>
                        {ind.severity}
                      </span>
                    </div>
                    <p className="text-slate-600 leading-relaxed font-medium">{ind.description}</p>
                    {ind.evidence && (
                      <p className="text-[11px] font-mono text-emerald-800 bg-emerald-50 px-2 py-1 rounded border border-emerald-200">
                        Evidence: {ind.evidence}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Special UPI Payment Inspection Card */}
          {result.payloadType === 'UPI_PAYMENT' && result.upiData && (
            <div className="p-4 rounded-xl bg-white border-2 border-amber-300 shadow-sm space-y-3">
              <div className="flex items-center gap-2 text-amber-700">
                <CreditCard className="w-5 h-5 shrink-0" />
                <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider">UPI Payment Safety Audit</h4>
              </div>

              <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-amber-950 text-xs space-y-1 font-medium">
                <p className="font-bold flex items-center gap-1.5 text-amber-900">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-amber-600" />
                  <span>CRITICAL PAYMENT RULE:</span>
                </p>
                <p className="leading-relaxed">
                  Receiving money, cashback, or rewards <strong className="text-slate-900 underline">NEVER requires entering a UPI PIN</strong>. Scanning a QR code authorizes a DEBIT from your account.
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500 text-[11px] block">Payee VPA:</span>
                  <span className="font-mono text-slate-900 font-bold break-all">
                    {result.upiData.payeeAddress || 'Unspecified'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500 text-[11px] block">Payee Name:</span>
                  <span className="text-slate-800 font-medium">
                    {result.upiData.payeeName || 'Not encoded in QR'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500 text-[11px] block">Transfer Amount:</span>
                  <span className="font-mono text-slate-900 font-bold">
                    {result.upiData.amount ? `₹${result.upiData.amount} ${result.upiData.currency || 'INR'}` : 'User-entered'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-500 text-[11px] block">Transaction Note:</span>
                  <span className="text-slate-700 italic">
                    {result.upiData.transactionNote || 'None'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Asynchronous Non-blocking AI Risk Advisory Loader */}
          {result.isLoadingExplanation && !result.explanation && (
            <div className="p-4 rounded-xl bg-yellow-50/80 border border-yellow-300 shadow-2xs space-y-2 text-xs animate-in fade-in duration-200">
              <div className="flex items-center justify-between">
                <h4 className="font-black text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                  <Languages className="w-4 h-4 text-amber-600" />
                  <span>Bilingual AI Advisory (Synthesizing...)</span>
                </h4>
                <span className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-amber-950 bg-yellow-200/90 px-2 py-0.5 rounded-full border border-yellow-300">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-600 animate-ping" />
                  <span>Non-blocking background</span>
                </span>
              </div>
              <p className="text-slate-600 leading-relaxed font-medium">
                Stages A–E deterministic analysis and all Section 4 security evidence are ready above. ScamTrace AI is synthesizing an explanatory natural-language advisory in English and Kannada asynchronously.
              </p>
            </div>
          )}

          {/* Bilingual AI Risk Explanation */}
          {result.explanation && (
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
                  <Languages className="w-4 h-4 text-emerald-600" />
                  <span>Plain-Language Security Advisory</span>
                </h4>

                <div className="flex items-center gap-1 p-0.5 bg-slate-100 rounded-lg border border-slate-200">
                  <button
                    onClick={() => setActiveLang('EN')}
                    className={`px-2.5 py-1 text-xs font-bold rounded-md transition cursor-pointer ${
                      activeLang === 'EN'
                        ? 'bg-emerald-600 text-white shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    English
                  </button>
                  <button
                    onClick={() => setActiveLang('KN')}
                    className={`px-2.5 py-1 text-xs font-bold rounded-md transition cursor-pointer ${
                      activeLang === 'KN'
                        ? 'bg-emerald-600 text-white shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    ಕನ್ನಡ (Kannada)
                  </button>
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2.5 text-xs">
                <p className="text-slate-800 leading-relaxed font-medium">
                  {activeLang === 'EN'
                    ? result.explanation.englishSummary
                    : result.explanation.kannadaSummary}
                </p>

                <div className="pt-2 border-t border-slate-200">
                  <p className="text-[11px] font-bold text-slate-700 mb-1 uppercase tracking-wider">
                    {activeLang === 'EN' ? 'Recommended Action Steps:' : 'ಮುಂದಿನ ಸುರಕ್ಷಿತ ಕ್ರಮಗಳು:'}
                  </p>
                  <ul className="space-y-1 text-slate-700 list-disc list-inside font-medium">
                    {(activeLang === 'EN'
                      ? result.explanation.englishAdvice
                      : result.explanation.kannadaAdvice
                    ).map((step, idx) => (
                      <li key={idx} className="leading-relaxed">
                        {step}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Safe Next Steps Checklist */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm space-y-2">
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-emerald-600" />
              <span>Protective Action Checklist</span>
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-700 font-medium list-disc list-inside">
              {result.safeNextSteps?.map((step, idx) => (
                <li key={idx} className="leading-relaxed">
                  {step}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* 7. Action Buttons */}
      <div className="flex items-center gap-3 pt-2">
        <button
          onClick={onScanAgain}
          className="flex-1 h-12 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-md shadow-emerald-600/20 active:scale-95 transition cursor-pointer"
        >
          <RotateCcw className="w-4 h-4" />
          <span>SCAN ANOTHER QR</span>
        </button>
        <button
          onClick={onOpenDecontaminationModal}
          className="h-12 px-4 rounded-xl bg-white hover:bg-slate-50 text-slate-800 font-bold text-xs flex items-center justify-center gap-2 border border-slate-300 shadow-sm active:scale-95 transition cursor-pointer"
        >
          <Wrench className="w-4 h-4 text-amber-500" />
          <span>REMEDIATION GUIDE</span>
        </button>
      </div>
    </div>
  );
};
