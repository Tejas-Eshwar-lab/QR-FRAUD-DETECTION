import React, { useState } from 'react';
import {
  defangPayload,
  getDecontaminationChecklist,
  generateAbuseReport,
  RemediationStep,
} from '../lib/decontaminationGuide';
import {
  ShieldAlert,
  CheckCircle2,
  Copy,
  Check,
  ExternalLink,
  Smartphone,
  Shield,
  FileText,
  X,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';

interface DecontaminationModalProps {
  isOpen: boolean;
  onClose: () => void;
  rawPayload: string;
  payloadType: string;
  malwareType: string;
  targetPlatform: 'Android' | 'iOS' | 'Windows/Mac' | 'Cross-Platform' | 'All Devices';
  observedIndicators: string[];
}

export const DecontaminationModal: React.FC<DecontaminationModalProps> = ({
  isOpen,
  onClose,
  rawPayload,
  payloadType,
  malwareType,
  targetPlatform,
  observedIndicators,
}) => {
  const [selectedPlatform, setSelectedPlatform] = useState<'Android' | 'iOS' | 'All'>(
    targetPlatform === 'iOS' ? 'iOS' : 'Android'
  );
  const [completedSteps, setCompletedSteps] = useState<Record<string, boolean>>({});
  const [copiedDefanged, setCopiedDefanged] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  if (!isOpen) return null;

  const defanged = defangPayload(rawPayload);
  const checklist = getDecontaminationChecklist(payloadType, malwareType, selectedPlatform);
  const abuseReport = generateAbuseReport(rawPayload, malwareType, observedIndicators);

  const toggleStep = (id: string) => {
    setCompletedSteps((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopyDefanged = () => {
    navigator.clipboard.writeText(defanged);
    setCopiedDefanged(true);
    setTimeout(() => setCopiedDefanged(false), 2000);
  };

  const handleCopyReport = () => {
    navigator.clipboard.writeText(abuseReport);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const completedCount = checklist.filter((s) => completedSteps[s.id]).length;
  const progressPercent = Math.round((completedCount / checklist.length) * 100);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-3xl max-h-[92vh] bg-white border border-slate-200 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-amber-100 border border-amber-300 flex items-center justify-center text-amber-800">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Threat Neutralization &amp; Decontamination Protocol
              </h3>
              <p className="text-xs text-slate-500">
                Actionable checklist to neutralize the link and cleanse exposed devices
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 flex items-center justify-center transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 overflow-y-auto space-y-5 flex-1 text-xs text-slate-700">
          {/* Key Principle Alert */}
          <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-300 text-xs text-amber-950 space-y-1.5 leading-relaxed shadow-xs">
            <p className="font-bold text-amber-900 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
              <span>How "Malware Removal" Works for QR Codes:</span>
            </p>
            <p className="text-amber-900 leading-relaxed text-[11px] font-medium">
              A QR code is an optical pointer. You cannot alter or remove code from printed paper or images. However, you can neutralize the threat by <strong>(1) defanging the link</strong> so it cannot be clicked, <strong>(2) purging any rogue files or APKs from your device</strong>, and <strong>(3) reporting the malicious host</strong> for global browser takedown.
            </p>
          </div>

          {/* Section 1: Defanged Inert Payload */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
                <Shield className="w-4 h-4 text-emerald-600" />
                <span>Defanged Safe Payload (Neutralized)</span>
              </span>
              <button
                onClick={handleCopyDefanged}
                className="flex items-center gap-1 text-[11px] font-mono font-bold px-2.5 py-1 rounded-lg bg-white hover:bg-slate-100 text-slate-800 border border-slate-300 transition cursor-pointer shadow-2xs"
              >
                {copiedDefanged ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedDefanged ? 'COPIED' : 'COPY DEFANGED'}</span>
              </button>
            </div>
            <p className="text-[11px] text-slate-500">
              Safe for documentation, email reports, or ticket sharing without accidental click triggers:
            </p>
            <div className="p-3 rounded-lg bg-white border border-slate-300 font-mono text-emerald-800 text-xs break-all select-all shadow-inner font-bold">
              {defanged}
            </div>
          </div>

          {/* Section 2: Interactive Device Remediation Checklist */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div>
                <h4 className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
                  <Smartphone className="w-4 h-4 text-emerald-600" />
                  <span>Device Decontamination Checklist</span>
                </h4>
                <p className="text-[11px] text-slate-500 font-medium">
                  {completedCount} of {checklist.length} steps completed ({progressPercent}%)
                </p>
              </div>

              {/* Platform Filter */}
              <div className="flex items-center gap-1 p-0.5 bg-slate-100 rounded-lg border border-slate-200 text-[11px] font-mono">
                <button
                  onClick={() => setSelectedPlatform('Android')}
                  className={`px-3 py-1 rounded-md transition cursor-pointer font-bold ${
                    selectedPlatform === 'Android' ? 'bg-emerald-600 text-white shadow-xs' : 'text-slate-600'
                  }`}
                >
                  Android
                </button>
                <button
                  onClick={() => setSelectedPlatform('iOS')}
                  className={`px-3 py-1 rounded-md transition cursor-pointer font-bold ${
                    selectedPlatform === 'iOS' ? 'bg-emerald-600 text-white shadow-xs' : 'text-slate-600'
                  }`}
                >
                  iPhone / iOS
                </button>
              </div>
            </div>

            {/* Checklist Items */}
            <div className="space-y-2 pt-1">
              {checklist.map((step) => {
                const isDone = completedSteps[step.id];
                return (
                  <div
                    key={step.id}
                    onClick={() => toggleStep(step.id)}
                    className={`p-3 rounded-xl border transition cursor-pointer flex items-start gap-3 ${
                      isDone
                        ? 'bg-emerald-50/60 border-emerald-300 text-slate-700'
                        : 'bg-slate-50 border-slate-200 hover:border-emerald-300 text-slate-800'
                    }`}
                  >
                    <div className="mt-0.5">
                      <div
                        className={`w-4 h-4 rounded flex items-center justify-center border transition ${
                          isDone
                            ? 'bg-emerald-600 border-emerald-600 text-white'
                            : 'border-slate-400 bg-white'
                        }`}
                      >
                        {isDone && <Check className="w-3 h-3 stroke-[3]" />}
                      </div>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`font-bold text-xs ${isDone ? 'line-through text-slate-400' : 'text-slate-900'}`}>
                          {step.title}
                        </span>
                        {step.critical && (
                          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-red-100 text-red-800 border border-red-200 font-bold">
                            CRITICAL
                          </span>
                        )}
                      </div>
                      <p className={`text-[11px] leading-relaxed ${isDone ? 'text-slate-400' : 'text-slate-600'}`}>
                        {step.instructions}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Section 3: Ecosystem Takedown Report */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
                <FileText className="w-4 h-4 text-purple-700" />
                <span>Global Threat Takedown Report</span>
              </h4>
              <button
                onClick={handleCopyReport}
                className="flex items-center gap-1 text-[11px] font-mono font-bold px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 text-slate-800 border border-slate-300 transition cursor-pointer shadow-2xs"
              >
                {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedReport ? 'COPIED' : 'COPY REPORT'}</span>
              </button>
            </div>
            <p className="text-[11px] text-slate-600">
              Paste this report into security abuse portals to have the URL blocked globally in Chrome, Safari, and Edge:
            </p>
            <pre className="p-3 rounded-lg bg-white border border-slate-300 font-mono text-[11px] text-slate-800 whitespace-pre-wrap max-h-40 overflow-y-auto shadow-inner">
              {abuseReport}
            </pre>

            <div className="flex items-center gap-2 pt-1 flex-wrap">
              <span className="text-[11px] text-slate-500 font-medium">Official Reporting Portals:</span>
              <a
                href="https://safebrowsing.google.com/safebrowsing/report_phish/"
                target="_blank"
                rel="noreferrer"
                className="text-[11px] font-mono font-bold text-emerald-700 hover:underline flex items-center gap-1"
              >
                <span>Google Safe Browsing</span>
                <ExternalLink className="w-3 h-3" />
              </a>
              <span className="text-slate-400">·</span>
              <a
                href="https://urlhaus.abuse.ch/browse/"
                target="_blank"
                rel="noreferrer"
                className="text-[11px] font-mono font-bold text-emerald-700 hover:underline flex items-center gap-1"
              >
                <span>URLhaus Threat Feed</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
