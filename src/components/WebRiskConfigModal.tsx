import React from 'react';
import { Server, Key, ShieldCheck, X, AlertCircle, CheckCircle2 } from 'lucide-react';

interface WebRiskConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  serverStatus: {
    webRiskApiConfigured: boolean;
    geminiAiConfigured: boolean;
  } | null;
}

export const WebRiskConfigModal: React.FC<WebRiskConfigModalProps> = ({
  isOpen,
  onClose,
  serverStatus,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-white border border-slate-200 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-100 border border-emerald-300 flex items-center justify-center text-emerald-800">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Threat Intelligence Configuration
              </h3>
              <p className="text-xs text-slate-500">
                Google Web Risk &amp; Reputation Server Engine
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

        {/* Body */}
        <div className="p-5 space-y-4 text-xs text-slate-700">
          {/* Current Status Box */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2.5 shadow-2xs">
            <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider block font-bold">
              Active Integration Diagnostics:
            </span>

            <div className="flex items-center justify-between py-1 border-b border-slate-200">
              <span className="font-bold text-slate-800">Google Web Risk API:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  serverStatus?.webRiskApiConfigured
                    ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                    : 'bg-amber-100 text-amber-900 border-amber-300'
                }`}
              >
                {serverStatus?.webRiskApiConfigured ? 'ACTIVE' : 'NOT CONFIGURED'}
              </span>
            </div>

            <div className="flex items-center justify-between py-1">
              <span className="font-bold text-slate-800">Gemini 3.8 Flash Bilingual Advisor:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                  serverStatus?.geminiAiConfigured
                    ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                    : 'bg-slate-100 text-slate-700 border-slate-300'
                }`}
              >
                {serverStatus?.geminiAiConfigured ? 'ACTIVE' : 'DETERMINISTIC FALLBACK'}
              </span>
            </div>
          </div>

          {/* Setup Guide */}
          <div className="space-y-2">
            <h4 className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-emerald-600" />
              <span>How to Configure Web Risk API in Google Cloud</span>
            </h4>
            <ol className="list-decimal list-inside space-y-1.5 text-slate-600 leading-relaxed bg-slate-50 p-3.5 rounded-xl border border-slate-200 font-medium">
              <li>Open Google Cloud Console (console.cloud.google.com).</li>
              <li>Enable the <strong className="text-slate-900">Web Risk API</strong> for your project.</li>
              <li>Create or select an API key under APIs &amp; Services &gt; Credentials.</li>
              <li>Restrict the API key to "Web Risk API" for security.</li>
              <li>Add the key to your server environment secrets as <code className="text-emerald-700 font-mono font-bold">GOOGLE_WEB_RISK_API_KEY</code>.</li>
            </ol>
            <p className="text-[11px] text-slate-500 italic">
              When not configured, ScamTrace AI automatically triggers the required unknown-signature safety protocol without fabricating results.
            </p>
          </div>

          {/* Privacy Architecture Notice */}
          <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-950 space-y-1">
            <p className="font-bold flex items-center gap-1 text-emerald-900">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              <span>Air-Gapped Privacy Architecture:</span>
            </p>
            <p className="text-emerald-900 text-[11px] leading-relaxed font-medium">
              Camera video frames and uploaded QR photos are decoded entirely on your device inside browser memory. Video is never uploaded to any server. When a URL threat check is performed, only the sanitized URL string is submitted to the server reputation proxy.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
