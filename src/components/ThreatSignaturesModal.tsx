import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Search,
  X,
  FileText,
  AlertTriangle,
  Play,
  CheckCircle2,
  ExternalLink,
  BookOpen,
  Filter,
} from 'lucide-react';
import { THREAT_SIGNATURE_CATALOGUE, ThreatSignatureDefinition } from '../lib/threatSignatures';
import { IndicatorSeverity } from '../types/security';

interface ThreatSignaturesModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectSample: (payload: string) => void;
}

export const ThreatSignaturesModal: React.FC<ThreatSignaturesModalProps> = ({
  isOpen,
  onClose,
  onSelectSample,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  const categories = useMemo(() => {
    const set = new Set<string>();
    THREAT_SIGNATURE_CATALOGUE.forEach((s) => set.add(s.category));
    return ['ALL', ...Array.from(set)];
  }, []);

  const filteredSignatures = useMemo(() => {
    return THREAT_SIGNATURE_CATALOGUE.filter((sig) => {
      const matchesSearch =
        sig.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        sig.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        sig.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        sig.detectionRule.toLowerCase().includes(searchTerm.toLowerCase()) ||
        sig.pdfSection.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesCategory =
        selectedCategory === 'ALL' || sig.category === selectedCategory;

      const matchesSeverity =
        selectedSeverity === 'ALL' || sig.severity === selectedSeverity;

      return matchesSearch && matchesCategory && matchesSeverity;
    });
  }, [searchTerm, selectedCategory, selectedSeverity]);

  if (!isOpen) return null;

  const getSeverityBadge = (sev: IndicatorSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-600 text-white font-black';
      case 'HIGH':
        return 'bg-amber-600 text-white font-bold';
      case 'MEDIUM':
        return 'bg-yellow-400 text-yellow-950 font-bold';
      case 'LOW':
        return 'bg-blue-600 text-white font-bold';
      default:
        return 'bg-slate-500 text-white font-bold';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-200 flex items-start justify-between bg-gradient-to-r from-amber-500/10 via-yellow-400/10 to-amber-500/10">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-yellow-400 text-yellow-950 border border-yellow-500/30 shadow-xs">
              <BookOpen className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-base sm:text-lg font-black text-slate-900 tracking-tight">
                  Malware &amp; Threat Signatures Database
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-yellow-100 text-yellow-900 font-bold border border-yellow-300">
                  PDF Guide Integrated
                </span>
              </div>
              <p className="text-xs text-slate-600 font-medium mt-0.5">
                Defensive reference catalogue based directly on the 8-page{' '}
                <em>QR Code Threat Signatures &amp; Training Guide</em>.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Top Info Banner & Direct PDF Link */}
        <div className="px-4 py-3 bg-amber-50/70 border-b border-amber-200 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 text-amber-950 font-medium">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <span>
              <strong>Zero-Confidence Principle (Section 1):</strong> Threats change constantly. Absence of a matching signature does not guarantee a QR code is safe.
            </span>
          </div>
          <a
            href="/assets/aistudio/QR_Code_Threat_Signatures_and_Training_Guide_6ae9500e.pdf"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-yellow-400 hover:bg-yellow-500 text-yellow-950 font-black transition cursor-pointer border border-yellow-500/40 text-[11px]"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>View Original PDF Guide (8 Pages)</span>
            <ExternalLink className="w-3 h-3 ml-0.5" />
          </a>
        </div>

        {/* Search & Filter Controls */}
        <div className="p-4 border-b border-slate-200 bg-slate-50/60 space-y-3">
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search signatures by ID, name, extension (.apk, .exe), rule..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-2 text-xs rounded-xl bg-white border border-slate-200 text-slate-900 focus:outline-none focus:border-amber-500 font-medium shadow-2xs"
              />
            </div>
            <div className="flex items-center gap-2">
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="text-xs py-2 px-3 rounded-xl bg-white border border-slate-200 text-slate-800 font-semibold focus:outline-none focus:border-amber-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
              </select>
            </div>
          </div>

          {/* Category Filter Pills */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[11px]">
            <span className="text-slate-400 flex items-center gap-1 shrink-0 mr-1 font-mono text-[10px] uppercase">
              <Filter className="w-3 h-3" /> Category:
            </span>
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-1 rounded-lg shrink-0 font-medium transition cursor-pointer ${
                  selectedCategory === cat
                    ? 'bg-slate-900 text-yellow-400 font-bold'
                    : 'bg-white text-slate-600 hover:bg-slate-100 border border-slate-200'
                }`}
              >
                {cat === 'ALL' ? `All (${THREAT_SIGNATURE_CATALOGUE.length})` : cat}
              </button>
            ))}
          </div>
        </div>

        {/* Signatures List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3.5 bg-slate-50/30">
          <div className="text-xs font-mono text-slate-500 flex justify-between items-center mb-1">
            <span>SHOWING {filteredSignatures.length} SIGNATURE RULES</span>
            <span>AUTO-CHECKED ON EVERY QR SCAN</span>
          </div>

          {filteredSignatures.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-white rounded-xl border border-slate-200">
              <Search className="w-8 h-8 mx-auto mb-2 text-slate-300" />
              <p className="text-sm font-semibold text-slate-700">No threat signatures match your filters</p>
              <p className="text-xs text-slate-400 mt-1">Try searching for ".apk", "homoglyph", "intent", or clear your search.</p>
            </div>
          ) : (
            filteredSignatures.map((sig) => (
              <div
                key={sig.id}
                className="p-4 rounded-xl bg-white border border-slate-200 hover:border-amber-300 transition shadow-2xs space-y-3"
              >
                {/* Header Row */}
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className={`px-2 py-0.5 text-[10px] font-mono tracking-wider rounded ${getSeverityBadge(sig.severity)}`}>
                        {sig.severity}
                      </span>
                      <span className="font-mono text-xs font-bold text-slate-900 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                        {sig.id}
                      </span>
                      <span className="text-xs font-semibold text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">
                        {sig.category}
                      </span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-900 leading-snug">{sig.name}</h4>
                    <span className="text-[11px] font-mono text-slate-500 block mt-0.5">
                      📖 {sig.pdfSection}
                    </span>
                  </div>

                  <button
                    onClick={() => {
                      onSelectSample(sig.samplePayload);
                      onClose();
                    }}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-yellow-400 hover:bg-yellow-500 text-yellow-950 font-black text-xs transition cursor-pointer border border-yellow-500/40 shadow-2xs shrink-0"
                    title="Load this test sample into scanner and analyze immediately"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Test In Scanner</span>
                  </button>
                </div>

                {/* Description & Rule */}
                <p className="text-xs text-slate-700 leading-relaxed font-medium">
                  {sig.description}
                </p>

                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1.5">
                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase block font-bold">
                      Detection Logic:
                    </span>
                    <span className="font-mono text-[11px] text-slate-800 break-all">
                      {sig.detectionRule}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] font-mono text-slate-500 uppercase block font-bold">
                      Verified Test Payload Sample:
                    </span>
                    <span className="font-mono text-[11px] text-amber-900 break-all bg-amber-50/60 p-1.5 rounded block border border-amber-200/60 select-all">
                      {sig.samplePayload}
                    </span>
                  </div>
                </div>

                {/* Consequence & Defense */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs pt-1 border-t border-slate-100">
                  <div className="p-2 rounded bg-red-50/60 border border-red-200 text-red-950">
                    <span className="font-bold block text-[10px] uppercase text-red-700">
                      Potential Threat Consequence:
                    </span>
                    <span className="text-[11px] font-medium leading-relaxed block mt-0.5">
                      {sig.consequence}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-emerald-50/60 border border-emerald-200 text-emerald-950">
                    <span className="font-bold block text-[10px] uppercase text-emerald-700">
                      Recommended Defensive Action:
                    </span>
                    <span className="text-[11px] font-medium leading-relaxed block mt-0.5">
                      {sig.defensiveAction}
                    </span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 sm:p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs">
          <div className="flex items-center gap-1.5 text-slate-600 font-medium">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>All {THREAT_SIGNATURE_CATALOGUE.length} signatures are active and checked automatically during every scan.</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 text-yellow-400 font-bold hover:bg-slate-800 transition cursor-pointer text-xs"
          >
            Close Explorer
          </button>
        </div>
      </div>
    </div>
  );
};
