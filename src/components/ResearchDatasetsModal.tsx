import React from 'react';
import { Database, ExternalLink, BookOpen, X, ArrowRight, ShieldCheck, FileCheck } from 'lucide-react';

interface ResearchDatasetsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectSample: (payload: string) => void;
}

export const ResearchDatasetsModal: React.FC<ResearchDatasetsModalProps> = ({
  isOpen,
  onClose,
  onSelectSample,
}) => {
  if (!isOpen) return null;

  const starterPackSamples = [
    {
      id: 'TEST-001',
      name: 'Google Malware Test Fixture',
      category: 'official_security_test_fixture',
      payload: 'http://testsafebrowsing.appspot.com/s/malware.html',
      notes: 'Official Google Safe Browsing test page simulating a malware distribution vector.',
    },
    {
      id: 'TEST-002',
      name: 'Google Phishing Test Fixture',
      category: 'official_security_test_fixture',
      payload: 'https://testsafebrowsing.appspot.com/s/phishing.html',
      notes: 'Official Google Safe Browsing fixture simulating credential phishing.',
    },
    {
      id: 'BENIGN-001',
      name: 'Example.org Benign Standard',
      category: 'benign_known',
      payload: 'https://example.org/',
      notes: 'Reserved IANA example domain representing safe benign web content.',
    },
    {
      id: 'SYNTH-001',
      name: 'PayPal Lookalike Domain Lure',
      category: 'suspicious_heuristic_only',
      payload: 'https://paypaI-login.example/auth',
      notes: 'Synthetic lookalike domain using capital I instead of lowercase l.',
    },
    {
      id: 'SYNTH-002',
      name: 'Short Link Cloaking Pattern',
      category: 'suspicious_heuristic_only',
      payload: 'https://short.example/AbC123_token',
      notes: 'Synthetic shortened link pattern used to evaluate cloaking detection.',
    },
  ];

  const datasetSources = [
    {
      name: 'CIC-Trap4Phish 2025',
      institution: 'Canadian Institute for Cybersecurity (UNB)',
      reportedSize: '1,000,000 QR images (430k benign, 575k malicious)',
      description: 'Quishing benchmark covering image subset plus URL strings for defensive quishing research.',
      link: 'https://www.unb.ca/cic/datasets/trap4phish2025.html',
    },
    {
      name: 'Mendeley Malicious & Benign QR Codes (2025)',
      institution: 'Mendeley Data (CC BY 4.0)',
      reportedSize: '1,000 QR images (500 malicious, 500 benign)',
      description: 'Hand-curated image classification benchmark for visual and pixel analysis.',
      link: 'https://data.mendeley.com/datasets/cmhh7744sp/1',
    },
    {
      name: 'BanglaQR-Quish Synthetic Dataset (2026)',
      institution: 'Mendeley Data (CC BY 4.0)',
      reportedSize: '50,000 synthetic QR images (25k benign, 25k malicious)',
      description: 'Payment-specific QR scenarios including URL injection and payment redirection.',
      link: 'https://data.mendeley.com/datasets/pz95pr8pyd/1',
    },
    {
      name: 'Mobile QR Scanner Quishing Dataset',
      institution: 'GitHub (CC0-1.0)',
      reportedSize: '1,000 URLs (850 phishing, 150 benign)',
      description: 'Empirical study dataset evaluating real-world mobile scanner detection outcomes.',
      link: 'https://github.com/Hyphen-14/quishing-scanner-empirical-study-dataset',
    },
    {
      name: 'URLhaus Threat Intel Feed',
      institution: 'abuse.ch',
      reportedSize: 'Live Community Feed',
      description: 'Real-time database of confirmed malware-associated URLs and cyber threats.',
      link: 'https://urlhaus.abuse.ch/api/',
    },
    {
      name: 'PhishTank Developer Feed',
      institution: 'OpenDNS / Cisco',
      reportedSize: 'Live Verified Feed',
      description: 'Global crowdsourced and verified database of active phishing URLs.',
      link: 'https://phishtank.org/developer_info.php',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-4xl max-h-[92vh] bg-white border border-slate-200 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-100 border border-emerald-300 flex items-center justify-center text-emerald-800">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Research Datasets &amp; Starter Pack
              </h3>
              <p className="text-xs text-slate-500">
                Official benchmarks, academic quishing corpora, and safe evaluation fixtures
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
        <div className="p-5 overflow-y-auto space-y-6 flex-1 text-xs text-slate-700">
          {/* Starter Pack Samples Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
                <FileCheck className="w-4 h-4 text-emerald-600" />
                <span>Uploaded Starter Pack Fixtures (Click to Test)</span>
              </h4>
              <span className="text-[10px] font-mono text-slate-500">From qr_examples_metadata.csv</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {starterPackSamples.map((sample) => (
                <div
                  key={sample.id}
                  onClick={() => {
                    onSelectSample(sample.payload);
                    onClose();
                  }}
                  className="p-3.5 rounded-xl bg-slate-50 hover:bg-emerald-50 border border-slate-200 hover:border-emerald-300 transition cursor-pointer flex flex-col justify-between group shadow-2xs"
                >
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-slate-900 group-hover:text-emerald-800 transition text-xs">
                        {sample.name}
                      </span>
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-white text-slate-700 border border-slate-200 font-semibold">
                        {sample.id}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-600 leading-snug mb-2 font-medium">
                      {sample.notes}
                    </p>
                  </div>
                  <div className="flex items-center justify-between pt-2 border-t border-slate-200 font-mono text-[10px] text-slate-500">
                    <span className="truncate max-w-[200px]">{sample.payload}</span>
                    <span className="text-emerald-700 font-bold flex items-center gap-1 group-hover:translate-x-0.5 transition">
                      TEST <ArrowRight className="w-3 h-3" />
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Academic & Open Threat Intelligence Sources Index */}
          <div className="space-y-3 pt-2">
            <div className="flex items-center justify-between">
              <h4 className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
                <BookOpen className="w-4 h-4 text-purple-700" />
                <span>Indexed Research Sources &amp; Licensing</span>
              </h4>
              <span className="text-[10px] font-mono text-slate-500">From dataset_sources.csv</span>
            </div>

            <div className="space-y-2">
              {datasetSources.map((ds, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex items-start justify-between gap-4 shadow-2xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-slate-900 text-xs">{ds.name}</span>
                      <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-purple-100 text-purple-800 border border-purple-200 font-bold">
                        {ds.institution}
                      </span>
                      <span className="text-[10px] font-mono text-emerald-700 font-bold">
                        {ds.reportedSize}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-600 leading-relaxed font-medium">
                      {ds.description}
                    </p>
                  </div>
                  <a
                    href={ds.link}
                    target="_blank"
                    rel="noreferrer"
                    className="shrink-0 p-2 rounded-lg bg-white hover:bg-slate-100 text-slate-800 border border-slate-300 transition flex items-center gap-1 text-[11px] font-mono font-bold shadow-2xs"
                  >
                    <span>SOURCE</span>
                    <ExternalLink className="w-3 h-3 text-emerald-600" />
                  </a>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
