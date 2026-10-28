import React, { useState } from 'react';
import {
  EVALUATION_DATASET,
  SECTION_8_TEST_CASES,
  runAutomatedEvaluation,
  EvaluationMetrics,
  LabelledTestCase,
  Section8TestCase,
} from '../lib/evaluationDataset';
import {
  FlaskConical,
  Play,
  CheckCircle2,
  XCircle,
  AlertCircle,
  X,
  ShieldAlert,
  ArrowRight,
  ListOrdered,
  FileCheck2,
} from 'lucide-react';

interface TestBenchModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectPayload: (payload: string) => void;
}

export const TestBenchModal: React.FC<TestBenchModalProps> = ({
  isOpen,
  onClose,
  onSelectPayload,
}) => {
  const [activeTab, setActiveTab] = useState<'SECTION_8' | 'ALL_120'>('SECTION_8');
  const [evalMetrics, setEvalMetrics] = useState<EvaluationMetrics | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  if (!isOpen) return null;

  const handleRunEvaluation = () => {
    setIsRunning(true);
    setTimeout(() => {
      const outcome = runAutomatedEvaluation();
      setEvalMetrics(outcome.metrics);
      setIsRunning(false);
    }, 400);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-4xl max-h-[92vh] bg-white border border-slate-200 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/90">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-100 border border-amber-300 flex items-center justify-center text-amber-900 shadow-sm">
              <FlaskConical className="w-5 h-5 text-amber-700" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>Security Test Bench &amp; Research Suites</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-yellow-100 text-yellow-900 border border-yellow-300 font-bold">
                  12 Cases &amp; 120 Synthetic QRs
                </span>
              </h3>
              <p className="text-xs text-slate-500">
                Official Validation Cases (Section 8) &amp; arXiv:2505.03451v2 Benchmark
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 flex items-center justify-center transition cursor-pointer"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="px-5 pt-3 pb-0 border-b border-slate-100 flex items-center gap-2 bg-slate-50/40">
          <button
            onClick={() => setActiveTab('SECTION_8')}
            className={`px-3.5 py-2 text-xs font-bold rounded-t-lg transition flex items-center gap-2 cursor-pointer border-b-2 -mb-px ${
              activeTab === 'SECTION_8'
                ? 'border-amber-500 text-amber-950 bg-white shadow-2xs font-extrabold'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <ListOrdered className="w-4 h-4 text-amber-600" />
            <span>Section 8 Test Cases (12 Mandatory Scenarios)</span>
          </button>
          <button
            onClick={() => setActiveTab('ALL_120')}
            className={`px-3.5 py-2 text-xs font-bold rounded-t-lg transition flex items-center gap-2 cursor-pointer border-b-2 -mb-px ${
              activeTab === 'ALL_120'
                ? 'border-amber-500 text-amber-950 bg-white shadow-2xs font-extrabold'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            <FileCheck2 className="w-4 h-4 text-emerald-600" />
            <span>120 Synthetic Test Bench &amp; Metrics</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 overflow-y-auto space-y-5 flex-1 text-xs text-slate-700">
          {activeTab === 'SECTION_8' ? (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-yellow-50/80 border border-yellow-300 text-yellow-950 text-xs space-y-1">
                <span className="font-extrabold block text-yellow-900 text-xs flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 text-amber-600" />
                  <span>Section 8 Mandatory Test Verification Suite:</span>
                </span>
                <p className="text-yellow-900 font-medium leading-relaxed">
                  Click any of the 12 numbered test cases below to immediately execute and verify how ScamTrace AI handles each specific threat vector, fallback condition, or failure recovery state.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {SECTION_8_TEST_CASES.map((tc) => (
                  <div
                    key={tc.caseNumber}
                    onClick={() => {
                      onSelectPayload(tc.payload);
                      onClose();
                    }}
                    className="p-3.5 rounded-xl bg-white hover:bg-amber-50/60 border border-slate-200 hover:border-amber-400 transition cursor-pointer flex flex-col justify-between gap-2 shadow-2xs group"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="font-extrabold text-slate-900 text-xs flex items-center gap-1.5 group-hover:text-amber-900 transition">
                          <span className="w-5 h-5 rounded-md bg-amber-100 text-amber-950 border border-amber-300 flex items-center justify-center font-mono text-[10px] font-bold">
                            {tc.caseNumber}
                          </span>
                          <span>{tc.title}</span>
                        </span>
                        <span
                          className={`text-[9px] font-mono px-2 py-0.5 rounded font-bold border shrink-0 ${
                            tc.category === 'BENIGN'
                              ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                              : tc.category === 'UNKNOWN'
                              ? 'bg-yellow-100 text-yellow-900 border-yellow-300'
                              : tc.category === 'MALWARE'
                              ? 'bg-red-50 text-red-800 border-red-200'
                              : tc.category === 'FAILURE'
                              ? 'bg-slate-100 text-slate-800 border-slate-300'
                              : 'bg-amber-100 text-amber-900 border-amber-300'
                          }`}
                        >
                          {tc.category}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-600 leading-snug font-medium mb-1.5">
                        {tc.expectedBehavior}
                      </p>
                    </div>

                    <div className="flex items-center justify-between pt-2 border-t border-slate-100 text-[10px] font-mono text-slate-500">
                      <span className="truncate max-w-[200px]">{tc.payload}</span>
                      <span className="text-amber-700 font-bold group-hover:translate-x-1 transition flex items-center gap-0.5">
                        <span>TEST</span>
                        <ArrowRight className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="space-y-5">
              {/* Top Banner: Synthetic Test Set Notice */}
              <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-300 text-xs text-amber-950 space-y-1.5 leading-relaxed shadow-xs">
                <p className="font-bold text-amber-900 flex items-center gap-1.5">
                  <AlertCircle className="w-4 h-4 text-amber-600" />
                  <span>Synthetic Test Corpus Notice (images_120_qr_code_35e1ffd3.pdf):</span>
                </p>
                <p className="text-amber-900 font-medium">
                  These 120 samples encode URLs on the reserved <code>.invalid</code> domain (RFC 6761) to safely simulate malicious patterns without referencing live attack servers.
                </p>
              </div>

              {/* Automated Evaluation Section */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                      Automated 120-Sample Benchmark Runner
                    </h4>
                    <p className="text-xs text-slate-500">
                      Evaluates all synthetic fixtures to calculate Precision, Recall, and False-Positive rate.
                    </p>
                  </div>
                  <button
                    onClick={handleRunEvaluation}
                    disabled={isRunning}
                    className="h-9 px-4 rounded-lg bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition active:scale-95 disabled:opacity-50 cursor-pointer shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>{isRunning ? 'EVALUATING...' : 'RUN BENCHMARK'}</span>
                  </button>
                </div>

                {/* Metrics Dashboard */}
                {evalMetrics && (
                  <div className="mt-4 pt-4 border-t border-slate-200">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-xs">
                        <span className="text-[10px] text-slate-500 font-mono block">PRECISION</span>
                        <span className="text-lg font-bold font-mono text-emerald-600">
                          {(evalMetrics.precision * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-xs">
                        <span className="text-[10px] text-slate-500 font-mono block">RECALL</span>
                        <span className="text-lg font-bold font-mono text-emerald-600">
                          {(evalMetrics.recall * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-xs">
                        <span className="text-[10px] text-slate-500 font-mono block">ACCURACY</span>
                        <span className="text-lg font-bold font-mono text-slate-900">
                          {(evalMetrics.accuracy * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-xs">
                        <span className="text-[10px] text-slate-500 font-mono block">FALSE POSITIVE RATE</span>
                        <span className="text-lg font-bold font-mono text-amber-600">
                          {(evalMetrics.falsePositiveRate * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-600 px-1 font-semibold">
                      <span>True Positives: {evalMetrics.truePositives}</span>
                      <span>True Negatives: {evalMetrics.trueNegatives}</span>
                      <span>False Positives: {evalMetrics.falsePositives}</span>
                      <span>False Negatives: {evalMetrics.falseNegatives}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Test Vectors Browser */}
              <div>
                <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2.5">
                  Available Labelled Test Samples
                </h4>
                <div className="space-y-2">
                  {EVALUATION_DATASET.map((tc) => (
                    <div
                      key={tc.id}
                      onClick={() => {
                        onSelectPayload(tc.payload);
                        onClose();
                      }}
                      className="p-3 rounded-xl bg-white hover:bg-amber-50/60 border border-slate-200 hover:border-amber-300 transition cursor-pointer flex items-center justify-between gap-3 group shadow-2xs"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span className="text-xs font-bold text-slate-900 group-hover:text-amber-900 transition">
                            {tc.name}
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-50 text-slate-700 border border-slate-200 font-semibold">
                            {tc.category}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">
                            Expected: {tc.expectedVerdict}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-600 leading-snug font-medium">
                          {tc.description}
                        </p>
                        <p className="text-[10px] font-mono text-slate-500 truncate mt-1">
                          {tc.payload}
                        </p>
                      </div>
                      <div className="shrink-0 flex items-center gap-1 text-xs text-amber-700 font-bold group-hover:translate-x-1 transition">
                        <span className="hidden sm:inline text-[11px] font-mono">TEST NOW</span>
                        <ArrowRight className="w-4 h-4" />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
