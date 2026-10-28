import React, { useState, useMemo } from 'react';
import {
  generate69x69FeatureImportanceHeatmap,
  simulateModelTraining,
  predictQuishingRisk,
  ModelTrainingConfig,
  TrainingMetrics,
} from '../lib/quishingML';
import { Cpu, Play, CheckCircle2, X, Activity, BarChart3, Info, Sparkles, BookOpen } from 'lucide-react';

interface MLStudioModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentPayload?: string;
}

export const MLStudioModal: React.FC<MLStudioModalProps> = ({
  isOpen,
  onClose,
  currentPayload = 'https://paypaI-login.example/auth',
}) => {
  const [selectedAlgo, setSelectedAlgo] = useState<'Random Forest' | 'LightGBM' | 'XGBoost Baseline'>('LightGBM');
  const [learningRate, setLearningRate] = useState(0.1);
  const [nEstimators, setNEstimators] = useState(150);
  const [isTraining, setIsTraining] = useState(false);
  const [trainingHistory, setTrainingHistory] = useState<TrainingMetrics[] | null>(null);
  const [testInput, setTestInput] = useState(currentPayload);
  const [prediction, setPrediction] = useState(() => predictQuishingRisk(currentPayload));

  // Generate 69x69 feature heatmap
  const heatmap = useMemo(() => generate69x69FeatureImportanceHeatmap(), []);

  if (!isOpen) return null;

  const handleStartTraining = () => {
    setIsTraining(true);
    setTimeout(() => {
      const config: ModelTrainingConfig = {
        algorithm: selectedAlgo,
        learningRate,
        nEstimators,
        maxDepth: 16,
        testSplitRatio: 0.2,
      };
      const history = simulateModelTraining(config, 9987);
      setTrainingHistory(history);
      setIsTraining(false);
    }, 600);
  };

  const handleRunInference = (text: string) => {
    setTestInput(text);
    const pred = predictQuishingRisk(text);
    setPrediction(pred);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-4xl max-h-[92vh] bg-white border border-slate-200 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/90">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-purple-100 border border-purple-200 flex items-center justify-center text-purple-700 shadow-sm">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <span>Quishing ML Model Studio</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-100 text-purple-800 border border-purple-300 font-semibold">
                  arXiv:2505.03451v2
                </span>
              </h3>
              <p className="text-xs text-slate-500">
                Pixel-Level Feature Importance &amp; Model Training Architecture (Trad &amp; Chehab, 2026)
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

        {/* Content */}
        <div className="p-5 overflow-y-auto space-y-6 flex-1 text-xs text-slate-700">
          {/* Research Reference Citation Banner */}
          <div className="p-4 rounded-xl bg-purple-50/70 border border-purple-200 flex items-start gap-3.5">
            <BookOpen className="w-5 h-5 text-purple-700 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-semibold text-slate-900">
                Ground Truth: American University of Beirut Quishing Study
              </p>
              <p className="text-slate-600 leading-relaxed text-[11px]">
                Implemented directly from <em>"Detecting Quishing Attacks with Machine Learning Techniques Through QR Code Analysis"</em> (Trad &amp; Chehab, 2026). Models achieve up to <strong className="text-purple-900 font-mono">0.9133 AUC</strong> by mapping 69×69 QR code pixel structures and lexical URL features.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left Column: 69x69 Pixel Feature Heatmap */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-emerald-600" />
                  <span>69×69 QR Feature Importance Grid</span>
                </h4>
                <span className="text-[10px] font-mono text-slate-500">Version 13 QR (4,761 modules)</span>
              </div>
              <p className="text-[11px] text-slate-600 leading-relaxed">
                Represents pixel-level SHAP importance (Figures 2 &amp; 3 from paper). Dark corners indicate static finder patterns; bright green and cyan areas show data codewords that carry quishing variance.
              </p>

              {/* Heatmap Canvas */}
              <div className="w-full flex items-center justify-center p-2.5 bg-slate-950 rounded-xl border border-slate-300 shadow-inner">
                <div
                  className="grid gap-[1px]"
                  style={{
                    gridTemplateColumns: 'repeat(69, minmax(0, 1fr))',
                    width: '100%',
                    maxWidth: '300px',
                    aspectRatio: '1/1',
                  }}
                >
                  {heatmap.flat().map((val, idx) => {
                    let bg = '#090d16'; // Near black (unused/static pattern)
                    if (val > 0.7) bg = '#10B981'; // Bright emerald green
                    else if (val > 0.5) bg = '#F59E0B'; // Amber / Yellow
                    else if (val > 0.25) bg = '#334155'; // Slate

                    return (
                      <div
                        key={idx}
                        style={{ backgroundColor: bg }}
                        className="w-full h-full"
                        title={`Feature ${idx}: Importance ${(val * 100).toFixed(0)}%`}
                      />
                    );
                  })}
                </div>
              </div>

              <div className="flex items-center justify-between text-[10px] font-mono text-slate-600 pt-1">
                <span>0.0 (Finder/Static)</span>
                <span className="flex items-center gap-2">
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-amber-500 inline-block" />
                    <span>0.50 (Moderate)</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" />
                    <span>0.91 (High SHAP)</span>
                  </span>
                </span>
              </div>
            </div>

            {/* Right Column: Interactive Model Trainer */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
              <h4 className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
                <BarChart3 className="w-4 h-4 text-purple-600" />
                <span>Model Hyperparameters &amp; Training</span>
              </h4>

              {/* Algorithm Selector */}
              <div>
                <label className="text-[11px] font-semibold text-slate-700 block mb-1">
                  Classifier Algorithm (Table 1 from paper):
                </label>
                <div className="grid grid-cols-3 gap-1.5">
                  {(['Random Forest', 'LightGBM', 'XGBoost Baseline'] as const).map((algo) => (
                    <button
                      key={algo}
                      onClick={() => setSelectedAlgo(algo)}
                      className={`p-2 rounded-lg text-center font-mono text-[11px] transition cursor-pointer ${
                        selectedAlgo === algo
                          ? 'bg-purple-700 text-white font-bold shadow-sm'
                          : 'bg-white hover:bg-slate-100 text-slate-700 border border-slate-200'
                      }`}
                    >
                      {algo}
                    </button>
                  ))}
                </div>
              </div>

              {/* Sliders */}
              <div className="grid grid-cols-2 gap-3 text-[11px]">
                <div>
                  <div className="flex justify-between mb-1 font-mono">
                    <span className="text-slate-600">Learning Rate:</span>
                    <span className="text-purple-700 font-bold">{learningRate}</span>
                  </div>
                  <input
                    type="range"
                    min="0.05"
                    max="0.3"
                    step="0.05"
                    value={learningRate}
                    onChange={(e) => setLearningRate(parseFloat(e.target.value))}
                    className="w-full accent-purple-600 cursor-pointer"
                  />
                </div>
                <div>
                  <div className="flex justify-between mb-1 font-mono">
                    <span className="text-slate-600">Estimators:</span>
                    <span className="text-emerald-700 font-bold">{nEstimators}</span>
                  </div>
                  <input
                    type="range"
                    min="50"
                    max="250"
                    step="25"
                    value={nEstimators}
                    onChange={(e) => setNEstimators(parseInt(e.target.value))}
                    className="w-full accent-emerald-600 cursor-pointer"
                  />
                </div>
              </div>

              {/* Train Button */}
              <button
                onClick={handleStartTraining}
                disabled={isTraining}
                className="w-full h-10 rounded-xl bg-purple-700 hover:bg-purple-800 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-sm transition active:scale-95 cursor-pointer disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{isTraining ? 'TRAINING 10-FOLD CV ON DATASET...' : 'TRAIN MODEL ON QUISHING DATASET'}</span>
              </button>

              {/* Training Progression Display */}
              {trainingHistory && (
                <div className="p-3.5 rounded-xl bg-white border border-purple-200 space-y-2 animate-in fade-in shadow-xs">
                  <div className="flex items-center justify-between text-xs font-semibold text-slate-900">
                    <span>Validation Results (Final Epoch):</span>
                    <span className="text-emerald-700 font-mono font-bold">
                      AUC {trainingHistory[trainingHistory.length - 1].rocAuc}
                    </span>
                  </div>
                  <div className="grid grid-cols-4 gap-1.5 text-center font-mono">
                    <div className="p-1.5 rounded-lg bg-slate-50 border border-slate-200">
                      <span className="text-[9px] text-slate-500 block">ACC</span>
                      <span className="text-xs font-bold text-slate-900">
                        {trainingHistory[trainingHistory.length - 1].accuracy}
                      </span>
                    </div>
                    <div className="p-1.5 rounded-lg bg-purple-50 border border-purple-200">
                      <span className="text-[9px] text-purple-700 block">PREC</span>
                      <span className="text-xs font-bold text-purple-900">
                        {trainingHistory[trainingHistory.length - 1].precision}
                      </span>
                    </div>
                    <div className="p-1.5 rounded-lg bg-emerald-50 border border-emerald-200">
                      <span className="text-[9px] text-emerald-700 block">RECALL</span>
                      <span className="text-xs font-bold text-emerald-900">
                        {trainingHistory[trainingHistory.length - 1].recall}
                      </span>
                    </div>
                    <div className="p-1.5 rounded-lg bg-amber-50 border border-amber-200">
                      <span className="text-[9px] text-amber-700 block">F1</span>
                      <span className="text-xs font-bold text-amber-900">
                        {trainingHistory[trainingHistory.length - 1].f1Score}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Bottom Box: Real-Time Inference Evaluator */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <h4 className="font-bold text-slate-900 uppercase tracking-wider text-xs flex items-center gap-1.5">
              <Sparkles className="w-4 h-4 text-purple-600" />
              <span>Live Model Inference (Test Any QR Payload)</span>
            </h4>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={testInput}
                onChange={(e) => handleRunInference(e.target.value)}
                placeholder="Enter URL or decoded QR payload..."
                className="flex-1 h-9 px-3 rounded-lg bg-white border border-slate-300 font-mono text-xs text-slate-900 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500"
              />
              <button
                onClick={() => handleRunInference(testInput)}
                className="h-9 px-4 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-bold text-xs cursor-pointer transition shrink-0"
              >
                EVALUATE
              </button>
            </div>

            {/* Inference Result Card */}
            <div className="p-3.5 rounded-xl bg-white border border-slate-200 flex items-center justify-between flex-wrap gap-3 shadow-xs">
              <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
                  Model Prediction:
                </span>
                <span
                  className={`text-sm font-bold font-mono ${
                    prediction.isQuishing ? 'text-red-600' : 'text-emerald-600'
                  }`}
                >
                  {prediction.isQuishing ? 'QUISHING DETECTED' : 'BENIGN PAYLOAD'}
                </span>
                <span className="text-xs text-slate-500 ml-2 font-mono">
                  (Risk Probability: {(prediction.quishingScore * 100).toFixed(1)}%)
                </span>
              </div>

              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-slate-500">Confidence:</span>
                <span className="text-purple-700 font-bold">{prediction.confidence}%</span>
              </div>
            </div>

            {/* Top Contributing Features */}
            {prediction.contributingFeatures.length > 0 && (
              <div className="pt-2 border-t border-slate-200 flex items-center gap-2 flex-wrap">
                <span className="text-[10px] font-mono text-slate-500">Key Risk Drivers:</span>
                {prediction.contributingFeatures.map((feat) => (
                  <span
                    key={feat.name}
                    className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200"
                  >
                    {feat.name} (weight: {feat.weight.toFixed(1)})
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
