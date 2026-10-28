import React from 'react';
import { ScanResult } from '../types/security';
import { History, Trash2, Download, X, ArrowRight, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

interface AuditHistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  history: ScanResult[];
  onSelectResult: (res: ScanResult) => void;
  onClearHistory: () => void;
  isHistoryEnabled: boolean;
  setIsHistoryEnabled: (val: boolean) => void;
}

export const AuditHistoryModal: React.FC<AuditHistoryModalProps> = ({
  isOpen,
  onClose,
  history,
  onSelectResult,
  onClearHistory,
  isHistoryEnabled,
  setIsHistoryEnabled,
}) => {
  if (!isOpen) return null;

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(history, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `scamtrace-audit-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-2xl max-h-[85vh] bg-white border border-slate-200 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-100 border border-emerald-300 flex items-center justify-center text-emerald-800">
              <History className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Scan Audit History
              </h3>
              <p className="text-xs text-slate-500">
                Local-only device log ({history.length} records)
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

        {/* Privacy & Control Bar */}
        <div className="p-3.5 bg-slate-50/70 border-b border-slate-200 flex items-center justify-between flex-wrap gap-2 text-xs">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={isHistoryEnabled}
              onChange={(e) => setIsHistoryEnabled(e.target.checked)}
              className="w-4 h-4 rounded text-emerald-600 bg-white border-slate-300 focus:ring-emerald-500 cursor-pointer"
            />
            <span className="text-slate-800 font-bold">Store local device history</span>
          </label>

          <div className="flex items-center gap-2">
            {history.length > 0 && (
              <>
                <button
                  onClick={handleExportJson}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-100 text-slate-700 border border-slate-300 transition cursor-pointer font-mono text-[11px] font-bold shadow-2xs"
                >
                  <Download className="w-3.5 h-3.5 text-emerald-600" />
                  <span>EXPORT JSON</span>
                </button>
                <button
                  onClick={onClearHistory}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 transition cursor-pointer font-mono text-[11px] font-bold shadow-2xs"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>CLEAR ALL</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* List of scans */}
        <div className="p-4 overflow-y-auto space-y-2 flex-1">
          {history.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-xs font-medium">
              No scan records in local storage.
            </div>
          ) : (
            history.map((record) => (
              <div
                key={record.id}
                onClick={() => {
                  onSelectResult(record);
                  onClose();
                }}
                className="p-3 rounded-xl bg-slate-50 hover:bg-emerald-50 border border-slate-200 hover:border-emerald-300 transition cursor-pointer flex items-center justify-between gap-3 group shadow-2xs"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                        record.overallRisk === 'CONFIRMED_THREAT'
                          ? 'bg-red-100 text-red-800 border-red-300'
                          : record.overallRisk === 'SUSPICIOUS'
                          ? 'bg-amber-100 text-amber-800 border-amber-300'
                          : record.overallRisk === 'NO_KNOWN_THREAT'
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-300'
                          : 'bg-yellow-100 text-yellow-800 border-yellow-300'
                      }`}
                    >
                      {record.overallRisk}
                    </span>
                    <span className="text-[11px] font-mono text-slate-600 font-bold">
                      {record.payloadType}
                    </span>
                    <span className="text-[11px] text-slate-400">
                      {new Date(record.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-xs text-slate-800 truncate font-mono font-medium">
                    {record.rawPayload}
                  </p>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-emerald-700 group-hover:translate-x-1 transition shrink-0" />
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
