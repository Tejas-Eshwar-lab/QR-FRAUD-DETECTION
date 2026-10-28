import React, { useState, useRef } from 'react';
import { BrowserQRCodeReader } from '@zxing/browser';
import { BarcodeFormat, DecodeHintType } from '@zxing/library';
import { UploadCloud, Image, AlertCircle, Sparkles, Cpu, CheckCircle2 } from 'lucide-react';

interface FileDropScannerProps {
  onScanSuccess: (payload: string) => void;
  onCancel: () => void;
}

export const FileDropScanner: React.FC<FileDropScannerProps> = ({ onScanSuccess, onCancel }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isDecoding, setIsDecoding] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [scanSpeedMetric, setScanSpeedMetric] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    if (!file.type.startsWith('image/')) {
      setErrorMessage('Please upload a valid image file (PNG, JPG, WEBP).');
      return;
    }

    setErrorMessage(null);
    setIsDecoding(true);
    setScanSpeedMetric(null);
    const startTime = performance.now();

    const objectUrl = URL.createObjectURL(file);
    setPreviewUrl(objectUrl);

    try {
      const img = document.createElement('img');
      img.src = objectUrl;

      await new Promise((resolve, reject) => {
        img.onload = resolve;
        img.onerror = () => reject(new Error('Failed to load image.'));
      });

      let detectedText: string | null = null;

      // Tier 1: Hardware-Accelerated BarcodeDetector (Fastest ~5ms)
      if (typeof window !== 'undefined' && 'BarcodeDetector' in window) {
        try {
          const detector = new (window as any).BarcodeDetector({
            formats: ['qr_code'],
          });
          const barcodes = await detector.detect(img);
          if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
            detectedText = barcodes[0].rawValue;
            const latency = Math.round(performance.now() - startTime);
            setScanSpeedMetric(`Native GPU Decoded in ${latency}ms`);
          }
        } catch (e) {
          // Fallback to ZXing
        }
      }

      // Tier 2: Optimized ZXing with QR_CODE hint only
      if (!detectedText) {
        const hints = new Map<DecodeHintType, any>();
        hints.set(DecodeHintType.POSSIBLE_FORMATS, [BarcodeFormat.QR_CODE]);
        hints.set(DecodeHintType.TRY_HARDER, false);

        const codeReader = new BrowserQRCodeReader(hints);
        try {
          const result = await codeReader.decodeFromImageElement(img);
          detectedText = result.getText();
          const latency = Math.round(performance.now() - startTime);
          setScanSpeedMetric(`Decoded in ${latency}ms`);
        } catch (e) {
          // Tier 3: Deep scan with TRY_HARDER: true
          const deepHints = new Map<DecodeHintType, any>();
          deepHints.set(DecodeHintType.POSSIBLE_FORMATS, [BarcodeFormat.QR_CODE]);
          deepHints.set(DecodeHintType.TRY_HARDER, true);
          const deepReader = new BrowserQRCodeReader(deepHints);
          const deepResult = await deepReader.decodeFromImageElement(img);
          detectedText = deepResult.getText();
          const latency = Math.round(performance.now() - startTime);
          setScanSpeedMetric(`Deep Scan Decoded in ${latency}ms`);
        }
      }

      if (detectedText) {
        onScanSuccess(detectedText);
      } else {
        setErrorMessage(
          'No valid QR code was detected in this image. Please ensure the QR is clear and well-lit.'
        );
      }
    } catch (err: any) {
      setErrorMessage(
        'Could not decode a QR code from this image. Please upload a clearer QR-code image or try scanning with the live camera.'
      );
    } finally {
      setIsDecoding(false);
    }
  };

  const handleLoadSampleImage = async () => {
    try {
      setIsDecoding(true);
      setErrorMessage(null);
      const res = await fetch('/assets/aistudio/WhatsApp_Image_2026-10-27_at_8.58.09_PM_f96091c4.jpeg');
      if (!res.ok) throw new Error('Sample image file not found on server.');
      const blob = await res.blob();
      const file = new File([blob], 'WhatsApp_Image.jpeg', { type: 'image/jpeg' });
      await handleFile(file);
    } catch (e: any) {
      setErrorMessage('Could not load sample image: ' + (e?.message || 'Network error'));
      setIsDecoding(false);
    }
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = () => {
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="w-full max-w-xl mx-auto p-6 rounded-2xl bg-white border border-yellow-300 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-base font-extrabold text-slate-900 flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-amber-600" />
            <span>Upload Existing QR Image</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Decoded locally with hardware sorting. Image files are never transmitted to any server.
          </p>
        </div>
        <button
          onClick={onCancel}
          className="text-xs font-bold text-slate-700 hover:text-slate-900 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 transition cursor-pointer"
        >
          Back to Camera
        </button>
      </div>

      {/* Drag & Drop Area */}
      <div
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all ${
          isDragging
            ? 'border-amber-500 bg-yellow-50'
            : 'border-yellow-300 hover:border-amber-400 bg-yellow-50/40'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFile(e.target.files[0]);
            }
          }}
        />

        {previewUrl ? (
          <div className="flex flex-col items-center">
            <img
              src={previewUrl}
              alt="Uploaded QR Code"
              className="w-36 h-36 object-contain rounded-lg border-2 border-yellow-300 mb-3 bg-white p-1.5 shadow-sm"
            />
            <p className="text-xs font-mono text-amber-800 font-extrabold flex items-center gap-1.5">
              {isDecoding ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping" />
                  <span>Executing Fast QR Matrix Decode...</span>
                </>
              ) : (
                <span>{scanSpeedMetric || 'Click to select a different image'}</span>
              )}
            </p>
          </div>
        ) : (
          <>
            <div className="w-14 h-14 rounded-2xl bg-yellow-100 border border-yellow-300 flex items-center justify-center text-amber-800 mb-3 shadow-inner">
              <Image className="w-7 h-7" />
            </div>
            <p className="text-sm font-black text-slate-800 mb-1">
              Drop screenshot or QR photo here
            </p>
            <p className="text-xs text-slate-500 max-w-xs mb-2">
              Supports PNG, JPG, WEBP, or SVG files from your device
            </p>
            <div className="inline-flex items-center gap-1 text-[11px] font-mono text-amber-900 bg-yellow-200/70 px-2.5 py-0.5 rounded-full font-bold">
              <Sparkles className="w-3 h-3 text-amber-700" />
              <span>Multi-Tier Fast Decoding: Active</span>
            </div>
          </>
        )}
      </div>

      {/* Quick sample image shortcut */}
      <div className="mt-3 flex items-center justify-between text-xs text-slate-600 pt-2.5 border-t border-slate-100 font-medium">
        <span>Have an image ready to test?</span>
        <button
          type="button"
          onClick={handleLoadSampleImage}
          disabled={isDecoding}
          className="text-xs font-black text-amber-950 bg-amber-300 hover:bg-amber-400 border border-amber-400 px-3.5 py-1.5 rounded-lg transition cursor-pointer disabled:opacity-50 shadow-2xs"
        >
          {isDecoding ? 'Decoding...' : 'Load Attached Sample QR Image'}
        </button>
      </div>

      {/* Error state */}
      {errorMessage && (
        <div className="mt-4 p-3.5 rounded-xl bg-amber-50 border border-amber-300 text-amber-900 text-xs flex items-start gap-2.5 shadow-sm">
          <AlertCircle className="w-4 h-4 shrink-0 text-amber-600 mt-0.5" />
          <p className="leading-relaxed font-semibold">{errorMessage}</p>
        </div>
      )}
    </div>
  );
};
