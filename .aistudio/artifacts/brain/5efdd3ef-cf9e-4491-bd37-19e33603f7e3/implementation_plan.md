# ScamTrace AI — Quishing ML Detection, Malware Diagnostics & Threat Neutralization

ScamTrace AI is a production-grade, explainable QR code cybersecurity application engineered to decode and inspect QR payloads, execute machine-learning quishing classification based on the Trad & Chehab (2026) research framework, explain malware delivery mechanics, and provide actionable threat neutralization and device decontamination protocols.

## User Review & Critical Decisions

> [!IMPORTANT]
> - **Malware Delivery Reality & Explanation**: A QR code is a data carrier (encoding a URL, URI, or text string), not an executable binary file itself. ScamTrace AI will explain exactly how the QR delivers malware (e.g., drive-by APK drops, banking trojans, credential phishing) based on payload forensics and threat intelligence taxonomy.
> - **Remediation & Decontamination ("Remove the Malware")**: Since a printed QR code cannot be edited in the physical world, ScamTrace AI provides a three-tier remediation suite:
>   1. **Payload Defanging & Sanitization**: Neutralizes dangerous schemes (`hxxp://`), strips tracking and download tokens, and prevents automated execution.
>   2. **Device Decontamination Protocol**: Clear, step-by-step triage for users who already clicked or downloaded a file (Android Play Protect audit, APK quarantine checklist, Accessibility permission revocation, credential rotation).
>   3. **Threat Takedown & Reporting**: One-click generation of RFC-compliant abuse reports for Google Safe Browsing, URLhaus, and domain registrars.
> - **Quishing ML Model Studio**: Implements a real, interactive machine-learning module inspired by the uploaded research paper (*Detecting Quishing Attacks with Machine Learning Techniques Through QR Code Analysis*, Trad & Chehab, arXiv:2505.03451v2). Includes pre-trained weights, live model retraining, feature importance heatmap (69x69 QR pixel matrix), and real ROC/AUC evaluation.
> - **Multi-Feed Threat Intelligence**: Expands the backend threat engine to query Google Web Risk, URLhaus, and PhishTank test feeds with transparent provider status and zero fabricated results.

---

### Confirmed Decisions Summary
- **Architecture**: Full-stack Express backend (`server.ts`) with Vite SPA frontend.
- **ML Engine**: Hybrid model combining QR structural pixel analysis (Trad & Chehab model) with lexical URL risk scoring.
- **Malware Analysis**: Threat family attribution (Trojans, Infostealers, Phishing kits, Fake payment collectors) derived from live feeds and heuristic signatures.
- **Decontamination**: Actionable remediation wizard for post-scan incident response.

---

## 1. Overview & Core Concept

**ScamTrace AI** bridges physical QR scanning with deep digital forensics. When users ask *"What malware is inside my QR code?"* and *"How can I remove it?"*, the engine provides an uncompromising, clear technical breakdown:
1. Explains what the QR payload is attempting to execute or download.
2. Identifies whether it leads to known trojans (e.g., SharkBot, TeaBot APKs), credential harvesters, or financial fraud.
3. Guides the user through neutralizing the link and cleaning their device if exposed.
4. Allows security analysts and users to train and benchmark the machine-learning quishing detector directly in the app.

---

## 2. User Experience & Visual Design

Following the **Universal Frontend Design Constitution** and **Mobile & Touch-First Design Reference**:

### Visual Identity
- **Cybersecurity Dark Canvas**: Deep obsidian navy (`#080D1A`), structural slate (`#131D33`), subtle cyan hairline borders (`rgba(0, 240, 255, 0.2)`), and high-contrast alert accents (`#EF4444` Threat, `#F59E0B` Suspicious, `#10B981` Clean).
- **Typography**: Display headers in `Plus Jakarta Sans`, technical telemetry in `JetBrains Mono` (`font-mono tabular-nums`).
- **Zero-Pill Discipline**: Clean unboxed metadata with typographic separators (`·`).

### Navigation Structure
- **Live Scanner**: In-browser camera with cyber reticle, rear-camera preference, and torch.
- **Upload & File Drop**: Local image decoding via `@zxing/browser`.
- **Malware Diagnostic & Remediation Panel**: Deep payload breakdown, malware delivery vectors, defanging tool, and device decontamination wizard.
- **ML Model Studio**: Interactive model training, 69x69 feature importance heatmap viewer, and live test evaluation based on Trad & Chehab (arXiv:2505.03451v2).
- **Threat Intel & Sources**: Research dataset browser indexing CIC-Trap4Phish, Mendeley, BanglaQR-Quish, URLhaus, and Google Web Risk.
- **Audit History**: Private local storage log with export and purge.

---

## 3. Technical Architecture & Component Hierarchy

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                               CLIENT BROWSER (Vite + React)                  │
├──────────────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌──────────────────┐  │
│  │   LiveCameraScanner   │  │   FileDropScanner     │  │  ML Model Studio │  │
│  └───────────┬───────────┘  └───────────┬───────────┘  └─────────┬────────┘  │
│              │                          │                        │           │
│              └─────────────────┬────────┴────────────────────────┘           │
│                                ▼                                             │
│                 ┌─────────────────────────────┐                              │
│                 │  Payload Parser & Router    │                              │
│                 └──────────────┬──────────────┘                              │
│                                │                                             │
│        ┌───────────────────────┼────────────────────────┐                    │
│        ▼                       ▼                        ▼                    │
│  ┌───────────────┐     ┌───────────────┐      ┌──────────────────┐           │
│  │ URL & Domain  │     │  UPI & Pay    │      │ Quishing ML      │           │
│  │ Heuristics    │     │  Protection   │      │ Feature Engine   │           │
│  └───────┬───────┘     └───────┬───────┘      └─────────┬────────┘           │
│          │                     │                        │                    │
│          └─────────────────────┼────────────────────────┘                    │
│                                ▼                                             │
│                 ┌─────────────────────────────┐                              │
│                 │  Deterministic Risk Engine  │                              │
│                 └──────────────┬──────────────┘                              │
│                                │                                             │
│                                ▼                                             │
│                 ┌─────────────────────────────┐                              │
│                 │ Malware Diagnostics &       │                              │
│                 │ Decontamination Wizard      │                              │
│                 │ - Threat Attribution        │                              │
│                 │ - Payload Defanger          │                              │
│                 │ - Device Cleanup Checklist  │                              │
│                 │ - Takedown Report Generator │                              │
│                 └─────────────────────────────┘                              │
└────────────────────────────────▲─────────────────────────────────────────────┘
                                 │ HTTP POST /api/threat-intel
                                 │ HTTP POST /api/explain
                                 │ HTTP POST /api/ml-classify
┌────────────────────────────────▼─────────────────────────────────────────────┐
│                         EXPRESS BACKEND (server.ts)                          │
├──────────────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌──────────────────┐  │
│  │ /api/threat-intel     │  │ /api/explain          │  │ /api/ml-train    │  │
│  │ (Web Risk & URLhaus)  │  │ (Gemini 3.8 Flash)    │  │ (Trad & Chehab)  │  │
│  └───────────────────────┘  └───────────────────────┘  └──────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Key Implementation Modules

1. **Malware Diagnostics Engine (`src/lib/malwareAnalyzer.ts`)**:
   - Analyzes payload for malware delivery indicators (direct `.apk`, `.exe`, `.dmg` file downloads, rogue certificate profiles, fake Android update packages, intent schemes).
   - Maps observed patterns to threat classifications (e.g., Banking Trojan / Quishing Dropper, Credential Harvester, Subscription SMS Fraud, Wi-Fi Eavesdropping).
   - Generates educational breakdown answering *"What malware does this QR deliver?"*.

2. **Remediation & Decontamination Protocol (`src/lib/decontaminationGuide.ts`)**:
   - **Defanger**: Converts `http://evil.com/app.apk` into defanged `hxxp://evil[.]com/app[.]apk` and removes tracking query strings.
   - **Device Clean-up Guide**: Actionable checklists for Android (check `/sdcard/Download`, verify Play Protect, revoke Unknown Apps install permission) and iOS (remove unverified Configuration Profiles under Settings > General > VPN & Device Management).
   - **Abuse Reporting Tool**: Pre-fills one-click takedown submissions for Google Safe Browsing and URLhaus.

3. **Trad & Chehab Quishing ML Studio (`src/lib/quishingML.ts` & `src/components/MLStudioModal.tsx`)**:
   - Implements the feature extraction methodology from arXiv:2505.03451v2.
   - Computes structural pixel density, alignment pattern variance, timing pattern coherence, and lexical URL vectorization.
   - Visualizes the 69x69 QR pixel importance grid (matching Figure 2 & 3 of the paper).
   - Provides interactive model retraining and reports Accuracy, Precision, Recall, F1, and AUC.

4. **Expanded Threat Intelligence Integration (`server.ts`)**:
   - Integrates Google Web Risk test fixtures (`http://testsafebrowsing.appspot.com/s/malware.html`, `https://testsafebrowsing.appspot.com/s/phishing.html`).
   - Integrates offline URLhaus test feed indicators.
   - Provides honest diagnostic status without fabricated results.

5. **Research Dataset Index & Browser (`src/components/ResearchDatasetsModal.tsx`)**:
   - Directly displays the user's uploaded dataset metadata (`qr_examples_metadata_5cbbf10b.csv` & `dataset_sources_c78f76c1.csv`).
   - Links to CIC-Trap4Phish, Mendeley, and BanglaQR-Quish.
