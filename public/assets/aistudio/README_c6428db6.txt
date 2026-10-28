# ScamTrace AI QR Research Starter Pack

## Contents
- `qr_examples/`: five generated QR images for safe scanner testing.
- `qr_examples_metadata.csv`: payload, category, and notes for each image.
- `dataset_sources.csv`: public research dataset and threat-intelligence source index.

## Important
This is a starter pack, not a complete copy of every public QR dataset. It does not contain the full CIC-Trap4Phish, Mendeley, BanglaQR-Quish, URLhaus, or PhishTank datasets. Those are linked in `dataset_sources.csv`; download them from their official pages and comply with their licenses/terms.

The sample QR codes include official security test fixtures, a reserved benign example domain, and synthetic `.example` patterns. The synthetic suspicious examples are NOT real malicious URLs and must NOT be labelled as verified malware/phishing. Do not open unknown URLs from third-party datasets.

## Recommended labels
Use labels such as:
- `verified_malicious_at_time_of_collection`
- `benign_known`
- `suspicious_heuristic_only`
- `unknown_or_unverified`
- `official_security_test_fixture`

Keep the source, timestamp, threat category, and evidence with every label. Do not use the image-only label as the sole truth; decode the QR and evaluate its payload too.

## Threat categories for ScamTrace
- phishing / credential theft
- malware-distribution URL
- unwanted-software URL
- redirect / shortened URL
- lookalike or homograph domain
- payment / UPI redirection
- phone, SMS, email or app-action payload
- benign / unknown / unsupported payload

## Safe evaluation
Decode images without opening destinations. Use an isolated test environment and reputable threat-reputation APIs. A "not found" result means no match was found by that provider; it does not prove safety.
