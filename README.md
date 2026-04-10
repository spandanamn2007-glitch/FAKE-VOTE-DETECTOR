# Fake Vote Detector

A web-based project that detects suspicious voting activity using device fingerprinting and vote metadata.

This app is designed to help catch fake votes when voter IDs are unreliable by focusing on the device/browser fingerprint and IP behavior.

## Features

- Detects duplicate fingerprints (same device/browser voting multiple times)
- Flags fingerprints associated with different voter IDs
- Flags IP addresses with many votes
- Identifies multiple votes at the same timestamp
- Includes sample data and live analysis

## How to run

1. Open `index.html` in your browser to view the UI guide.
2. Open `app.html` in your browser to use the main vote analyzer.
3. Paste vote data in CSV format or click **Load Sample Data** in the app.
4. Click **Analyze Votes**.

## UI guide

- `index.html` is now the UI guide landing page.
- `app.html` is the main vote detection interface.

## CSV format

The expected header row is:

```
fingerprint,voter_id,candidate,ip_address,timestamp
```

Example record:

```
fp-01,1001,Alpha,192.168.1.10,2026-04-10T08:05:12Z
```

## Notes

This project uses fingerprinting to reduce the reliance on voter IDs, which can be faked. You can extend it by:

- adding file upload support
- using a backend to store vote logs
- generating fingerprints from browser metadata or device identifiers
- improving anomaly detection with machine learning
