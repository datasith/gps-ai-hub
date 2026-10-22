# Customer Security Response — Workers' Compensation Agency (v2 Reworked)

## 1. Data Residency & CMEK Boundary
Gemini Enterprise enforces data residency (DRZ) and CMEK within the selected 'us' or 'eu' multi-region boundary.

## 2. Uploaded Claim PDF Handling
When Cloud SDP detects a configured InfoType such as an SSN during UploadSessionFile, Gemini Enterprise blocks the file upload before model inference.

## 3. Prompt Injection & Exfiltration Posture
Defense-in-depth controls—combining Model Armor (with failure_mode=FAIL_CLOSED configured by the customer administrator), Cloud SDP, and VPC Service Controls—mitigate prompt injection and data exfiltration risks.
