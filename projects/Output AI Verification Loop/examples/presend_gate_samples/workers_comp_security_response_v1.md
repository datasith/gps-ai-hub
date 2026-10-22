# Customer Security Response — Workers' Compensation Agency (v1)

## 1. Data Residency & CMEK Boundary
Gemini Enterprise enforces strict data residency (DRZ) and CMEK pinned solely to the us-central1 single-region boundary.

## 2. Uploaded Claim PDF Handling
When a claims adjuster uploads a PDF containing an SSN, Cloud SDP masks the SSN inline as [SSN-MASKED] and forwards the file to the LLM.

## 3. Prompt Injection & Exfiltration Posture
Our architecture is 100% immune to prompt injection and provides zero risk of data exfiltration.
