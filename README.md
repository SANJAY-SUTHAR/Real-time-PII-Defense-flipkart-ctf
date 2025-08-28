# Deployment Plan for PII Detector

Where to put it:
- Best fit is API Gateway (e.g. Nginx/Envoy plugin).
  - All requests pass through it, so we can scan once at ingress/egress.
  - Regex checks are cheap (<5ms per payload).
- For unstructured free-text (like reviews, chats), could run this as a sidecar container next to services.
  - Gateway does fast regex → if it looks suspicious, hand it to sidecar for deeper check.

Batch jobs:
- For CSV/ETL pipelines, just call this script as a cronjob or plug into Spark as a UDF.

Rollout:
1. Start in "detect only" mode (don’t redact yet, just log).
2. Once accuracy looks good, turn on redaction for outbound responses/logs.
3. Later, extend to DB exports and BI pipelines.

Config:
- Keep regex/rules in a config file or ConfigMap → easy to update without redeploy.
- Log # of redactions per service for monitoring.

Trade-offs:
- Gateway layer is low-latency and central.
- Sidecar gives flexibility if we need ML/NLP later.
- Batch jobs can reuse the same script → no duplication.
