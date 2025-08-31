# Deployment Plan for PII Detector

Where to place it:

-API Gateway (such as the Nginx/Envoy plugin) is the best option.
  -It processes all requests, allowing us to do a single scan at entry and egress.
  -Regex tests cost less than 5 milliseconds per payload.
  
-It is possible to use this as a sidecar container next to services for unstructured free-text, such as reviews and chats.
  -Fast regex is performed by the gateway; if it appears suspicious, it is sent to the sidecar for further investigation.

-Jobs in batches:
  -Simply run this script as a cronjob or insert it into Spark as a UDF for CSV/ETL pipelines.

Launch:
1.Start in "detect only" mode (log only, don't redact yet).
2.Turn on redaction for outgoing responses and logs once accuracy appears to be satisfactory.
3.Later, add BI pipelines and database exports.

Configuration:
-Regex/rules can be easily updated without redeploy by keeping them in a config file or ConfigMap.
-For monitoring, record the number of redactions for each service.

Trade-offs:
-The gateway layer is central and has low latency.
-Sidecar provides flexibility in case we use ML/NLP in the future.
-The same script can be reused by batch jobs, eliminating duplication.
