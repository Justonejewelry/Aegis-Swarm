# Runbook — Start an Authorized Engagement

1. Confirm written authorization and scope document.  
2. `POST /engagements` with `in_scope_*` and `out_of_scope`.  
3. Peer review scope with SOC lead.  
4. `POST /engagements/{id}/approve?approver=...`  
5. Dispatch discovery and monitoring tasks only.  
6. For purple/red validation modes, confirm `allowed_validation_actions`.  
7. Monitor `/health` and audit_log stream.  
8. On anomaly or scope breach: Mission Controller **abort**.  
9. Complete engagement; export executive + technical reports.  
10. File remediation tickets; schedule retest.
