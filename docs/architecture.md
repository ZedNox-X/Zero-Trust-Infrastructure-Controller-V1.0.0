# Architecture

The controller is a policy decision point. It receives an operation, evaluates principal and device context, applies policy-as-code, runs an infrastructure-specific analyzer, calculates explainable risk, and emits an allow/audit/approval/deny decision plus an audit event.

Production integrations should use an enterprise IdP, OIDC/JWT, device posture service, SIEM, secrets manager and Kubernetes admission integration.
