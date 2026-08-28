from .models import Decision

def calculate_risk(findings,environment,action): return min(sum(f.points for f in findings)+(15 if environment=="production" else 0)+(10 if action in {"delete","terraform_apply"} else 0),100)
def decision_for(score,findings,environment):
 codes={f.code for f in findings}
 if any(f.severity=="critical" for f in findings) or score>=81: return Decision.DENY
 if environment=="production" and {"POLICY_MFA_REQUIRED","POLICY_UNTRUSTED_DEVICE"}&codes: return Decision.DENY
 if score>=51:return Decision.APPROVAL
 if score>=21:return Decision.AUDIT
 return Decision.ALLOW
