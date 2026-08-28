from ..models import Finding
def analyze_kubernetes(p):
 fs=[]
 if p.get("kind") not in {"Pod","Deployment","StatefulSet","DaemonSet","Job","CronJob"}: return fs
 s=p.get("spec",{}); s=s.get("template",{}).get("spec",s); cs=s.get("containers",[])+s.get("initContainers",[])
 if s.get("hostNetwork"): fs.append(Finding(code="K8S_HOST_NETWORK",severity="high",points=30,message="Workload uses hostNetwork.",control="kubernetes"))
 for c in cs:
  n=c.get("name","unnamed"); sec=c.get("securityContext",{}); res=c.get("resources",{}); img=c.get("image","")
  if sec.get("privileged"): fs.append(Finding(code="K8S_PRIVILEGED",severity="critical",points=50,message=f"Container '{n}' is privileged.",control="kubernetes"))
  if sec.get("runAsNonRoot") is not True: fs.append(Finding(code="K8S_ROOT_EXECUTION",severity="high",points=25,message=f"Container '{n}' does not require non-root execution.",control="kubernetes"))
  if sec.get("allowPrivilegeEscalation") is not False: fs.append(Finding(code="K8S_PRIV_ESCALATION",severity="medium",points=15,message=f"Container '{n}' does not disable privilege escalation.",control="kubernetes"))
  if not img or "/" not in img: fs.append(Finding(code="K8S_UNTRUSTED_IMAGE",severity="medium",points=20,message=f"Container '{n}' does not use an approved private registry.",control="supply-chain"))
  if not res.get("limits") or not res.get("requests"): fs.append(Finding(code="K8S_RESOURCE_LIMITS",severity="low",points=10,message=f"Container '{n}' is missing resource requests/limits.",control="availability"))
 return fs
