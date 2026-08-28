from pathlib import Path
import yaml
from .config import get_settings
class PolicyEngine:
 def __init__(self,directory=None): self.directory=Path(directory or get_settings().policy_dir)
 def load(self):
  out=[]
  if not self.directory.exists(): return out
  for p in sorted(self.directory.glob("*.yaml")):
   x=yaml.safe_load(p.read_text()) or {}
   if x.get("enabled",True): x["_file"]=p.name; out.append(x)
  return out
 def evaluate(self,r):
  names=[]; fs=[]
  for p in self.load():
   c=p.get("conditions",{}); env=c.get("environment")
   if env and env!=r.resource.environment: continue
   n=p.get("name",p["_file"]); names.append(n)
   if c.get("require_mfa") and not r.principal.mfa_verified: fs.append({"code":"POLICY_MFA_REQUIRED","severity":"high","points":35,"message":f"Policy '{n}' requires MFA.","control":"identity"})
   if c.get("trusted_device") and not r.device.trusted: fs.append({"code":"POLICY_UNTRUSTED_DEVICE","severity":"high","points":30,"message":f"Policy '{n}' requires a trusted device.","control":"device"})
   if c.get("require_approval") and r.action in {"deploy","terraform_apply","delete","scale"}: fs.append({"code":"POLICY_APPROVAL_REQUIRED","severity":"medium","points":25,"message":f"Policy '{n}' requires approval.","control":"change-management"})
  return names,fs
