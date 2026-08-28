import re
from ..models import Finding
def analyze_terraform(p):
 t=p.get("content",""); fs=[]
 for pat,code,sev,pts,msg in [(r"0\.0\.0\.0/0","TF_PUBLIC_NETWORK","high",35,"Broad 0.0.0.0/0 network exposure."),(r"publicly_accessible\s*=\s*true","TF_PUBLIC_DATABASE","critical",50,"Public database accessibility enabled."),(r"encrypted\s*=\s*false","TF_UNENCRYPTED","high",30,"Encryption explicitly disabled."),(r'password\s*=\s*"[^"]+"',"TF_HARDCODED_SECRET","critical",50,"Hardcoded password detected.")]:
  if re.search(pat,t,re.I): fs.append(Finding(code=code,severity=sev,points=pts,message=msg,control="terraform"))
 return fs
