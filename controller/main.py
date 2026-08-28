import uuid
from fastapi import FastAPI,Depends
from sqlalchemy.orm import Session
from prometheus_client import generate_latest,CONTENT_TYPE_LATEST
from fastapi.responses import Response
from .auth import require_token
from .config import get_settings
from .db import init_db,get_db,save,recent
from .models import *
from .policies import PolicyEngine
from .risk import calculate_risk,decision_for
from .analyzers.kubernetes import analyze_kubernetes
from .analyzers.docker import analyze_docker
from .analyzers.terraform import analyze_terraform
s=get_settings(); app=FastAPI(title="Zero-Trust Infrastructure Controller",version="1.0.0",description="Policy-driven infrastructure security decision point."); engine=PolicyEngine()
@app.on_event("startup")
def startup(): init_db()
@app.get("/health")
def health(): return {"status":"ok","service":s.app_name,"version":"1.0.0"}
@app.get("/ready")
def ready(): return {"status":"ready"}
@app.get("/metrics")
def metrics(): return Response(generate_latest(),media_type=CONTENT_TYPE_LATEST)
@app.get("/api/v1/policies")
def policies(_=Depends(require_token)): return {"policies":engine.load()}
@app.post("/api/v1/analyze/kubernetes")
def kubernetes(payload:dict,_=Depends(require_token)): return {"findings":[x.model_dump() for x in analyze_kubernetes(payload)]}
@app.post("/api/v1/analyze/docker")
def docker(payload:dict,_=Depends(require_token)): return {"findings":[x.model_dump() for x in analyze_docker(payload)]}
@app.post("/api/v1/analyze/terraform")
def terraform(payload:dict,_=Depends(require_token)): return {"findings":[x.model_dump() for x in analyze_terraform(payload)]}
@app.post("/api/v1/evaluate",response_model=EvaluationResponse)
def evaluate(r:EvaluationRequest,db:Session=Depends(get_db),_=Depends(require_token)):
 fs=[]; names,pf=engine.evaluate(r); fs.extend(Finding(**x) for x in pf)
 if r.resource.type=="kubernetes": fs+=analyze_kubernetes(r.payload)
 elif r.resource.type=="docker": fs+=analyze_docker(r.payload)
 elif r.resource.type=="terraform": fs+=analyze_terraform(r.payload)
 if not r.device.encrypted: fs.append(Finding(code="DEVICE_UNENCRYPTED",severity="high",points=25,message="Device encryption is not verified.",control="device"))
 if not r.device.edr_enabled: fs.append(Finding(code="DEVICE_EDR_MISSING",severity="medium",points=15,message="EDR is not verified.",control="device"))
 if not r.device.patched: fs.append(Finding(code="DEVICE_UNPATCHED",severity="medium",points=15,message="Patch compliance is not verified.",control="device"))
 score=calculate_risk(fs,r.resource.environment,r.action); decision=decision_for(score,fs,r.resource.environment); rid="ztc-"+uuid.uuid4().hex[:16]
 ev=AuditEvent(request_id=rid,principal=r.principal.id,resource=r.resource.name,action=r.action,decision=decision,risk_score=score,findings=fs); save(db,ev)
 return EvaluationResponse(decision=decision,risk_score=score,findings=fs,policies=names,request_id=rid)
@app.get("/api/v1/audit")
def audit(limit:int=50,db:Session=Depends(get_db),_=Depends(require_token)): return {"events":[{"request_id":e.request_id,"principal":e.principal,"resource":e.resource,"action":e.action,"decision":e.decision,"risk_score":e.risk_score,"findings":e.findings,"timestamp":e.timestamp} for e in recent(db,limit)]}
