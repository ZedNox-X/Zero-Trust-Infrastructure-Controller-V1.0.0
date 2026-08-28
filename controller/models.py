from datetime import datetime,timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel,Field
class Decision(str,Enum): ALLOW="ALLOW"; AUDIT="AUDIT"; APPROVAL="APPROVAL"; DENY="DENY"
class Principal(BaseModel): id:str; roles:list[str]=Field(default_factory=list); mfa_verified:bool=False
class Device(BaseModel): id:str; trusted:bool=False; encrypted:bool=False; edr_enabled:bool=False; patched:bool=False
class Resource(BaseModel): name:str; environment:str="development"; type:str="generic"
class EvaluationRequest(BaseModel): principal:Principal; device:Device; resource:Resource; action:str; payload:dict[str,Any]=Field(default_factory=dict)
class Finding(BaseModel): code:str; severity:str; points:int; message:str; control:str|None=None
class EvaluationResponse(BaseModel): decision:Decision; risk_score:int; findings:list[Finding]; policies:list[str]; request_id:str; evaluated_at:datetime=Field(default_factory=lambda:datetime.now(timezone.utc))
