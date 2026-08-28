from fastapi import Header,HTTPException
from .config import get_settings
def require_token(authorization:str|None=Header(default=None)):
 if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Missing bearer token")
 if authorization[7:].strip()!=get_settings().api_token: raise HTTPException(403,"Invalid bearer token")
 return True
