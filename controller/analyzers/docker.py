from ..models import Finding
def analyze_docker(p):
 fs=[]
 if p.get("privileged"): fs.append(Finding(code="DOCKER_PRIVILEGED",severity="critical",points=50,message="Container requests privileged mode.",control="container"))
 if p.get("network_mode")=="host": fs.append(Finding(code="DOCKER_HOST_NETWORK",severity="high",points=30,message="Container uses host networking.",control="container"))
 if p.get("user") in (None,"","root","0"): fs.append(Finding(code="DOCKER_ROOT_USER",severity="high",points=25,message="Container does not explicitly run as non-root.",control="container"))
 if any("SECRET" in str(x).upper() or "PASSWORD" in str(x).upper() for x in p.get("environment",[])): fs.append(Finding(code="DOCKER_SECRET_ENV",severity="high",points=30,message="Potential secret exposed through environment configuration.",control="secrets"))
 if p.get("read_only") is not True: fs.append(Finding(code="DOCKER_WRITABLE_FS",severity="low",points=10,message="Container filesystem is not read-only.",control="container"))
 return fs
