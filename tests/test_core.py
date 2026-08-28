from controller.analyzers.kubernetes import analyze_kubernetes
from controller.analyzers.docker import analyze_docker
from controller.analyzers.terraform import analyze_terraform
from controller.models import Finding,Decision
from controller.risk import decision_for

def test_k8s_privileged(): assert any(x.code=="K8S_PRIVILEGED" for x in analyze_kubernetes({"kind":"Pod","spec":{"containers":[{"name":"x","securityContext":{"privileged":True}}]}}))
def test_docker(): assert any(x.code=="DOCKER_PRIVILEGED" for x in analyze_docker({"privileged":True}))
def test_tf(): assert any(x.code=="TF_PUBLIC_NETWORK" for x in analyze_terraform({"content":"cidr=\"0.0.0.0/0\""}))
def test_risk(): assert decision_for(90,[Finding(code="x",severity="high",points=90,message="x")],"development")==Decision.DENY
