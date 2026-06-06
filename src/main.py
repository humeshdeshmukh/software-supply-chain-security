import time
import uuid
from typing import List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Supply Chain Security Control API", version="1.0.0")

# Enable CORS for frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# Simulation State
# ==============================================================================

class PipelineStep(BaseModel):
    name: str
    status: str  # pending, running, success, failed, skipped
    logs: List[str]
    duration: float  # seconds

class BuildResult(BaseModel):
    id: str
    commit_sha: str
    version: str
    trigger: str
    timestamp: str
    status: str  # success, failed
    fail_reason: Optional[str] = None
    config: dict
    steps: List[PipelineStep]

# Prepopulate database state
builds_db: List[BuildResult] = []
rekor_ledger: List[dict] = []
dependency_track_sbom: List[dict] = []
deployed_pods: List[dict] = []
falco_alerts: List[dict] = []

# Initial mock data for active components
vault_keys = {
    "key_name": "cosign-key",
    "type": "ecdsa-p256",
    "created_time": "2026-06-05T10:12:00Z",
    "vault_path": "transit/keys/cosign-key",
    "status": "active",
    "public_key": (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2Z3lq4T0FzFv2TeeY3u4hP6NqYq3\n"
        "lP5n9N/2vWn1+H/Z12e/22aWn1eW2F2qYq3lP5n9N/2vWn1+H/Z12e/22aWn1eW\n"
        "-----END PUBLIC KEY-----"
    )
}

# Vulnerability DB
packages_vulnerabilities = [
    {"package": "openssl", "current_version": "1.1.1u-r0", "safe_version": "1.1.1w-r0", "severity": "Medium", "cve": "CVE-2023-3446"},
    {"package": "curl", "current_version": "7.88.1-r0", "safe_version": "8.4.0-r0", "severity": "Critical", "cve": "CVE-2023-38545"},
    {"package": "zlib1g", "current_version": "1:1.2.13.dfsg-1", "safe_version": "1:1.2.13.dfsg-1ubuntu1.2", "severity": "Low", "cve": "CVE-2023-45853"},
    {"package": "libc-bin", "current_version": "2.36-9", "safe_version": "2.36-9+deb12u3", "severity": "Critical", "cve": "CVE-2023-4911"}
]

# Base pipeline options
current_pipeline_config = {
    "fail_secret_scan": False,
    "use_heavy_base_image": False,
    "fail_cve_scan": False,
    "skip_signing": False,
    "skip_sbom": False,
    "run_as_root": False
}

# ==============================================================================
# Helper Methods to Generate Logs
# ==============================================================================

def generate_rekor_entry(image: str, signature: str, cert: str):
    entry = {
        "index": len(rekor_ledger) + 12489050,
        "uuid": str(uuid.uuid4()).replace("-", "")[:29],
        "image": image,
        "signature_hash": "sha256:" + signature[:20] + "...",
        "integrated_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "certificate_issuer": "https://token.actions.githubusercontent.com",
        "subject": "https://github.com/fintech-startup/api-service/.github/workflows/secure_pipeline.yml@refs/heads/main"
    }
    rekor_ledger.insert(0, entry)
    return entry

# Prepopulate a couple builds
def prepopulate_builds():
    build_id = "bld_" + str(uuid.uuid4())[:8]
    builds_db.append(BuildResult(
        id=build_id,
        commit_sha="a5b7c8d9e0f1",
        version="v1.2.3",
        trigger="merge request #45 by dev-security",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600)),
        status="success",
        config={
            "fail_secret_scan": False,
            "use_heavy_base_image": False,
            "fail_cve_scan": False,
            "skip_signing": False,
            "skip_sbom": False,
            "run_as_root": False
        },
        steps=[
            PipelineStep(name="TruffleHog Git Secret Scan", status="success", logs=["[trufflehog] Scanning repository...", "✓ No high entropy credentials or plain text keys found.", "✓ Codebase clean."], duration=1.2),
            PipelineStep(name="Docker Image Compile", status="success", logs=["[docker] Step 1/5: FROM cgr.dev/chainguard/wolfi-base", "[docker] Step 2/5: WORKDIR /app", "[docker] Step 3/5: COPY . .", "[docker] Step 4/5: RUN python -m pip install -r requirements.txt", "[docker] Step 5/5: USER 10001", "✓ Image built successfully: harbor.internal.fintech/finance/api-service:v1.2.3"], duration=3.5),
            PipelineStep(name="Syft SBOM Creation", status="success", logs=["[syft] Compiling package manifest...", "[syft] Identified 14 OS dependencies, 21 python packages.", "✓ CycloneDX SBOM generated."], duration=2.1),
            PipelineStep(name="Trivy & Grype Dual Vulnerability Check", status="success", logs=["[trivy] Scanning container image...", "✓ 0 Critical, 0 High vulnerabilities.", "[grype] Matching SBOM components against NVD...", "✓ No critical package vulnerabilities found."], duration=2.8),
            PipelineStep(name="Cosign OIDC Keyless Signing", status="success", logs=["[cosign] Retrieving OIDC identity token...", "[cosign] Authenticating with Sigstore Fulcio CA...", "[cosign] short-lived signing certificate generated.", "[rekor] Adding entry to Rekor public transparency log...", "✓ Signature pushed to harbor.internal.fintech/finance/api-service:v1.2.3.sig"], duration=3.0),
            PipelineStep(name="Provenance Upload", status="success", logs=["[cosign] Constructing in-toto build provenance...", "[cosign] Builder: GitHub Actions runner 2.4", "[cosign] Attesting SBOM metadata...", "✓ Provenance uploaded: harbor.internal.fintech/finance/api-service:v1.2.3.att"], duration=1.5)
        ]
    ))
    
    # Prepopulate deployed pod
    deployed_pods.append({
        "pod_name": "fintech-api-deployment-6fcf85c88b-k2l8x",
        "image": "harbor.internal.fintech/finance/api-service:v1.2.3",
        "status": "Running",
        "node": "k8s-node-2",
        "age": "55m",
        "signature_verified": True,
        "sbom_attached": True,
        "runtime_compliant": True
    })

    # Add initial Rekor log
    generate_rekor_entry(
        image="harbor.internal.fintech/finance/api-service:v1.2.3",
        signature="3045022100e47da2dfb6fcd92c019d...",
        cert="fulcio-cert-uuid-1248"
    )

    # Initial Dependency Track SBOM entries
    dependency_track_sbom.append({
        "project_name": "fintech-api-service",
        "project_version": "v1.2.3",
        "risk_score": 12,
        "total_components": 35,
        "vulnerabilities": {"critical": 0, "high": 1, "medium": 4, "low": 7},
        "last_scan": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600)),
        "status": "compliant"
    })

prepopulate_builds()

# ==============================================================================
# Pipeline Run Logic
# ==============================================================================

def execute_pipeline_in_background(build_id: str, config: dict):
    # Retrieve build
    build = next((b for b in builds_db if b.id == build_id), None)
    if not build:
        return

    # Step 1: TruffleHog Git Secrets Scan
    step1 = build.steps[0]
    step1.status = "running"
    step1.logs.append("⏳ Starting secret scanning...")
    time.sleep(0.5)
    
    if config["fail_secret_scan"]:
        step1.status = "failed"
        step1.logs.extend([
            "[trufflehog] Analysing Git commit history...",
            "❌ [CRITICAL] Secret Found in git history: config/secrets.yaml",
            "   └─ Type: HashiCorp Vault Token (plain-text)",
            "   └─ Value: s.7d98A2f1b4C9e01... (entropy: 65.4)",
            "   └─ Location: config/secrets.yaml:L15",
            "❌ Build aborted due to severe compliance vulnerability (Plain-text credentials in SCM)."
        ])
        build.status = "failed"
        build.fail_reason = "TruffleHog found hardcoded secret in Git commit history."
        return
    else:
        step1.status = "success"
        step1.logs.extend([
            "[trufflehog] Analysing Git commit history...",
            "✓ Checked 18 commits, 24 files.",
            "✓ No hardcoded private keys, OAuth credentials, or API tokens found.",
            "✓ TruffleHog secrets scanning: PASSED"
        ])
    
    # Step 2: Docker Image Compile
    step2 = build.steps[1]
    step2.status = "running"
    step2.logs.append("⏳ Initializing container builder context...")
    time.sleep(0.6)
    
    if config["use_heavy_base_image"]:
        step2.logs.extend([
            "[docker] Resolving base image 'ubuntu:20.04' from public registry...",
            "[docker] Step 1/5: FROM ubuntu:20.04",
            "[docker] Step 2/5: RUN apt-get update && apt-get install -y python3 python3-pip curl",
            "[docker] Step 3/5: COPY . /app",
            "[docker] Step 4/5: RUN pip install -r /app/requirements.txt",
            "⚠️  Warning: Container specifies running as 'root' default.",
            "✓ Image built successfully: harbor.internal.fintech/finance/api-service:" + build.version
        ])
        step2.status = "success"
    else:
        step2.logs.extend([
            "[docker] Resolving base image 'cgr.dev/chainguard/wolfi-base' from secure mirror...",
            "[docker] Step 1/5: FROM cgr.dev/chainguard/wolfi-base:latest",
            "[docker] Step 2/5: WORKDIR /app",
            "[docker] Step 3/5: COPY . .",
            "[docker] Step 4/5: RUN python -m pip install -r requirements.txt",
            "[docker] Step 5/5: USER 10001 (Ensuring non-root environment)",
            "✓ Image built successfully: harbor.internal.fintech/finance/api-service:" + build.version
        ])
        step2.status = "success"

    # Step 3: Syft SBOM Creation
    step3 = build.steps[2]
    step3.status = "running"
    step3.logs.append("⏳ Compiling Software Bill of Materials (SBOM)...")
    time.sleep(0.5)

    if config["skip_sbom"]:
        step3.status = "skipped"
        step3.logs.append("⚠️ SBOM attestation skipped per user configuration override.")
    else:
        step3.status = "success"
        if config["use_heavy_base_image"]:
            step3.logs.extend([
                "[syft] Cataloging container components...",
                "🧬 Cataloged 215 OS packages (dpkg) due to heavy Ubuntu base image.",
                "🧬 Cataloged 24 python libraries.",
                "✓ CycloneDX SBOM exported successfully to /tmp/sbom.json"
            ])
        else:
            step3.logs.extend([
                "[syft] Cataloging container components...",
                "🧬 Cataloged 12 OS packages (apk/wolfi-base) due to minimal distroless layout.",
                "🧬 Cataloged 18 python libraries.",
                "✓ CycloneDX SBOM exported successfully to /tmp/sbom.json"
            ])

    # Step 4: Trivy & Grype Dual Vulnerability Check
    step4 = build.steps[3]
    step4.status = "running"
    step4.logs.append("⏳ Querying package registries for vulnerabilities...")
    time.sleep(0.8)

    if config["fail_cve_scan"] or (config["use_heavy_base_image"] and not config["fail_secret_scan"]):
        step4.status = "failed"
        if config["use_heavy_base_image"]:
            step4.logs.extend([
                "[trivy] Scanning image harbor.internal.fintech/finance/api-service:" + build.version,
                "❌ [HIGH] openssl-1.1.1u-r0: CVE-2023-3446 (Medium severity)",
                "❌ [CRITICAL] curl-7.88.1-r0: CVE-2023-38545 (SOCKS5 heap buffer overflow - CRITICAL)",
                "❌ [CRITICAL] libc-bin-2.36-9: CVE-2023-4911 (Looney Tunables Glibc escalation - CRITICAL)",
                "[grype] Double-checking SBOM elements...",
                "❌ Grype audit failed: Found 2 CRITICAL and 1 HIGH vulnerabilities in Ubuntu dependency tree.",
                "❌ Compliance Failure: SLSA policy requires zero CRITICAL vulnerabilities."
            ])
        else:
            step4.logs.extend([
                "[trivy] Scanning image harbor.internal.fintech/finance/api-service:" + build.version,
                "❌ [CRITICAL] curl-7.88.1-r0: CVE-2023-38545 (SOCKS5 heap buffer overflow - CRITICAL)",
                "❌ Grype audit failed: Found 1 CRITICAL vulnerability in 'curl' package.",
                "❌ Compliance Failure: SLSA policy requires zero CRITICAL vulnerabilities."
            ])
        build.status = "failed"
        build.fail_reason = "Dual Vulnerability Scanner identified critical CVE-2023-38545."
        return
    else:
        step4.status = "success"
        step4.logs.extend([
            "[trivy] Scanning image harbor.internal.fintech/finance/api-service:" + build.version,
            "✓ Trivy: Found 0 Critical, 0 High, 2 Medium vulnerabilities.",
            "[grype] Auditing CycloneDX SBOM list...",
            "✓ Grype: Matches verified.",
            "✓ Compliance check passed: 0 Critical package CVEs in runtime context."
        ])

    # Step 5: Cosign OIDC Keyless Signing
    step5 = build.steps[4]
    step5.status = "running"
    step5.logs.append("⏳ Acquiring Sigstore credential tokens...")
    time.sleep(0.7)

    if config["skip_signing"]:
        step5.status = "skipped"
        step5.logs.append("⚠️ Image cryptographic signing skipped per user request.")
    else:
        sig = str(uuid.uuid4()).replace("-", "") * 2
        cert_id = "cert_" + str(uuid.uuid4())[:8]
        step5.status = "success"
        step5.logs.extend([
            "[cosign] Authenticating OIDC credentials...",
            "🔑 Identity token validated: https://token.actions.githubusercontent.com",
            "[cosign] Requesting signing certificate from Sigstore Fulcio...",
            "✓ Certificate generated for subject: https://github.com/fintech-startup/api-service",
            "[cosign] Uploading cryptographic proof to Rekor public transparency ledger...",
            "✓ Registered entry in public audit log."
        ])
        generate_rekor_entry(
            image=f"harbor.internal.fintech/finance/api-service:{build.version}",
            signature=sig,
            cert=cert_id
        )

    # Step 6: Provenance Upload
    step6 = build.steps[5]
    step6.status = "running"
    step6.logs.append("⏳ Packaging build attestation payload...")
    time.sleep(0.4)

    if config["skip_sbom"] or config["skip_signing"]:
        step6.status = "skipped"
        step6.logs.append("⚠️ Attestation process skipped because signing or SBOM steps were bypassed.")
    else:
        step6.status = "success"
        step6.logs.extend([
            "[cosign] Building in-toto provenance (v0.2 predicate)...",
            "🧬 Source Repository: github.com/fintech-startup/api-service",
            f"🧬 Commit Hash: {build.commit_sha}",
            "🧬 Builder Endpoint: https://token.actions.githubusercontent.com",
            "[cosign] Signing build provenance statement using Vault Transit KMS...",
            "✓ Attestation metadata successfully pushed to Harbor OCI Registry."
        ])
        
        # Add dependency track metadata
        dependency_track_sbom.insert(0, {
            "project_name": "fintech-api-service",
            "project_version": build.version,
            "risk_score": 0,
            "total_components": 30,
            "vulnerabilities": {"critical": 0, "high": 0, "medium": 2, "low": 5},
            "last_scan": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "compliant"
        })

    # Complete Build
    build.status = "success"

# ==============================================================================
# REST Controllers
# ==============================================================================

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": time.time()}

class StartBuildRequest(BaseModel):
    fail_secret_scan: bool
    use_heavy_base_image: bool
    fail_cve_scan: bool
    skip_signing: bool
    skip_sbom: bool
    run_as_root: bool
    version: Optional[str] = "v1.2.4"

@app.post("/api/pipeline/run")
def run_pipeline(req: StartBuildRequest, background_tasks: BackgroundTasks):
    global current_pipeline_config
    
    # Store settings
    current_pipeline_config = {
        "fail_secret_scan": req.fail_secret_scan,
        "use_heavy_base_image": req.use_heavy_base_image,
        "fail_cve_scan": req.fail_cve_scan,
        "skip_signing": req.skip_signing,
        "skip_sbom": req.skip_sbom,
        "run_as_root": req.run_as_root
    }

    # Generate version or increment
    version_str = req.version
    commit_sha = str(uuid.uuid4()).replace("-", "")[:12]
    build_id = "bld_" + str(uuid.uuid4())[:8]

    # Create empty build steps
    steps = [
        PipelineStep(name="TruffleHog Git Secret Scan", status="pending", logs=[], duration=0.8),
        PipelineStep(name="Docker Image Compile", status="pending", logs=[], duration=2.1),
        PipelineStep(name="Syft SBOM Creation", status="pending", logs=[], duration=1.2),
        PipelineStep(name="Trivy & Grype Dual Vulnerability Check", status="pending", logs=[], duration=1.8),
        PipelineStep(name="Cosign OIDC Keyless Signing", status="pending", logs=[], duration=2.2),
        PipelineStep(name="Provenance Upload", status="pending", logs=[], duration=1.0)
    ]

    new_build = BuildResult(
        id=build_id,
        commit_sha=commit_sha,
        version=version_str,
        trigger="Web Dashboard Manual Run",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        status="running",
        config=current_pipeline_config,
        steps=steps
    )

    builds_db.insert(0, new_build)
    
    # Trigger background compilation
    background_tasks.add_task(execute_pipeline_in_background, build_id, current_pipeline_config)
    
    return {"build_id": build_id, "status": "started"}

@app.get("/api/pipeline/history")
def get_pipeline_history():
    return builds_db

@app.post("/api/pipeline/patch")
def patch_vulnerabilities():
    global current_pipeline_config
    # Toggle configurations to safe defaults
    current_pipeline_config["fail_secret_scan"] = False
    current_pipeline_config["use_heavy_base_image"] = False
    current_pipeline_config["fail_cve_scan"] = False
    current_pipeline_config["run_as_root"] = False
    
    # Return mock pull request patch detail
    return {
        "status": "patched",
        "pull_request": "PR #46 created and merged in repository.",
        "changes": [
            "Modified Dockerfile: Bumped FROM ubuntu:20.04 to cgr.dev/chainguard/wolfi-base:latest",
            "Modified requirements.txt: Bumped pyOpenSSL from 22.0.0 to 24.1.0",
            "Added USER 10001 inside Dockerfile context to ensure non-root container profiles.",
            "Rotated leaked Vault Token and updated .github/workflows to fetch credentials via OIDC token."
        ]
    }

class DeployRequest(BaseModel):
    image: str
    run_as_root: bool

@app.post("/api/k8s/deploy")
def k8s_deploy(req: DeployRequest):
    # Admission Controller simulation logic
    image_tag = req.image.split(":")[-1] if ":" in req.image else "latest"
    
    # Look up build corresponding to this version/tag in builds_db
    matching_build = next((b for b in builds_db if b.version == image_tag), None)
    
    # Logs list
    admission_logs = [
        "⚓ Intercepting pod deployment request via Admission Controller Webhook...",
        f"⚓ Request object: pod name: fintech-api, image: {req.image}"
    ]

    # Rule 1: OPA Gatekeeper Checks
    admission_logs.append("🛡️ Evaluated OPA Gatekeeper policy rules (Rego):")
    
    # Base Image check
    is_approved = any(keyword in req.image for keyword in ["cgr.dev/", "wolfi", "harbor.internal.fintech/"])
    if not is_approved:
        admission_logs.append("❌ OPA Gatekeeper Blocked: Base image is not secure (must use Wolfi or Chainguard distroless).")
        return {
            "status": "Denied",
            "code": 403,
            "policy": "OPA Gatekeeper",
            "logs": admission_logs,
            "reason": f"Admission Controller Denied: Image '{req.image}' does not use approved minimal base registry (cgr.dev/chainguard)."
        }
    else:
        admission_logs.append("✓ OPA Gatekeeper: Distroless Base Image Approved.")

    # Privilege constraint check
    if req.run_as_root:
        admission_logs.append("❌ OPA Gatekeeper Blocked: Container 'api-service' running as root user.")
        return {
            "status": "Denied",
            "code": 403,
            "policy": "OPA Gatekeeper",
            "logs": admission_logs,
            "reason": "Admission Controller Denied: Containers must run as non-root (SecurityContext.runAsNonRoot must be true)."
        }
    else:
        admission_logs.append("✓ OPA Gatekeeper: Non-Root Security Context Approved.")

    # Rule 2: Kyverno Checks
    admission_logs.append("☸️ Evaluating Kyverno signature policies:")
    
    # If we have a matching build, let's look at its config
    if matching_build:
        cfg = matching_build.config
        
        # Check Signature Verification
        if cfg["skip_signing"]:
            admission_logs.append("❌ Kyverno signature check failed: Image is not cryptographically signed.")
            return {
                "status": "Denied",
                "code": 403,
                "policy": "Kyverno (verify-image-signatures)",
                "logs": admission_logs,
                "reason": "Admission Controller Denied: image signature verification failed (No signature available)."
            }
        else:
            admission_logs.append("✓ Kyverno: Cryptographic signature verification succeeded (OIDC certificate match).")
            
        # Check SBOM
        if cfg["skip_sbom"]:
            admission_logs.append("❌ Kyverno SBOM check failed: Missing CycloneDX SBOM attestation.")
            return {
                "status": "Denied",
                "code": 403,
                "policy": "Kyverno (require-image-sbom)",
                "logs": admission_logs,
                "reason": "Admission Controller Denied: Image requires verified in-toto CycloneDX SBOM attestation."
            }
        else:
            admission_logs.append("✓ Kyverno: CycloneDX SBOM attestation verified successfully.")
            
        # Check CVEs
        if cfg["fail_cve_scan"]:
            admission_logs.append("❌ Kyverno CVE policy failed: Image contains critical vulnerabilities.")
            return {
                "status": "Denied",
                "code": 403,
                "policy": "Kyverno (zero-critical-cve-policy)",
                "logs": admission_logs,
                "reason": "Admission Controller Denied: Policy restricts images with Critical CVEs from running."
            }
    else:
        # Default fallback for images not built through our pipeline
        admission_logs.append("❌ Kyverno verification failed: Image metadata not found in pipeline database.")
        return {
            "status": "Denied",
            "code": 403,
            "policy": "Kyverno (trust-pipeline-origin)",
            "logs": admission_logs,
            "reason": "Admission Controller Denied: Pod image is untrusted. Origin signature missing."
        }

    # If passes all, deploy!
    admission_logs.append("✓ Webhook Verification Complete. Request admitted to API Server.")
    admission_logs.append("🚀 Creating pods in namespace 'production'...")
    
    new_pod = {
        "pod_name": f"fintech-api-deployment-{str(uuid.uuid4())[:8]}-x23rf",
        "image": req.image,
        "status": "Running",
        "node": "k8s-node-1",
        "age": "1s",
        "signature_verified": True,
        "sbom_attached": True,
        "runtime_compliant": True
    }
    
    # Limit deployed pods in UI
    deployed_pods.insert(0, new_pod)
    if len(deployed_pods) > 6:
        deployed_pods.pop()

    return {
        "status": "Approved",
        "code": 200,
        "logs": admission_logs,
        "pod": new_pod
    }

@app.get("/api/k8s/pods")
def get_pods():
    return deployed_pods

@app.post("/api/k8s/pods/clear")
def clear_pods():
    global deployed_pods
    deployed_pods = []
    return {"status": "cleared"}

@app.get("/api/rekor/ledger")
def get_rekor_ledger():
    return rekor_ledger

@app.get("/api/vault/keys")
def get_vault_keys():
    return vault_keys

@app.get("/api/deptrack/metrics")
def get_deptrack_metrics():
    return dependency_track_sbom

@app.post("/api/falco/simulate")
def simulate_falco_alert():
    # Insert a new runtime drift event
    alert = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rule": "Write below monitored dir",
        "priority": "Critical",
        "output": (
            f"Falco Alert: File was written below monitored directory (user=root "
            f"parent=nginx pcmdline=bash -c 'echo malware > /etc/cron.d/malicious' "
            f"file=/etc/cron.d/malicious container_id={str(uuid.uuid4())[:12]} "
            f"image=harbor.internal.fintech/finance/api-service:v1.2.3)"
        )
    }
    falco_alerts.insert(0, alert)
    if len(falco_alerts) > 10:
        falco_alerts.pop()
    return alert

@app.get("/api/falco/logs")
def get_falco_logs():
    # Return active runtime drift logs
    if not falco_alerts:
        return [{
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rule": "System State Compliance",
            "priority": "Informational",
            "output": "Falco: Monitoring pods. No drift or security compliance anomalies detected in namespace 'production'."
        }]
    return falco_alerts

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
