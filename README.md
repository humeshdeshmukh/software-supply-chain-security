# 🛡️ Obsidian Security: Software Supply Chain Control Cockpit (SLSA Level 4 Compliance)

> **Obsidian Security is a production-grade DevSecOps software supply chain security cockpit. It implements end-to-end provenance validation, container vulnerability intelligence, OIDC keyless signing, policy-driven admission controls, and real-time kernel-level runtime monitoring. Designed with a premium dark cyber theme, it serves as a central control plane to prevent, detect, and remediate supply chain compromises.**

[![Compliance](https://img.shields.io/badge/SLSA-Level%204%20Compliant-purple?style=for-the-badge)]()
[![Dashboard](https://img.shields.io/badge/Theme-Obsidian%20Dark%20Cyber-violet?style=for-the-badge)]()
[![Admission](https://img.shields.io/badge/Admission-Kyverno%20%7C%20OPA-blue?style=for-the-badge)]()
[![Audit](https://img.shields.io/badge/Audit-Dependency--Track%20%7C%20Falco-emerald?style=for-the-badge)]()

---

## 🖥️ Live Dashboard Preview

![Obsidian Cockpit Overview](assets/Screenshot%20From%202026-06-06%2018-25-01.png)

---

## 🏗️ Architecture & DevSecOps Lifecycle Graph

The cockpit monitors the software delivery lifecycle across three major phases: **Build-Time Verification (CI)**, **Admission Control Verification (Deploy)**, and **Kernel Runtime Auditing (Run)**.

```mermaid
graph TD
    %% Styling
    classDef build fill:#1e1b4b,stroke:#8b5cf6,stroke-width:2px,color:#fff;
    classDef deploy fill:#0f172a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef run fill:#06101e,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef storage fill:#18181b,stroke:#52525b,stroke-width:1px,color:#cbd5e1;

    %% Nodes
    A[Developer Commit] --> B(TruffleHog Scan)
    B -->|Passed| C[Chainguard/Wolfi Compiler]
    C --> D[Dependency Catalog Attestation]
    D --> E(Trivy & Grype Dual CVE Scan)
    E -->|Passed| F[Cosign OIDC Keyless Sign-off]
    F --> G[Upload SLSA Provenance]
    G --> H[(Harbor Secure Registry)]
    
    H --> I[Kyverno & OPA Webhook Gate]
    I -->|Valid Signature & Attestation| J[Production Pod Deployment]
    I -->|Bypassed / Unsigned| K[Workload Denied 403]
    
    J --> L[Falco Runtime Kernel Monitor]
    J --> M[Dependency-Track Live Audits]

    %% Applying Classes
    class A,B,C,D,E,F,G build;
    class I,J,K deploy;
    class L,M run;
    class H storage;
```

---

## 📊 Compliance Infographics (SLSA Level 1-4 Comparison)

| Control Standard | SLSA Level 1 | SLSA Level 2 | SLSA Level 3 | SLSA Level 4 | **Obsidian Security Enforcement** |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Scripted Builds** | ✔ | ✔ | ✔ | ✔ | **Stateless Wolfi/Chainguard build layers** |
| **Build Service** | ❌ | ✔ | ✔ | ✔ | **Hosted GitHub Actions Runner Environment** |
| **Signed Provenance** | ❌ | ✔ | ✔ | ✔ | **Cosign signing via short-lived OIDC claims** |
| **Security Scanning** | ❌ | ❌ | ✔ | ✔ | **Dual-pipeline Trivy & Grype vulnerability blocks** |
| **Secret Detection** | ❌ | ❌ | ❌ | ✔ | **Pre-compilation git delta scanner (TruffleHog)** |
| **Admission Gateways** | ❌ | ❌ | ❌ | ✔ | **Kyverno verifies Fulcio identity & Rekor ledger** |
| **Runtime Enforcement** | ❌ | ❌ | ❌ | ✔ | **Falco monitors runtime kernel filesystem drifts** |

---

## 🛠️ Security-as-Code Technical Stack

*   **Secrets Analysis:** [TruffleHog](https://github.com/trufflesecurity/trufflehog) scans SCM commit logs for high-entropy tokens.
*   **Vulnerability Intelligence:** Dual scanning utilizing [Trivy](https://aquasecurity.github.io/trivy/) & [Grype](https://github.com/anchore/grype) checks dependencies against the National Vulnerability Database (NVD).
*   **Base Layer security:** Wolfi / Chainguard distroless base image reduces baseline CVE footprint.
*   **Cryptographic Signatures:** [Cosign (Sigstore)](https://docs.sigstore.dev/cosign/overview/) executes OIDC keyless signing, logging proofs to the [Rekor Log](https://github.com/sigstore/rekor) public transparency ledger.
*   **Admission Controls:** [Kyverno](https://kyverno.io/) and OPA Gatekeeper validate provenance and signatures at deployment time.
*   **Threat Audit & Runtime Security:** [Falco](https://falco.org/) monitors active container namespaces for system-call anomalies, while [Dependency-Track](https://dependencytrack.org/) analyzes running packages.

---

## 🎮 Platform Features & Deep-Dive

### 1. Production Security Pipeline & Artifact Registry
Monitor compile-time logs, verify cryptographic signatures, and audit code credentials before build layers compile. Toggle **Simulate Risk Scenarios** (e.g., *Leak Plaintext Secret*, *Introduce Legacy Ubuntu Image*) to watch the compile gates abort the build.
*   **Visual Control Plane:**
    ![Pipeline & Build Registry](assets/Screenshot%20From%202026-06-06%2018-25-01.png)

### 2. Vulnerability Intelligence & Remediation Gateway
Allows real-time inspection of high-risk CVE advisories without exposing raw package list grids. Clicking **Remediate Security Advisories** triggers a simulated Git PR that automatically patches dependency tags, allowing subsequent builds to pass.
*   **Visual Control Plane:**
    ![Vulnerability Intel](assets/Screenshot%20From%202026-06-06%2018-25-14.png)

### 3. HashiCorp Vault KMS & Sigstore Ledger
View the cryptographic layout of keys configured inside Vault's transit encryption engine, and inspect public transparency ledger logs (Rekor) validating keyless OIDC identity claims.
*   **Visual Control Plane:**
    ![Vault KMS & Rekor Log](assets/Screenshot%20From%202026-06-06%2018-25-21.png)

### 4. Cryptographic Provenance Receipts
Inspect the sealed in-toto SLSA build provenance JSON record. This attestation contains compile parameters, git repository source commits, OIDC builders, and materials hashes required to verify the chain of trust.
*   **Visual Control Plane:**
    ![Provenance Attestations](assets/Screenshot%20From%202026-06-06%2018-25-34.png)

### 5. Production Admission Gateway (Kyverno & OPA)
A sandbox to apply deployment manifests. Workloads are intercepted by Kyverno webhooks (validating Cosign OIDC certificates) and OPA Gatekeeper policies (blocking root users and unapproved registries).
*   **Visual Control Plane:**
    ![Admission Controller Gates](assets/Screenshot%20From%202026-06-06%2018-25-38.png)

```mermaid
sequenceDiagram
    autonumber
    actor DevClient as Developer/GitOps
    participant K8s as Kubernetes API Server
    participant Webhook as Admission Controller (Kyverno/OPA)
    participant Harbor as Harbor OCI Registry
    participant Sigstore as Sigstore (Rekor/Fulcio)

    DevClient->>K8s: Apply deployment manifest (Image: v1.2.4)
    K8s->>Webhook: Validate Pod spec request
    Webhook->>Harbor: Fetch image signature metadata
    Webhook->>Sigstore: Verify cryptographic claims against Rekor ledger
    alt Claims Validated & Non-Root
        Sigstore-->>Webhook: Verified OK
        Webhook-->>K8s: Admitted (Create Pods)
        K8s-->>DevClient: Pod successfully deployed
    else Signature Bypassed or Privileged Root user
        Webhook-->>K8s: Rejection response (403 Forbidden)
        K8s-->>DevClient: Deployment blocked by policy webhooks
    end
```

### 6. Continuous Runtime Security & Audit Feed
Monitors system drift logs. Clicking **Simulate Runtime Audit Event** triggers an intrusion scenario (e.g. bash file-write below `/etc/cron.d/malicious`), prompting Falco's system call tracer to instantly flag the container's privilege escalation in real-time.
*   **Visual Control Plane:**
    ![Runtime Threat Audit](assets/Screenshot%20From%202026-06-06%2018-25-41.png)

### 7. Security-as-Code & GitOps Blueprints
Browse the source configurations powering the security lifecycle, including OPA Rego rules, Kyverno policy YAML declarations, secure pipeline workflows, and Vault Transit configuration policies.
*   **Visual Control Plane:**
    ![Security as Code Blueprints](assets/Screenshot%20From%202026-06-06%2018-25-49.png)

---

## 🚀 Quick Start & Deployment

### 📋 Prerequisites
- Linux / macOS environment
- Docker Engine & Daemon running
- Docker Compose installed and available in `$PATH`

### ⚙️ Bootstrap Platform
1.  Clone this repository:
    ```bash
    git clone <repository-url> && cd 13-software-supply-chain-security
    ```
2.  Start the control-plane container stack:
    ```bash
    ./start.sh
    ```
3.  Launch the secure interfaces:
    - **Obsidian Control Cockpit:** http://localhost:3000
    - **Backend FastAPI Docs:** http://localhost:8000/docs
    - **Backend Health Check:** http://localhost:8000/health

### 🛑 Tear Down Platform
```bash
./stop.sh
```
