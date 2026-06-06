import React, { useState, useEffect, useRef } from 'react'

export default function App() {
  // Navigation
  const [activeTab, setActiveTab] = useState('overview')

  // Pipeline Config States (Mapped to real-life policy configurations)
  const [failSecretScan, setFailSecretScan] = useState(false) // Permit credentials leak
  const [useHeavyBaseImage, setUseHeavyBaseImage] = useState(false) // Allow heavy unapproved base layers
  const [failCveScan, setFailCveScan] = useState(false) // Allow critical package CVEs
  const [skipSigning, setSkipSigning] = useState(false) // Disable container signing
  const [runAsRoot, setRunAsRoot] = useState(false) // Permit privileged root container execution

  // Pipeline Execution / Running State
  const [runningBuild, setRunningBuild] = useState(null)
  const [terminalLogs, setTerminalLogs] = useState([
    "💡 System online. Connection established to Secure OIDC pipeline runners.",
    "💡 Enforce active policy guardrails on the left, then click 'Trigger Production Build & Scan'."
  ])
  const [activeStepIndex, setActiveStepIndex] = useState(-1)
  const [pipelineSteps, setPipelineSteps] = useState([
    { name: "Secret Verification (TruffleHog)", status: "pending", desc: "Pre-build credentials & entropy scan" },
    { name: "Secure Image Compilation (Chainguard)", status: "pending", desc: "Stateless container image compilation" },
    { name: "Dependency Attestation", status: "pending", desc: "CycloneDX package listings and metadata compilation" },
    { name: "Double-Vulnerability Audit (Trivy & Grype)", status: "pending", desc: "Package dependency vulnerabilities checks" },
    { name: "Sigstore Cryptographic Sign-off", status: "pending", desc: "Cryptographic signing using Fulcio OIDC certificates" },
    { name: "SLSA Provenance Attestation", status: "pending", desc: "in-toto SLSA provenance metadata attestation" }
  ])

  // Data Feeds (Synced with FastAPI Backend)
  const [buildHistory, setBuildHistory] = useState([])
  const [deployedPods, setDeployedPods] = useState([])
  const [rekorLedger, setRekorLedger] = useState([])
  const [vaultKeys, setVaultKeys] = useState(null)
  const [deptrackMetrics, setDeptrackMetrics] = useState([])
  const [falcoLogs, setFalcoLogs] = useState([])
  
  // Custom interactive playground inputs
  const [playImage, setPlayImage] = useState('harbor.internal.fintech/finance/api-service:v1.2.4')
  const [playRoot, setPlayRoot] = useState(false)
  const [playLogs, setPlayLogs] = useState([])
  const [playResult, setPlayResult] = useState(null)

  // Patching states
  const [patchStatus, setPatchStatus] = useState(null)

  // Reference for auto-scrolling terminal logs
  const terminalEndRef = useRef(null)

  useEffect(() => {
    fetchInitialData()
    // Poll updates every 5 seconds
    const interval = setInterval(() => {
      pollData()
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [terminalLogs])

  const fetchInitialData = async () => {
    try {
      const hRes = await fetch('/api/pipeline/history')
      const hData = await hRes.json()
      setBuildHistory(hData)

      const pRes = await fetch('/api/k8s/pods')
      const pData = await pRes.json()
      setDeployedPods(pData)

      const rRes = await fetch('/api/rekor/ledger')
      const rData = await rRes.json()
      setRekorLedger(rData)

      const vRes = await fetch('/api/vault/keys')
      const vData = await vRes.json()
      setVaultKeys(vData)

      const dRes = await fetch('/api/deptrack/metrics')
      const dData = await dRes.json()
      setDeptrackMetrics(dData)

      const fRes = await fetch('/api/falco/logs')
      const fData = await fRes.json()
      setFalcoLogs(fData)
    } catch (err) {
      console.error("Error fetching initial database configurations:", err)
    }
  }

  const pollData = async () => {
    try {
      const hRes = await fetch('/api/pipeline/history')
      const hData = await hRes.json()
      setBuildHistory(hData)

      const pRes = await fetch('/api/k8s/pods')
      const pData = await pRes.json()
      setDeployedPods(pData)

      const rRes = await fetch('/api/rekor/ledger')
      const rData = await rRes.json()
      setRekorLedger(rData)

      const dRes = await fetch('/api/deptrack/metrics')
      const dData = await dRes.json()
      setDeptrackMetrics(dData)

      const fRes = await fetch('/api/falco/logs')
      const fData = await fRes.json()
      setFalcoLogs(fData)
    } catch (err) {
      console.log("Polling error:", err)
    }
  }

  // ==============================================================================
  // CI/CD Simulator Execution
  // ==============================================================================
  const handleRunPipeline = async () => {
    setRunningBuild("running")
    setPatchStatus(null)
    setTerminalLogs([
      `🚀 [GITOPS] Triggered production artifact build run for tag ${playImage.split(':')[1] || 'v1.2.4'}`,
      `🚀 [GITOPS] Commit SHA target: sha256:${Math.random().toString(16).substring(2, 14)}`,
      `🚀 [GITOPS] Build Host: Ephemeral runner instance (OIDC Verified SLSA L4 Configuration)`
    ])
    setActiveStepIndex(0)

    // Reset steps UI to pending
    setPipelineSteps(prev => prev.map(s => ({ ...s, status: "pending" })))

    try {
      const res = await fetch('/api/pipeline/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fail_secret_scan: failSecretScan,
          use_heavy_base_image: useHeavyBaseImage,
          fail_cve_scan: failCveScan,
          skip_signing: skipSigning,
          skip_sbom: false, // Hardcoded so SBOM is compiled but not visible in the UI
          run_as_root: runAsRoot,
          version: playImage.split(':')[1] || 'v1.2.4'
        })
      })
      const data = await res.json()
      
      // Simulate step progression inside React for real-time visualization
      simulateStepProgression(data.build_id)
    } catch (err) {
      console.error(err)
      setRunningBuild("failed")
      setTerminalLogs(prev => [...prev, "❌ Connection to pipeline compiler agent severed."])
    }
  }

  const simulateStepProgression = (buildId) => {
    let currentStep = 0
    
    const runNextStep = () => {
      if (currentStep >= 6) {
        setRunningBuild("success")
        setTerminalLogs(prev => [...prev, "✓ [GITOPS] Compliance verification checks successfully passed.", "🚀 Artifact and signatures published to production registry."])
        fetchInitialData()
        return
      }

      setActiveStepIndex(currentStep)
      setPipelineSteps(prev => {
        const next = [...prev]
        next[currentStep].status = "running"
        return next
      })

      // Select log lines to stream
      let stepLogs = []
      let stepSuccess = true

      switch (currentStep) {
        case 0:
          stepLogs = [
            "⚡ [trufflehog] Pre-build Secrets Scan activated.",
            "[trufflehog] Loading repository git commit delta tree...",
            "[trufflehog] Scanning files with entropy classifiers..."
          ]
          if (failSecretScan) {
            stepLogs.push(
              "❌ [CRITICAL SECRETS FOUND] HashiCorp Vault Token plain-text credentials leak.",
              "   └─ Location: config/secrets.yaml:L15",
              "❌ Policy Guardrail Exception: Git Secret check failed. Aborting compilation."
            )
            stepSuccess = false
          } else {
            stepLogs.push(
              "✓ No plaintext credentials, private keys, or API tokens found.",
              "✓ Secret scanner compliance verified."
            )
          }
          break;
        case 1:
          stepLogs = [
            "⚡ [compiler] Secure image compilation started.",
            useHeavyBaseImage 
              ? "[compiler] Base image selection: ubuntu:20.04 (Heavy base overlay)" 
              : "[compiler] Base image selection: cgr.dev/chainguard/wolfi-base:latest (Secure distroless base)",
            "[compiler] Loading runtime dependency libraries...",
            "[compiler] Building workspace layer cache...",
            useHeavyBaseImage 
              ? "⚠️  Security Warning: Base layer contains default root user settings." 
              : "[compiler] Forcing non-privileged user space (UID 10001)",
            `✓ Image compile succeeded: harbor.internal.fintech/finance/api-service:${playImage.split(':')[1] || 'v1.2.4'}`
          ]
          break;
        case 2:
          stepLogs = [
            "⚡ [attestation-compiler] Compiling container package signature profiles...",
            useHeavyBaseImage 
              ? "[attestation-compiler] Generating metadata layers for standard system packages..." 
              : "[attestation-compiler] Generating metadata layers for minimal secure packages...",
            "[attestation-compiler] Sealing attestation profiles...",
            "✓ Dependency attestation compiled successfully."
          ]
          break;
        case 3:
          stepLogs = [
            "⚡ [vulnerability-scanner] Querying vulnerability intelligence databases...",
            "[vulnerability-scanner] Cross-referencing catalog inventory against CVE databases..."
          ]
          if (failCveScan || useHeavyBaseImage) {
            if (useHeavyBaseImage) {
              stepLogs.push(
                "❌ [CRITICAL] curl-7.88.1-r0: CVE-2023-38545 (SOCKS5 Heap Buffer Overflow)",
                "❌ [CRITICAL] libc-bin-2.36-9: CVE-2023-4911 (Glibc Tunables Privilege Escalation)",
                "❌ [HIGH] openssl-1.1.1u-r0: CVE-2023-3446 (DH Key Negotiation)",
                "❌ vulnerability-scanner: Critical packages violating gate standards. Threshold required: zero critical CVEs."
              )
            } else {
              stepLogs.push(
                "❌ [CRITICAL] curl-7.88.1-r0: CVE-2023-38545 (SOCKS5 Heap Buffer Overflow)",
                "❌ vulnerability-scanner: Critical package detected. Scan failed."
              )
            }
            stepSuccess = false
          } else {
            stepLogs.push(
              "✓ Compliance Gate Passed: 0 Critical, 0 High vulnerabilities.",
              "✓ Active dependencies matched compliant security threshold."
            )
          }
          break;
        case 4:
          if (skipSigning) {
            stepLogs = [
              "⚠️ [cosign] Cryptographic signing bypassed by policy overrides."
            ]
          } else {
            stepLogs = [
              "⚡ [cosign] Retrieving ephemeral signing credential token via OIDC...",
              "🔑 GitHub OIDC token verified: https://token.actions.githubusercontent.com",
              "[cosign] fulcio: Issuing short-lived signature certificate...",
              "[rekor] Uploading entry to public transparency log ledger...",
              "✓ Cryptographic signature integrated successfully into Sigstore ledger."
            ]
          }
          break;
        case 5:
          if (skipSigning) {
            stepLogs = [
              "⚠️ [cosign] Attestation packaging aborted: Cryptographic signatures are disabled."
            ]
          } else {
            stepLogs = [
              "⚡ [cosign] Generating in-toto build provenance statement...",
              "🧬 Builder: https://token.actions.githubusercontent.com",
              "🧬 Source Git: github.com/fintech-startup/api-service",
              "[cosign] Sealing attestation using Vault Transit Key engine...",
              "✓ SLSA Provenance attestation successfully pushed to Harbor OCI registry."
            ]
          }
          break;
      }

      setTerminalLogs(prev => [...prev, ...stepLogs])
      
      setTimeout(() => {
        setPipelineSteps(prev => {
          const next = [...prev]
          next[currentStep].status = stepSuccess ? "success" : "failed"
          return next
        })

        if (!stepSuccess) {
          setRunningBuild("failed")
          setTerminalLogs(prev => {
            const lastLog = prev[prev.length - 1] || "";
            const cleanLog = lastLog.replace(/^❌\s*/, "");
            return [...prev, `❌ [GITOPS] Compilation failed: ${cleanLog}`];
          })
          fetchInitialData()
        } else {
          currentStep++
          runNextStep()
        }
      }, 1500)
    }

    runNextStep()
  }

  // ==============================================================================
  // Vulnerability Patching Automation
  // ==============================================================================
  const handleAutoPatch = async () => {
    try {
      const res = await fetch('/api/pipeline/patch', { method: 'POST' })
      const data = await res.json()
      setPatchStatus(data)
      // Resolve states locally
      setFailSecretScan(false)
      setUseHeavyBaseImage(false)
      setFailCveScan(false)
      setRunAsRoot(false)
    } catch (err) {
      console.error(err)
    }
  }

  // ==============================================================================
  // Admission Gate (Kyverno & Gatekeeper Playground)
  // ==============================================================================
  const handleTestDeployment = async () => {
    setPlayLogs(["⏳ Contacting Kubernetes API Server...", "⚓ Forwarding request to Admission Controller Webhooks..."])
    setPlayResult(null)
    
    try {
      const res = await fetch('/api/k8s/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          image: playImage,
          run_as_root: playRoot
        })
      })
      const data = await res.json()
      
      setTimeout(() => {
        setPlayLogs(data.logs)
        setPlayResult(data)
        pollData()
      }, 1200)
    } catch (err) {
      setPlayLogs(prev => [...prev, "❌ Failed to reach admission webhooks."])
    }
  }

  // ==============================================================================
  // Continuous Audit Interactions
  // ==============================================================================
  const handleTriggerFalcoDrift = async () => {
    try {
      const res = await fetch('/api/falco/simulate', { method: 'POST' })
      const data = await res.json()
      // Refresh Falco list
      const fRes = await fetch('/api/falco/logs')
      const fData = await fRes.json()
      setFalcoLogs(fData)
    } catch (err) {
      console.error(err)
    }
  }

  // Helper properties
  const activeOverridesCount = [failSecretScan, useHeavyBaseImage, failCveScan, skipSigning, runAsRoot].filter(Boolean).length
  const hasVulnerabilitiesActive = useHeavyBaseImage || failCveScan

  // Static package descriptions for vulnerability logs
  const packages_vulnerabilities = [
    { package: "openssl", current_version: "1.1.1u-r0", safe_version: "1.1.1w-r0", severity: "Medium", cve: "CVE-2023-3446" },
    { package: "curl", current_version: "7.88.1-r0", safe_version: "8.4.0-r0", severity: "Critical", cve: "CVE-2023-38545" },
    { package: "libc-bin", current_version: "2.36-9", safe_version: "2.36-9+deb12u3", severity: "Critical", cve: "CVE-2023-4911" }
  ]

  return (
    <div className="app-shell">
      {/* ── Left Sidebar Navigation ── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-logo">🛡️</div>
          <div>
            <h1 className="sidebar-name">Obsidian Security</h1>
            <p className="sidebar-sub">DevSecOps Control Panel</p>
          </div>
        </div>

        <div className="sidebar-status-box">
          <div className="sidebar-status-header">
            <span>Production Cluster</span>
            <span className="badge success">Active</span>
          </div>
          <div className="sidebar-status-indicator">
            <span className="pulse-dot"></span>
            <span>Gateway: Connected</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <button className={`sidebar-nav-item ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
            <span>📊</span> Pipeline & Builds
          </button>
          <button className={`sidebar-nav-item ${activeTab === 'cves' ? 'active' : ''}`} onClick={() => setActiveTab('cves')}>
            <span>🛡️</span> Vulnerability Intel
          </button>
          <button className={`sidebar-nav-item ${activeTab === 'vault' ? 'active' : ''}`} onClick={() => setActiveTab('vault')}>
            <span>🔑</span> KMS & Ledger
          </button>
          <button className={`sidebar-nav-item ${activeTab === 'provenance' ? 'active' : ''}`} onClick={() => setActiveTab('provenance')}>
            <span>📜</span> Provenance Receipts
          </button>
          <button className={`sidebar-nav-item ${activeTab === 'admission' ? 'active' : ''}`} onClick={() => setActiveTab('admission')}>
            <span>☸️</span> Admission Gate
          </button>
          <button className={`sidebar-nav-item ${activeTab === 'audit' ? 'active' : ''}`} onClick={() => setActiveTab('audit')}>
            <span>🔍</span> Runtime Threat Audit
          </button>
          <button className={`sidebar-nav-item ${activeTab === 'blueprint' ? 'active' : ''}`} onClick={() => setActiveTab('blueprint')}>
            <span>📁</span> Security-as-Code
          </button>
        </nav>

        {/* ── Clicking external official links to tools used ── */}
        <div className="sidebar-integrations">
          <h3 className="sidebar-integrations-title">Active Integrations</h3>
          <div className="integration-links">
            <a href="https://github.com/trufflesecurity/trufflehog" target="_blank" rel="noopener noreferrer" className="integration-link">TruffleHog</a>
            <a href="https://aquasecurity.github.io/trivy/" target="_blank" rel="noopener noreferrer" className="integration-link">Trivy</a>
            <a href="https://github.com/anchore/grype" target="_blank" rel="noopener noreferrer" className="integration-link">Grype</a>
            <a href="https://docs.sigstore.dev/cosign/overview/" target="_blank" rel="noopener noreferrer" className="integration-link">Cosign</a>
            <a href="https://github.com/sigstore/rekor" target="_blank" rel="noopener noreferrer" className="integration-link">RekorLog</a>
            <a href="https://kyverno.io/" target="_blank" rel="noopener noreferrer" className="integration-link">Kyverno</a>
            <a href="https://www.vaultproject.io/" target="_blank" rel="noopener noreferrer" className="integration-link">VaultKMS</a>
            <a href="https://falco.org/" target="_blank" rel="noopener noreferrer" className="integration-link">Falco</a>
            <a href="https://dependencytrack.org/" target="_blank" rel="noopener noreferrer" className="integration-link" style={{ gridColumn: 'span 2' }}>Dependency-Track</a>
          </div>
        </div>
      </aside>

      {/* ── Right Main Layout ── */}
      <div className="main-layout">
        <header className="main-header">
          <div className="header-compliance-badge">
            <span className="header-status-title">Compliance Posture:</span>
            {activeOverridesCount > 0 ? (
              <span className="compliance-status-text warning">⚠️ DEVIATIONS ACTIVE ({activeOverridesCount})</span>
            ) : (
              <span className="compliance-status-text">✓ SECURE & COMPLIANT (SLSA L4)</span>
            )}
          </div>

          <div className="header-metrics">
            <div className="header-metric-item">
              <span className="header-metric-label">Active Registry</span>
              <span className="header-metric-value">harbor.internal</span>
            </div>
            <div className="header-metric-item">
              <span className="header-metric-label">Cluster Pods</span>
              <span className="header-metric-value">{deployedPods.length} pods</span>
            </div>
            <div className="header-metric-item">
              <span className="header-metric-label">Vault KMS</span>
              <span className="header-metric-value" style={{ color: 'var(--emerald)' }}>ACTIVE</span>
            </div>
          </div>
        </header>

        <main className="main-content">
          
          {/* ====================================================================
              TAB: PIPELINE & BUILDS (OVERVIEW)
              ==================================================================== */}
          {activeTab === 'overview' && (
            <div>
              <div className="page-header">
                <h2 className="page-title">Production Security Pipeline & Artifact Registry</h2>
                <p className="page-desc">Monitors automated compiler steps, policy guardrails, and artifact attestation sign-offs.</p>
              </div>

              {/* Stat Cards Banner */}
              <div className="metrics-banner">
                <div className="stat-card active-gate">
                  <span className="stat-label">Security Gates</span>
                  <span className="stat-value">{6 - activeOverridesCount}/6</span>
                  <span className="stat-desc">Active build verification policies</span>
                </div>
                <div className={`stat-card cve-status ${hasVulnerabilitiesActive ? 'warning' : ''}`}>
                  <span className="stat-label">Vulnerability Health</span>
                  <span className="stat-value">{hasVulnerabilitiesActive ? 'Risk Alert' : '0 CVEs'}</span>
                  <span className="stat-desc">{hasVulnerabilitiesActive ? 'Critical vulnerabilities active' : 'All packages verified secure'}</span>
                </div>
                <div className="stat-card signatures">
                  <span className="stat-label">Cryptographic Registry</span>
                  <span className="stat-value">{rekorLedger.length} Signed</span>
                  <span className="stat-desc">Images signed via Sigstore</span>
                </div>
                <div className="stat-card drift-alerts">
                  <span className="stat-label">Audit Logs</span>
                  <span className="stat-value">{falcoLogs.filter(l => l.priority === 'Critical').length} Threats</span>
                  <span className="stat-desc">Active pods runtime exceptions</span>
                </div>
              </div>

              <div className="grid-3" style={{ gridTemplateColumns: '340px 1fr 1fr', alignItems: 'stretch' }}>
                
                {/* GitOps Policy Configurations */}
                <div className="card">
                  <h3 className="card-title" style={{ marginBottom: '16px' }}>GitOps Policy Configurations</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    
                    <div className="admission-config-group">
                      <label>Target Version Tag</label>
                      <input 
                        type="text" 
                        value={playImage.split(':')[1] || 'v1.2.4'} 
                        onChange={(e) => setPlayImage(`harbor.internal.fintech/finance/api-service:${e.target.value}`)} 
                        placeholder="e.g. v1.2.4"
                      />
                    </div>

                    <hr style={{ border: 'none', borderBottom: '1px solid var(--border)' }} />

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                      <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', fontWeight: '700', letterSpacing: '0.04em' }}>Simulate Risk Scenarios</h4>
                      
                      <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer' }}>
                        <input 
                          type="checkbox" 
                          checked={failSecretScan} 
                          onChange={(e) => setFailSecretScan(e.target.checked)} 
                        />
                        <span>Introduce Plaintext Secret in SCM</span>
                      </label>

                      <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer' }}>
                        <input 
                          type="checkbox" 
                          checked={useHeavyBaseImage} 
                          onChange={(e) => setUseHeavyBaseImage(e.target.checked)} 
                        />
                        <span>Use Vulnerable Ubuntu Legacy Image</span>
                      </label>

                      <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer' }}>
                        <input 
                          type="checkbox" 
                          checked={failCveScan} 
                          onChange={(e) => setFailCveScan(e.target.checked)} 
                        />
                        <span>Introduce Critical Package CVE</span>
                      </label>

                      <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer' }}>
                        <input 
                          type="checkbox" 
                          checked={skipSigning} 
                          onChange={(e) => setSkipSigning(e.target.checked)} 
                        />
                        <span>Bypass Sigstore Cryptographic Signatures</span>
                      </label>

                      <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer' }}>
                        <input 
                          type="checkbox" 
                          checked={runAsRoot} 
                          onChange={(e) => setRunAsRoot(e.target.checked)} 
                        />
                        <span>Allow Container Privilege Escalation</span>
                      </label>
                    </div>

                    <button 
                      className="btn btn-primary" 
                      onClick={handleRunPipeline} 
                      disabled={runningBuild === 'running'}
                      style={{ marginTop: '10px' }}
                    >
                      {runningBuild === 'running' ? 'Compiling Artifact...' : '🚀 Trigger Production Build & Scan'}
                    </button>
                  </div>
                </div>

                {/* Visual Pipeline Nodes Map */}
                <div className="card">
                  <h3 className="card-title" style={{ marginBottom: '16px' }}>Compliance Gate Logs</h3>
                  <div className="pipeline-layout">
                    {pipelineSteps.map((step, idx) => (
                      <div 
                        key={idx} 
                        className={`pipeline-node ${activeStepIndex === idx ? 'running' : ''} ${step.status}`}
                      >
                        <div className={`pipeline-node-status ${step.status}`}>
                          {step.status === 'pending' && '○'}
                          {step.status === 'running' && '⚡'}
                          {step.status === 'success' && '✓'}
                          {step.status === 'failed' && '✗'}
                          {step.status === 'skipped' && '—'}
                        </div>
                        <div className="pipeline-node-details">
                          <div className="pipeline-node-title">{step.name}</div>
                          <div className="pipeline-node-subtitle">{step.desc}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Terminal Logs View */}
                <div className="terminal-console">
                  <div className="terminal-header">
                    <div className="terminal-dots">
                      <span className="terminal-dot red"></span>
                      <span className="terminal-dot yellow"></span>
                      <span className="terminal-dot green"></span>
                    </div>
                    <div className="terminal-title">oidc-runner-agent-logs</div>
                  </div>
                  <div className="terminal-body">
                    {terminalLogs.map((line, idx) => {
                      let className = 'terminal-line info'
                      if (line.startsWith('❌') || line.startsWith('error') || line.includes('[CRITICAL]') || line.includes('failed')) className = 'terminal-line error'
                      if (line.startsWith('✓') || line.startsWith('success') || line.includes('PASSED') || line.includes('Approved') || line.includes('successfully')) className = 'terminal-line success'
                      if (line.startsWith('🚀') || line.startsWith('⚡')) className = 'terminal-line cmd'
                      if (line.startsWith('⚠️')) className = 'terminal-line warn'

                      return (
                        <div key={idx} className={className}>
                          {line}
                        </div>
                      )
                    })}
                    <div ref={terminalEndRef} />
                  </div>
                </div>
              </div>

              {/* Build History Database */}
              <div className="card" style={{ marginTop: '24px' }}>
                <div className="card-header">
                  <h3 className="card-title">Artifact Registry & Compliance Logs</h3>
                </div>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Build ID</th>
                        <th>Version Tag</th>
                        <th>Trigger Origin</th>
                        <th>Secret Check</th>
                        <th>Base Layer</th>
                        <th>Vulnerability Gate</th>
                        <th>Cosign Signed</th>
                        <th>SLSA Level</th>
                        <th>Registry Timestamp</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {buildHistory.map((b, idx) => (
                        <tr key={idx}>
                          <td><strong>{b.id}</strong></td>
                          <td><span className="badge info">{b.version}</span></td>
                          <td>{b.trigger}</td>
                          <td>
                            <span className={`badge ${b.config.fail_secret_scan ? 'danger' : 'success'}`}>
                              {b.config.fail_secret_scan ? 'Violated' : 'Passed'}
                            </span>
                          </td>
                          <td>{b.config.use_heavy_base_image ? 'Ubuntu (Heavy)' : 'Wolfi (Distroless)'}</td>
                          <td>
                            <span className={`badge ${b.config.fail_cve_scan ? 'danger' : 'success'}`}>
                              {b.config.fail_cve_scan ? 'Critical CVE' : 'Passed'}
                            </span>
                          </td>
                          <td>
                            <span className={`badge ${b.config.skip_signing ? 'danger' : 'success'}`}>
                              {b.config.skip_signing ? 'Bypassed' : 'Signed'}
                            </span>
                          </td>
                          <td>
                            <span className={`badge ${b.config.skip_signing ? 'danger' : 'success'}`}>
                              {b.config.skip_signing ? 'Unrated' : 'Level 4'}
                            </span>
                          </td>
                          <td>{b.timestamp}</td>
                          <td>
                            <span className={`badge ${b.status === 'success' ? 'success' : 'danger'}`}>
                              {b.status.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ====================================================================
              TAB: VULNERABILITY INTEL (SBOM HIDDEN)
              ==================================================================== */}
          {activeTab === 'cves' && (
            <div>
              <div className="page-header">
                <h2 className="page-title">Vulnerability Intelligence & Remediation Gateway</h2>
                <p className="page-desc">Track active CVE logs, security advisories, and trigger automated GitOps patches.</p>
              </div>

              {hasVulnerabilitiesActive && (
                <div className="patch-alert-box">
                  <div>
                    <strong>⚠️ Critical Vulnerability Alert:</strong> High-risk packages detected in active image layout. Built images will be denied at admission control.
                  </div>
                  <button className="btn btn-sm btn-primary" onClick={handleAutoPatch} style={{ background: '#ef4444', color: 'white' }}>
                    🔧 Remediate Security Advisories (Patch Git PR)
                  </button>
                </div>
              )}

              {patchStatus && (
                <div className="patch-success-box">
                  <h4 style={{ fontWeight: '700', marginBottom: '8px' }}>✓ Security Patch PR #46 Merged Successfully!</h4>
                  <p style={{ fontSize: '13px', marginBottom: '8px' }}>{patchStatus.pull_request}</p>
                  <ul style={{ paddingLeft: '18px', fontSize: '12px' }}>
                    {patchStatus.changes.map((c, i) => <li key={i}>{c}</li>)}
                  </ul>
                  <p style={{ marginTop: '8px', fontSize: '12.5px', fontWeight: '600' }}>💡 Re-run the compiler pipeline in the Pipeline & Builds tab to compile a secure production artifact.</p>
                </div>
              )}

              <div className="grid-2" style={{ gridTemplateColumns: '1.2fr 0.8fr' }}>
                {/* Security Advisories (Active Warnings) */}
                <div className="card">
                  <h3 className="card-title" style={{ marginBottom: '16px' }}>Active Security Advisories</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    {hasVulnerabilitiesActive ? (
                      packages_vulnerabilities.map((pkg, idx) => {
                        const active = (pkg.package === 'curl' && (failCveScan || useHeavyBaseImage)) || 
                                       (pkg.package === 'libc-bin' && useHeavyBaseImage) ||
                                       (pkg.package === 'openssl' && useHeavyBaseImage);
                        if (!active) return null;
                        return (
                          <div key={idx} style={{ padding: '16px', border: '1px solid rgba(239, 68, 68, 0.15)', background: 'rgba(239, 68, 68, 0.02)', borderRadius: '8px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                              <span style={{ fontWeight: '700', fontSize: '14px', color: '#fca5a5' }}>{pkg.cve} — {pkg.package}</span>
                              <span className="badge danger">{pkg.severity}</span>
                            </div>
                            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                              High-risk dependency version <code>{pkg.current_version}</code> detected in active package inventory. Upgrade target defined to secure version <code>{pkg.safe_version}</code>.
                            </p>
                          </div>
                        )
                      })
                    ) : (
                      <div style={{ padding: '40px 24px', textAlign: 'center', color: 'var(--text-secondary)', background: 'rgba(16, 185, 129, 0.03)', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.15)' }}>
                        <span style={{ fontSize: '36px', color: 'var(--emerald)' }}>✓</span>
                        <p style={{ fontWeight: '700', marginTop: '12px', fontSize: '14px', color: '#ffffff' }}>Compliance Audit Passed</p>
                        <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '4px' }}>Active container inventory reports zero critical or high vulnerabilities.</p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Vulnerability Metrics */}
                <div className="card">
                  <h3 className="card-title" style={{ marginBottom: '16px' }}>Threat Inventory Summary</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div style={{ display: 'flex', gap: '12px' }}>
                      <div style={{ flex: 1, padding: '16px', background: 'rgba(255,255,255,0.01)', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: '700', textTransform: 'uppercase' }}>CRITICAL CVES</div>
                        <div style={{ fontSize: '28px', fontWeight: '800', color: hasVulnerabilitiesActive ? 'var(--rose)' : 'var(--emerald)' }}>
                          {hasVulnerabilitiesActive ? (useHeavyBaseImage ? '2' : '1') : '0'}
                        </div>
                      </div>
                      <div style={{ flex: 1, padding: '16px', background: 'rgba(255,255,255,0.01)', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: '10px', color: 'var(--text-secondary)', fontWeight: '700', textTransform: 'uppercase' }}>HIGH CVES</div>
                        <div style={{ fontSize: '28px', fontWeight: '800', color: useHeavyBaseImage ? 'var(--amber)' : 'var(--emerald)' }}>
                          {useHeavyBaseImage ? '1' : '0'}
                        </div>
                      </div>
                    </div>

                    <div style={{ padding: '16px', background: 'rgba(255, 255, 255, 0.01)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                      <h4 style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '8px' }}>Remediation Status</h4>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className={`pulse-dot ${patchStatus ? '' : 'offline'}`} style={{ width: '8px', height: '8px' }}></span>
                        <span style={{ fontSize: '13px', fontWeight: '600' }}>
                          {patchStatus ? 'Remediation patches applied' : 'Security patches pending'}
                        </span>
                      </div>
                      <p style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                        {patchStatus ? 'Build inventory was auto-patched by security daemon.' : 'Trigger security patch to pull down remediated packages.'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ====================================================================
              TAB: VAULT KMS & REKOR LEDGER
              ==================================================================== */}
          {activeTab === 'vault' && (
            <div>
              <div className="page-header">
                <h2 className="page-title">HashiCorp Vault KMS & Sigstore Transparency Log</h2>
                <p className="page-desc">Review central key management policies and public transparency logs validating OIDC keyless claims.</p>
              </div>

              <div className="grid-3" style={{ gridTemplateColumns: '1fr 2fr' }}>
                
                {/* Vault KMS Key Details */}
                <div className="card">
                  <h3 className="card-title" style={{ marginBottom: '16px' }}>Vault Transit Engine KMS</h3>
                  {vaultKeys && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                      <div>
                        <span style={{ color: 'var(--text-secondary)', fontWeight: '600' }}>Key Alias:</span>
                        <code style={{ float: 'right', color: 'var(--violet-l)' }}>{vaultKeys.key_name}</code>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-secondary)', fontWeight: '600' }}>Key Type:</span>
                        <code style={{ float: 'right' }}>{vaultKeys.type}</code>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-secondary)', fontWeight: '600' }}>Status:</span>
                        <span className="badge success" style={{ float: 'right' }}>{vaultKeys.status}</span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-secondary)', fontWeight: '600' }}>Vault Path:</span>
                        <code style={{ float: 'right' }}>{vaultKeys.vault_path}</code>
                      </div>
                      
                      <hr style={{ border: 'none', borderBottom: '1px solid var(--border)' }} />
                      
                      <div className="admission-config-group">
                        <label>Verification Public Key</label>
                        <pre className="code-block" style={{ fontSize: '10px', height: '120px', overflowY: 'auto' }}>
                          {vaultKeys.public_key}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>

                {/* Rekor transparency log list */}
                <div className="card">
                  <h3 className="card-title" style={{ marginBottom: '16px' }}>Rekor Public Ledger Signatures Registry</h3>
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Entry Index</th>
                          <th>UUID Log</th>
                          <th>Container Reference</th>
                          <th>OIDC Certificate Issuer</th>
                          <th>Timestamp</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rekorLedger.map((r, idx) => (
                          <tr key={idx}>
                            <td><strong>{r.index}</strong></td>
                            <td><code>{r.uuid}</code></td>
                            <td><code style={{ fontSize: '11px', color: 'var(--cyan-l)' }}>{r.image}</code></td>
                            <td><span style={{ fontSize: '11px', color: 'var(--violet-l)', fontWeight: '600' }}>{r.certificate_issuer}</span></td>
                            <td>{r.integrated_time}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ====================================================================
              TAB: PROVENANCE
              ==================================================================== */}
          {activeTab === 'provenance' && (
            <div>
              <div className="page-header">
                <h2 className="page-title">in-toto Provenance & SLSA Compliance Document</h2>
                <p className="page-desc">Inspect cryptographically signed JSON build receipts indicating the builder ID and metadata parameters.</p>
              </div>

              <div className="card">
                <h3 className="card-title" style={{ marginBottom: '16px' }}>in-toto Provenance Attestation (SLSA Level 4 Compliance)</h3>
                <pre className="code-block">
{JSON.stringify({
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "harbor.internal.fintech/finance/api-service",
      "digest": {
        "sha256": "8f1e679a14d2430cba29234b4c731e842420980afcb902148fa8efcd2409f848"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://token.actions.githubusercontent.com"
    },
    "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/fintech-startup/api-service.git",
        "digest": {
          "sha1": "a5b7c8d9e0f1"
        },
        "entryPoint": ".github/workflows/secure_pipeline.yml"
      },
      "parameters": {
        "runId": "5128912",
        "actor": "dev-security",
        "event": "push"
      }
    },
    "metadata": {
      "buildStartedOn": new Date(Date.now() - 3600*1000).toISOString(),
      "buildFinishedOn": new Date().toISOString(),
      "completeness": {
        "parameters": true,
        "environment": true,
        "materials": true
      },
      "reproducible": true
    },
    "materials": [
      {
        "uri": "git+https://github.com/fintech-startup/api-service.git",
        "digest": {
          "sha1": "a5b7c8d9e0f1"
        }
      },
      {
        "uri": "cgr.dev/chainguard/wolfi-base:latest",
        "digest": {
          "sha256": "f3b392a832fa89b2138982ba09fc2c2dfc838902ff2356782390234a9ef1d02c"
        }
      }
    ]
  }
}, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {/* ====================================================================
              TAB: ADMISSION WEBHOOK GATES
              ==================================================================== */}
          {activeTab === 'admission' && (
            <div>
              <div className="page-header">
                <h2 className="page-title">Kubernetes Admission Webhook Policies Gate</h2>
                <p className="page-desc">Enforce OPA Gatekeeper and Kyverno verification rules to block container creation inside the production namespace.</p>
              </div>

              <div className="admission-playground">
                
                {/* Play Configuration */}
                <div className="admission-config-panel">
                  <h3 className="card-title">Production Admission Gateway</h3>
                  
                  <div className="admission-config-group">
                    <label>Container Image Reference</label>
                    <input 
                      type="text" 
                      value={playImage}
                      onChange={(e) => setPlayImage(e.target.value)}
                      placeholder="harbor.internal.fintech/finance/api-service:latest"
                    />
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      💡 Set version tags matching your builds (e.g. <code>v1.2.3</code> or custom version).
                    </span>
                  </div>

                  <div className="admission-config-group">
                    <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                      <input 
                        type="checkbox" 
                        checked={playRoot}
                        onChange={(e) => setPlayRoot(e.target.checked)}
                      />
                      <span>Run container as Root user</span>
                    </label>
                  </div>

                  <button className="btn btn-primary" onClick={handleTestDeployment}>
                    ☸️ Apply Deployment Manifest
                  </button>

                  {playResult && (
                    <div style={{ marginTop: '10px' }}>
                      <h4 style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-primary)' }}>Admission Decision:</h4>
                      <div style={{ marginTop: '8px' }}>
                        <span className={`badge ${playResult.status === 'Approved' ? 'success' : 'danger'}`}>
                          {playResult.status}
                        </span>
                      </div>
                      {playResult.reason && (
                        <p style={{ fontSize: '12px', color: '#f87171', marginTop: '6px', fontWeight: '600' }}>
                          {playResult.reason}
                        </p>
                      )}
                    </div>
                  )}
                </div>

                {/* Logs and Active Deployments */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  
                  {/* Deployment Check Logs */}
                  <div className="terminal-console" style={{ height: '260px' }}>
                    <div className="terminal-header">
                      <div className="terminal-dots">
                        <span className="terminal-dot red"></span>
                        <span className="terminal-dot yellow"></span>
                        <span className="terminal-dot green"></span>
                      </div>
                      <div className="terminal-title">admission-controller-logs</div>
                    </div>
                    <div className="terminal-body">
                      {playLogs.map((log, idx) => {
                        let className = 'terminal-line info'
                        if (log.startsWith('❌')) className = 'terminal-line error'
                        if (log.startsWith('✓')) className = 'terminal-line success'
                        if (log.startsWith('⚓') || log.startsWith('🛡️') || log.startsWith('☸️')) className = 'terminal-line cmd'
                        return <div key={idx} className={className}>{log}</div>
                      })}
                    </div>
                  </div>

                  {/* Active Cluster Pods */}
                  <div className="card">
                    <div className="card-header">
                      <h3 className="card-title">Running Pods in production namespace</h3>
                      <button className="btn btn-sm btn-secondary" onClick={async () => {
                        await fetch('/api/k8s/pods/clear', { method: 'POST' })
                        pollData()
                      }}>Clear Pods</button>
                    </div>
                    <div className="table-wrap">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Pod Name</th>
                            <th>Image Reference</th>
                            <th>Status</th>
                            <th>Signature Checked</th>
                            <th>Attestation Checked</th>
                            <th>Node</th>
                            <th>Age</th>
                          </tr>
                        </thead>
                        <tbody>
                          {deployedPods.map((p, idx) => (
                            <tr key={idx}>
                              <td><strong>{p.pod_name}</strong></td>
                              <td><code>{p.image}</code></td>
                              <td><span className="badge success">{p.status}</span></td>
                              <td>{p.signature_verified ? 'Verified ✔' : '—'}</td>
                              <td>{p.sbom_attached ? 'Verified ✔' : '—'}</td>
                              <td>{p.node}</td>
                              <td>{p.age}</td>
                            </tr>
                          ))}
                          {deployedPods.length === 0 && (
                            <tr>
                              <td colSpan="7" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                                No active pods running in cluster namespace. Deploy a secure image manifest.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ====================================================================
              TAB: CONTINUOUS AUDIT & RUNTIME (FALCO)
              ==================================================================== */}
          {activeTab === 'audit' && (
            <div>
              <div className="page-header">
                <h2 className="page-title">Continuous Runtime Security & Audit Log</h2>
                <p className="page-desc">Track active deployments, zero-day vulnerabilities, and runtime container drift anomalies.</p>
              </div>

              <div className="grid-2">
                
                {/* Dependency-Track Dashboard */}
                <div className="card">
                  <h3 className="card-title" style={{ marginBottom: '16px' }}>Dependency-Track Continuous Audit</h3>
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Project Name</th>
                          <th>Active Version</th>
                          <th>Risk Score</th>
                          <th>CVE Breakdowns</th>
                          <th>Last Sync</th>
                          <th>Audit Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {deptrackMetrics.map((d, idx) => (
                          <tr key={idx}>
                            <td><strong>{d.project_name}</strong></td>
                            <td><span className="badge info">{d.project_version}</span></td>
                            <td>
                              <strong style={{ color: d.risk_score > 10 ? 'var(--amber)' : 'var(--emerald)' }}>
                                {d.risk_score}
                              </strong>
                            </td>
                            <td style={{ fontSize: '11px' }}>
                              <span style={{ color: 'var(--rose-l)', marginRight: '8px' }}>Crit: {d.vulnerabilities.critical}</span>
                              <span style={{ color: 'var(--amber-l)', marginRight: '8px' }}>High: {d.vulnerabilities.high}</span>
                              <span style={{ color: 'var(--blue-l)' }}>Med: {d.vulnerabilities.medium}</span>
                            </td>
                            <td>{d.last_scan}</td>
                            <td>
                              <span className={`badge ${d.status === 'compliant' ? 'success' : 'danger'}`}>
                                {d.status.toUpperCase()}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Falco Runtime Security Logs */}
                <div className="card">
                  <div className="card-header">
                    <h3 className="card-title">Falco Container Runtime Monitoring</h3>
                    <button className="btn btn-sm btn-primary" onClick={handleTriggerFalcoDrift} style={{ background: 'var(--rose)', borderColor: 'var(--rose)' }}>
                      🚨 Simulate Runtime Audit Event
                    </button>
                  </div>

                  <div className="terminal-console" style={{ height: '320px' }}>
                    <div className="terminal-header">
                      <div className="terminal-dots">
                        <span className="terminal-dot red"></span>
                        <span className="terminal-dot yellow"></span>
                        <span className="terminal-dot green"></span>
                      </div>
                      <div className="terminal-title">falco-runtime-alerts-feed</div>
                    </div>
                    <div className="terminal-body" style={{ background: '#04070e' }}>
                      {falcoLogs.map((alert, idx) => (
                        <div key={idx} style={{ marginBottom: '10px', fontSize: '11.5px', borderBottom: '1px solid #1e293b', paddingBottom: '6px' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', marginBottom: '2px' }}>
                            <span>[{alert.timestamp}]</span>
                            <span style={{ color: alert.priority === 'Critical' ? '#f43f5e' : '#818cf8', fontWeight: 'bold' }}>
                              {alert.priority}
                            </span>
                          </div>
                          <div style={{ color: alert.priority === 'Critical' ? '#fca5a5' : '#e2e8f0', fontFamily: 'var(--font-mono)' }}>
                            {alert.output}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ====================================================================
              TAB: BLUEPRINT CODE FILES
              ==================================================================== */}
          {activeTab === 'blueprint' && (
            <div>
              <div className="page-header">
                <h2 className="page-title">Security-as-Code & GitOps Blueprints</h2>
                <p className="page-desc">Inspect security compliance manifests designed for SLSA compilation pipelines, OPA policies, and Kyverno guards.</p>
              </div>

              <div className="grid-2" style={{ gridTemplateColumns: '320px 1fr' }}>
                
                {/* File List */}
                <div className="admission-config-panel" style={{ height: '480px', overflowY: 'auto' }}>
                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', fontWeight: '700', marginBottom: '8px' }}>Pipeline Configs</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <button className="btn btn-sm btn-secondary" style={{ textAlign: 'left', display: 'block' }}>
                      📄 .github/workflows/secure_pipeline.yml
                    </button>
                    <button className="btn btn-sm btn-secondary" style={{ textAlign: 'left', display: 'block' }}>
                      📄 scripts/generate_sbom.sh
                    </button>
                    <button className="btn btn-sm btn-secondary" style={{ textAlign: 'left', display: 'block' }}>
                      📄 scripts/sign_image.sh
                    </button>
                  </div>

                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', fontWeight: '700', marginTop: '16px', marginBottom: '8px' }}>Admission Control (K8s)</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <button className="btn btn-sm btn-secondary" style={{ textAlign: 'left', display: 'block' }}>
                      📄 kyverno/policy_verify_signature.yaml
                    </button>
                    <button className="btn btn-sm btn-secondary" style={{ textAlign: 'left', display: 'block' }}>
                      📄 kyverno/policy_require_sbom.yaml
                    </button>
                    <button className="btn btn-sm btn-secondary" style={{ textAlign: 'left', display: 'block' }}>
                      📄 gatekeeper/gatekeeper_policy.rego
                    </button>
                    <button className="btn btn-sm btn-secondary" style={{ textAlign: 'left', display: 'block' }}>
                      📄 deployment.yaml
                    </button>
                  </div>

                  <h4 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', fontWeight: '700', marginTop: '16px', marginBottom: '8px' }}>Secrets Vault</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <button className="btn btn-sm btn-secondary" style={{ textAlign: 'left', display: 'block' }}>
                      📄 vault/policies/kms_signing.json
                    </button>
                  </div>
                </div>

                {/* Code viewer */}
                <div className="card" style={{ height: '480px', overflowY: 'auto' }}>
                  <h3 className="card-title" style={{ marginBottom: '14px' }}>Configuration Blueprint Viewer</h3>
                  <pre className="code-block" style={{ height: '380px', overflow: 'auto' }}>
{`name: Secure DevSecOps Supply Chain Pipeline (SLSA Level 4)
on:
  push:
    branches: [ main ]

jobs:
  secure-build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # Needed for OIDC keyless
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      - name: TruffleHog Secrets scan
        uses: trufflesecurity/trufflehog@main
      - name: Generate Attestations
        uses: anchore/sbom-action@v0
      - name: Compile and Push Container
        uses: docker/build-push-action@v5
      - name: Cosign Cryptographic Sign
        run: cosign sign --yes harbor.internal.fintech/finance/api-service:\${{ github.sha }}
      - name: Attest Build Provenance
        run: cosign attest --yes --predicate sbom.json --type cyclonedx ...`}
                  </pre>
                </div>

              </div>
            </div>
          )}

        </main>
      </div>
    </div>
  )
}
