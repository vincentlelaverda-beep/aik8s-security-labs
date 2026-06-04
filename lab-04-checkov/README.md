# Lab 04 — Checkov: IaC / YAML Static Scanning

## What is Checkov?

Checkov is an ope
n-source static analysis tool that scans Infrastructure-as-Code files — Kubernetes YAML manifests, Helm charts, Terraform, Dockerfiles — and flags security misconfigurations before anything is deployed.

It maps every finding to a named policy check (e.g., `CKV_K8S_16`) and cross-references it against:
- CIS Kubernetes Benchmark
- NSA/CISA Kubernetes Hardening Guidance
- MITRE ATT&CK

### Where Checkov sits in the security stack

| Layer | Tool | When it runs |
|-------|------|-------------|
| IaC (pre-deploy) | **Checkov** | At commit / in CI pipeline — before any cluster sees the YAML |
| Cluster config (live) | Kube-Bench (Lab 02) | Against a running cluster |
| Runtime (in-flight) | Falco (Lab 03) | During execution |

Checkov is the shift-left gate. A misconfiguration caught at code review costs nothing to fix. The same misconfiguration found after a breach costs everything.

In a DevSecOps pipeline it sits between the code repo and the build pipeline — the IaC Scan step before ArgoCD deploys anything to the cluster.

---

## Setup — Install Checkov

```bash
pip3 install checkov
checkov --version
```

> Checkov requires Python 3.8+. On WSL2, `python3.12` is available via Homebrew if needed.

---

## The Test Manifests

Four YAML files make up this lab:

| File | Purpose |
|------|---------|
| `bad-pod.yaml` | Deliberately insecure — covers 12+ real misconfigurations |
| `good-pod.yaml` | Hardened equivalent — passes all checks except image digest (see below) |
| `namespace.yaml` | Dedicated `lab-04` namespace — avoids the default namespace check |
| `networkpolicy.yaml` | Deny-all NetworkPolicy for the pod — required for CKV2_K8S_6 |

### What's wrong with `bad-pod.yaml`

Every line is intentional. This is not a contrived strawman — each setting maps to a real attack technique:

| Setting | Risk | MITRE |
|---------|------|-------|
| `privileged: true` | Full host kernel access from inside the container | T1611 — Escape to Host |
| `hostNetwork: true` | Container sees all host network interfaces, bypasses NetworkPolicy | T1599 |
| `hostPID: true` | Container can see and signal every process on the host | T1057 |
| `hostIPC: true` | Shared memory access to host processes | T1611 |
| `runAsUser: 0` | Runs as root — UID 0 maps to root on the host if combined with privileged | T1078 |
| `allowPrivilegeEscalation: true` | Allows `setuid` binaries to gain elevated privileges at runtime | T1548 |
| `readOnlyRootFilesystem: false` | Writable filesystem enables persistence (drop tools, modify configs) | T1222 |
| `capabilities: add: [SYS_ADMIN, NET_ADMIN]` | Near-root kernel capabilities — SYS_ADMIN alone is essentially privileged | T1611 |
| `hostPath: /` | Mounts the entire host filesystem into the container — full node compromise | T1005 |
| Hardcoded AWS credentials in `env` | Secrets in YAML end up in `kubectl describe`, logs, and git history | T1552 |
| `image: ubuntu:latest` | Mutable tag — the image can change between pulls, breaking reproducibility | — |
| No `resources` limits | Enables resource exhaustion (CPU/memory DoS against the node) | T1499 |

### What `good-pod.yaml` fixes

**Security context (pod-level)**
- `runAsNonRoot: true` + `runAsUser: 10000` — no root, and UID > 10000 avoids collision with any host system user (CKV_K8S_40)
- `seccompProfile: RuntimeDefault` — restricts syscall surface to a known-safe set
- `automountServiceAccountToken: false` — prevents the pod from inheriting cluster API access it does not need (CKV_K8S_38)

**Security context (container-level)**
- `allowPrivilegeEscalation: false` — setuid binaries cannot escalate
- `readOnlyRootFilesystem: true` — no writes to the container filesystem
- `privileged: false` — explicit, not implicit
- `capabilities: drop: [ALL]` — starts with zero kernel capabilities

**Workload hygiene**
- `resources.requests` + `resources.limits` — bounded CPU/memory, prevents node exhaustion
- `imagePullPolicy: Always` — forces a fresh pull on every start, ensures the registry digest is re-checked (CKV_K8S_15)
- Pinned image tag (`ubuntu:22.04`) instead of `latest`
- Liveness and readiness probes configured (CKV_K8S_8, CKV_K8S_9)

**Isolation**
- `namespace: lab-04` instead of `default` — workloads belong in dedicated namespaces (CKV_K8S_21)
- No `hostNetwork`, `hostPID`, `hostIPC`
- No `hostPath` volumes
- `networkpolicy.yaml` provides a deny-all NetworkPolicy scoped to this pod (CKV2_K8S_6)

**One intentionally remaining check — CKV_K8S_43 (image digest)**

The image is pinned to `ubuntu:22.04` (a tag), not a SHA256 digest. Pinning to a digest is the correct production practice — it makes the exact image bytes immutable and detects tampering in the registry. But it requires pulling the image first to get the digest:

```bash
docker pull ubuntu:22.04
docker inspect --format='{{index .RepoDigests 0}}' ubuntu:22.04
# Returns: ubuntu@sha256:<hash>
# Replace the image field with that value
```

For this lab, the tag is kept intentionally to show that Checkov catches it. A digest pin is left as a follow-up step after running the lab.

---

## Running Checkov

> Checkov runs directly on Windows (PowerShell) for this lab — no WSL2 needed.

### Scan the bad manifest

```powershell
cd "c:\Users\vince\Claude Code Project\AIK8S Hands on Labs\lab-04-checkov"

checkov -f bad-pod.yaml --framework kubernetes
```

Take a screenshot of the output — you should see a long list of `FAILED` checks.

### Scan the good manifest (directory scan)

Scan the whole `lab-04-checkov/` directory so Checkov sees the NetworkPolicy alongside the pod — otherwise the CKV2_K8S_6 check (NetworkPolicy coverage) will fail even though the policy exists.

```powershell
checkov -d "c:\Users\vince\Claude Code Project\AIK8S Hands on Labs\lab-04-checkov" --framework kubernetes
```

Expected result: 1 failure (`CKV_K8S_43` — image digest), all other checks pass.

### Bonus — scan all lab YAML files

```powershell
checkov -d "c:\Users\vince\Claude Code Project\AIK8S Hands on Labs" --framework kubernetes --compact
```

This scans every `.yaml` file in the project, including the Falco values file and test pod from Lab 03. It is expected to find issues — those lab files were not written to be hardened manifests.

### Generate a JSON report

```bash
checkov -f bad-pod.yaml --framework kubernetes -o json > checkov-bad-pod-report.json
```

Useful for piping into a CI system or SIEM.

---

## Understanding the Output

A Checkov result looks like this:

```
Check: CKV_K8S_16: "Do not admit containers with the NET_ADMIN capability"
    FAILED for resource: Pod.default.bad-pod
    File: /bad-pod.yaml:1-34

    Code lines for this check:
    1  | apiVersion: v1
    ...
```

Each check has:
- **Check ID** (`CKV_K8S_16`) — stable identifier, searchable in Checkov docs
- **Check name** — human-readable description of what it enforces
- **Resource** — the K8S object that failed (Kind.namespace.name)
- **File + line range** — where in your YAML the violation lives

The summary at the end shows total passed/failed/skipped counts — this is your pipeline gate metric.

---

## What I Found / What This Means

Running Checkov against `bad-pod.yaml` produces **15+ failures** from a 34-line manifest. Every single one maps to a real attack path:

- The `hostPath: /` + `privileged: true` combination is a complete node compromise — an attacker inside `bad-pod` has full read/write access to the host filesystem and the host kernel. They can read `/etc/shadow`, modify kubelet config, or install a rootkit.

- The hardcoded AWS credentials in the `env` block will appear in `kubectl describe pod bad-pod`, in cluster audit logs, and in any git history that ever contained this file. This is one of the most common real-world cloud compromise vectors.

- The lack of resource limits means this pod can consume all CPU and memory on its node, causing other pods (including system pods) to be evicted. This is a denial-of-service vector from within the cluster.

**The key insight**: none of these misconfigurations require an attacker. They are developer mistakes that create the blast radius for when an attacker does arrive. Checkov's job is to make these visible before deployment, when they cost nothing to fix.

**In an ENGIE-scale environment**, the value of Checkov is in the CI pipeline gate — every PR that touches a K8S manifest gets scanned automatically, and a failing check blocks the merge. The alternative is an ops team manually reviewing hundreds of YAML files per sprint, which does not scale and does not happen consistently.

---

## Cleanup

No cluster resources were created in this lab. Checkov runs entirely locally against YAML files.

The KIND cluster from Lab 01 is still running and will be used in Lab 05 (Grype).

---

## Next Lab

**Lab 05 — Grype**: container image CVE scanning. Grype scans a Docker image layer-by-layer and reports known CVEs from the installed OS packages and language dependencies. We will scan a deliberately vulnerable image and a hardened one.
