# AI on Kubernetes — Security Labs

Hands-on security labs covering Kubernetes security foundations and AI-specific security controls. Each lab produces a technical reference (this repo) and a narrative blog post published at [vincentlelaverda.com/articles](https://vincentlelaverda.com/articles/index.html).

Source material: **"AI on K8S — Security Considerations"** by Bill Ho (CKA/CKAD/CKS/CAISP), presented 29-05-2026.

> **GitHub repo:** [github.com/vincentlelaverda-beep/aik8s-security-labs](https://github.com/vincentlelaverda-beep/aik8s-security-labs)  
> **Blog articles:** [vincentlelaverda.com/articles](https://vincentlelaverda.com/articles/index.html)

---

## Environment

- **OS:** WSL2 on Windows 11 Pro
- **Tools:** `kubectl`, `kind`, `helm`, `docker`, `python3`, `gh`
- Linux kernel required for Falco (eBPF) — WSL2 kernel 5.15+ satisfies this

---

## Lab Series

### Phase 1 — K8S Security Foundations

| Lab | Tool | Focus | Status |
|-----|------|--------|--------|
| [01](lab-01-kind/) | **KIND** | Spin up a local K8S cluster | ✅ Complete |
| [02](lab-02-kube-bench/) | **Kube-Bench** | CIS benchmark scan — 63 PASS / 12 FAIL / 56 WARN | ✅ Complete |
| [03](lab-03-falco/) | **Falco** | Runtime eBPF threat detection | 🔄 Files ready |
| 04 | **Checkov** | IaC/YAML static scanning | ⏳ Pending |
| 05 | **Grype** | Container image CVE scanning | ⏳ Pending |

### Phase 2 — AI-Specific Security

| Lab | Tool | Focus | Status |
|-----|------|--------|--------|
| 06 | **Bandit** | SAST on Python AI training code | ⏳ Pending |
| 07 | **ProtectAI Modelscan** | ML model backdoor detection | ⏳ Pending |
| 08 | **Garak** | LLM vulnerability scanning against Ollama | ⏳ Pending |
| 09 | **AI Stack on K8S** | Ollama + OpenWebUI with namespace isolation | ⏳ Pending |
| 10 | **Portkey / LiteLLM** | LLM guardrails and AI gateway | ⏳ Pending |
| 11 | **Full Security Stack** | KSPM + CWPP + XDR + Kasten + DSPM | ⏳ Pending |

---

## Repo Structure

Each lab folder follows this layout:

```
lab-XX-toolname/
├── README.md        # Setup steps, commands, key findings
├── *.yaml           # All K8S manifests used
└── screenshots/     # Terminal output proving the lab ran
```

Blog writeups (narrative format for a security engineer audience) are published separately at [vincentlelaverda.com/articles](https://vincentlelaverda.com/articles/index.html).  
Reference: [Bill Ho's original lab repo](https://github.com/billhoph/AwsEvent-AI-Lab)

---

## Key Findings So Far

### Lab 01 — KIND
- A fresh K8S cluster has zero hardening out of the box
- Pods in `default` namespace reach CoreDNS in `kube-system` with no NetworkPolicy to block them
- Cluster: 3 nodes (1 control-plane + 2 workers), name `security-lab`

### Lab 02 — Kube-Bench
- **63 PASS / 12 FAIL / 56 WARN** on a never-touched cluster
- Critical FAILs: audit logging missing (1.2.16–1.2.19), profiling enabled on all control plane components (1.2.15, 1.3.2, 1.4.1), etcd directory ownership wrong (1.1.12)
- 34 of 56 WARNs are in the Policies section — manual policy gaps Kube-Bench can flag but not auto-verify

---

## Reference

Bill Ho's original lab repo: [github.com/billhoph/AwsEvent-AI-Lab](https://github.com/billhoph/AwsEvent-AI-Lab)
