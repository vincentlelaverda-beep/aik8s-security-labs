# Lab 02 — Kube-Bench: CIS Kubernetes Benchmark Scan

**Phase**: 1 — K8S Security Foundations  
**Environment**: WSL2 (local, no cloud cost)  
**Prerequisite**: Lab 01 cluster must be running (`kind get clusters` should show `security-lab`)  
**Time**: ~15 min  
**Next lab**: [Lab 03 — Falco](../lab-03-falco/)

---

## What is the CIS Kubernetes Benchmark?

The **Center for Internet Security (CIS)** publishes a hardening guide for Kubernetes — a numbered list of configuration checks with a PASS/FAIL result and a remediation step for each failure. It covers:

| Section | What it checks |
|---------|---------------|
| 1 — Control Plane | API server flags, controller manager, scheduler |
| 2 — etcd | Encryption, TLS, auth |
| 3 — Control Plane Config | Admin kubeconfig, PKI |
| 4 — Worker Nodes | kubelet configuration per node |
| 5 — Policies | RBAC, NetworkPolicy, Pod Security, Secrets |

**Kube-Bench** is an open-source tool by Aqua Security that automates these checks. It runs against your live cluster and produces a scored report.

In a corporate cloud environment, this benchmark is the baseline for any K8S security posture review. Running it yourself on a raw KIND cluster shows you what the gap looks like before any hardening.

---

## How Kube-Bench works

Kube-Bench runs as a **Kubernetes Job** (a one-shot pod) inside your cluster. To check the control-plane, it needs to:

1. Run on the control-plane node (via `nodeSelector` + `toleration`)
2. Access the node's filesystem — the K8S config files live at paths like `/etc/kubernetes/`, `/var/lib/kubelet/` on the actual node
3. Read running processes (via `hostPID: true`) to check which flags the API server and kubelet were started with

This is why the Job YAML has all those `hostPath` volume mounts — kube-bench is reading the node's config files directly, not querying the API.

> **Security note**: this Job requires elevated access (hostPID, root filesystem mounts). In a production cluster you would run kube-bench from a privileged context with proper RBAC, not grant it to arbitrary users.

---

## Run the scan

Make sure you are in WSL2 and your KIND cluster is running:

```bash
kind get clusters
# Should show: security-lab

kubectl get nodes
# Should show 3 nodes Ready
```

Navigate to this lab directory:

```bash
cd /mnt/c/Users/<your-username>/Claude\ Code\ Project/AIK8S\ Hands\ on\ Labs/lab-02-kube-bench
```

Apply the Job:

```bash
kubectl apply -f kube-bench-job.yaml
```

Wait for the Job to complete (usually 30–60 seconds):

```bash
kubectl get job kube-bench --watch
# Wait until COMPLETIONS shows 1/1, then Ctrl+C
```

Retrieve the full report:

```bash
kubectl logs job/kube-bench
```

Save it to a file for reference:

```bash
kubectl logs job/kube-bench > kube-bench-results.txt
cat kube-bench-results.txt
```

---

## How to read the output

Each check is formatted like this:

```
[PASS] 1.2.1 Ensure that the --anonymous-auth argument is set to false
[FAIL] 1.2.22 Ensure that the --audit-log-path argument is set
[WARN] 4.2.12 Ensure that the RotateKubeletServerCertificate argument is set to true
[INFO] 5.1.1 Ensure that the cluster-admin role is only used where required
```

| Status | Meaning |
|--------|---------|
| PASS | Check passed — control is in place |
| FAIL | Check failed — remediation required |
| WARN | Cannot auto-verify — needs manual review |
| INFO | Informational — no direct pass/fail |

At the bottom of the report, kube-bench prints a summary:

```
== Summary total ==
63 checks PASS
12 checks FAIL
56 checks WARN
0 checks INFO
```

---

## Expected findings on a raw KIND cluster

These are the key FAIL results you should see and what they mean:

| Check | Finding | Why it matters |
|-------|---------|---------------|
| 1.1.12 | etcd data directory not owned by `etcd:etcd` | Other node processes could read/modify the backing store |
| 1.2.15 | `--profiling` enabled on API server | Exposes CPU/memory/goroutine traces over HTTP |
| 1.2.16 | `--audit-log-path` not set | No record of API server calls — blind to `kubectl exec` abuse |
| 1.2.17 | `--audit-log-maxage` not set | No log retention policy even if logging were on |
| 1.2.18 | `--audit-log-maxbackup` not set | No log rotation backup policy |
| 1.2.19 | `--audit-log-maxsize` not set | No log size limit |
| 1.3.2 | `--profiling` enabled on controller manager | Same exposure as API server |
| 1.4.1 | `--profiling` enabled on scheduler | Same exposure as API server |
| 5.3.2 | No NetworkPolicy exists (WARN) | All pods can talk to all pods — proven in Lab 01 |
| 5.6.2 | No seccomp profile on pods (WARN) | System calls from pods are unrestricted |
| 5.6.3 | No SecurityContext on pods (WARN) | No MAC policy or privilege restrictions |

These are **expected** on a raw cluster — they are the reason this lab exists.

### What KIND passes (and why)

| Check | Result | Reason |
|-------|--------|--------|
| 4.2.1 anonymous-auth=false | PASS | We saw this in the kubelet config in Lab 01 |
| 4.2.2 authorization-mode != AlwaysAllow | PASS | Webhook mode confirmed |
| 4.2.3 client-ca-file set | PASS | TLS client auth configured |

---

## Clean up

```bash
kubectl delete job kube-bench
```

The cluster stays up for Lab 03.

---

## What I found / What this means

A raw KIND cluster produces 12 FAILs and 56 WARNs out of ~74 checks. The most critical categories:

- **No audit logging** — you cannot detect or investigate an incident without logs
- **No NetworkPolicy** — lateral movement is unrestricted (proven in Lab 01)
- **No Pod Security** — pods can run as root, mount host paths, escape to the node
- **Certificate rotation gaps** — long-lived credentials increase compromise window

None of these require exotic attacks. Missing audit logging means an attacker who compromises a pod can run `kubectl` commands and leave no trace. Missing NetworkPolicy means they can reach every other pod for free.

Kube-Bench does not fix anything — it tells you what to fix. Labs 03–05 add layers of detection and prevention on top of this baseline.

---

## Screenshot checklist

- [ ] `kubectl apply -f kube-bench-job.yaml` — Job created
- [ ] `kubectl get job kube-bench` — COMPLETIONS 1/1
- [ ] `kubectl logs job/kube-bench` — full report visible (scroll to see FAIL entries)
- [ ] Summary line at the bottom showing PASS/FAIL/WARN counts

Save screenshots in `lab-02-kube-bench/screenshots/`.
