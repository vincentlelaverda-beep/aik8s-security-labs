# Lab 03 — Falco: eBPF Runtime Threat Detection

**Phase**: 1 — K8S Security Foundations  
**Environment**: WSL2 (local, no cloud cost)  
**Prerequisite**: Lab 01 cluster running, Helm installed  
**Time**: ~25 min  
**Next lab**: [Lab 04 — Checkov](../lab-04-checkov/)

---

## What is Falco and why does it matter?

Kube-Bench (Lab 02) scans **configuration** — it reads files and checks flags. It tells you what the cluster is set up to do.

Falco watches **what actually happens** at runtime. It hooks into the Linux kernel using eBPF and monitors every syscall made by every container, in real time. When a container does something suspicious — spawns a shell, reads a sensitive file, makes an unexpected network connection — Falco fires an alert immediately.

This is the difference between static and runtime security:

| | Kube-Bench (Lab 02) | Falco (Lab 03) |
|---|---|---|
| **What it checks** | Config files and flags | Live kernel syscalls |
| **When it runs** | On demand (a Job) | Continuously (a DaemonSet) |
| **What it catches** | Misconfigurations | Attacks in progress |
| **Can it be bypassed?** | By changing config | Very hard — operates below the container |

Falco sits below the container runtime. Even if an attacker fully controls a container, the sysca
lls it makes are still visible to Falco at the kernel level.

In a corporate cloud environment, Falco is the equivalent of an EDR agent on each K8S node — it is the runtime detection layer of the CWPP (Cloud Workload Protection Platform).

---

## How Falco works

```
Container process makes a syscall (e.g. open /etc/shadow)
        │
        ▼
Linux kernel — eBPF probe intercepts the call
        │
        ▼
Falco engine — checks the call against its rules
        │
   ┌────┴────┐
   │         │
MATCH      NO MATCH
   │
   ▼
Alert fired → stdout / syslog / webhook / Falcosidekick
```

Falco rules are YAML-based conditions. A rule looks like:

```yaml
- rule: Terminal shell in container
  desc: A shell was spawned in a container with an interactive terminal
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
  output: >
    A shell was spawned in a container
    (user=%user.name container=%container.name image=%container.image.repository)
  priority: NOTICE
```

Falco ships with a default ruleset covering the most common high-confidence attack patterns. As of `falco-rules:5` (Falco 0.38+), this is a curated set of ~26 rules. A broader `falco-incubating-rules` package is available for teams that want wider coverage at the cost of more noise.

---

## Install Falco via Helm

Add the Falco Helm repository:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

Install Falco into its own namespace using the provided values file:

```bash
cd /mnt/c/Users/<your-username>/Claude\ Code\ Project/AIK8S\ Hands\ on\ Labs/lab-03-falco

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --values falco-values.yaml
```

> **What `modern_ebpf` means**: instead of compiling a kernel module (which fails inside KIND containers), Falco uses CO-RE eBPF — a pre-compiled program that runs on any kernel 5.8+. WSL2 ships with kernel 5.15+, so this works without any extra setup.

Wait for the DaemonSet to be Ready (one pod per node — expect 3 pods):

```bash
kubectl get daemonset falco -n falco --watch
# Wait until DESIRED == READY, then Ctrl+C
```

Confirm Falco is running and loading rules:

```bash
kubectl logs -n falco daemonset/falco | head -30
```

You should see lines like:
```
Loading rules from file /etc/falco/falco_rules.yaml
Loading rules from file /etc/falco/falco_rules.local.yaml
Starting gRPC server
```

---

## Deploy the test pod

```bash
kubectl apply -f test-pod.yaml
kubectl get pod falco-test --watch
# Wait until STATUS = Running
```

---

## Trigger alerts

Open two terminals side by side in WSL2.

**Terminal 1 — watch Falco alerts in real time:**

```bash
# Get the Falco pod name running on the worker node
kubectl get pods -n falco -o wide

# Stream logs from any Falco pod (use the pod name from above)
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

Now switch to **Terminal 2** and run each trigger one at a time, watching Terminal 1 for the alert.

---

### Trigger 1 — Spawn a shell in a container

```bash
kubectl exec -it falco-test -- bash
# once inside, type: exit
```

> **Important**: the `-it` flag is required. It allocates a pseudo-TTY, setting `proc.tty != 0`. The Falco rule condition includes `proc.tty != 0` specifically to filter out non-interactive shell use (CI scripts, init commands, etc.) — so `bash -c "echo hello"` without `-it` will NOT fire the rule.

**Expected Falco alert:**
```
Notice A shell was spawned in a container under unusual circumstances
(user=root user_loginuid=-1 k8s.ns=default k8s.pod=falco-test 
container=falco-test shell=bash parent=runc cmdline=bash ...)
```

**Why this fires**: legitimate application containers should never have a shell spawned in them at runtime. If you see this in production, it means either an operator is debugging (expected, but should be audited) or an attacker has shell access inside your pod.

---

### Trigger 2 — Read a sensitive file

```bash
kubectl exec falco-test -- cat /etc/shadow
```

**Expected Falco alert:**
```
Warning Sensitive file opened for reading by non-trusted program
(user=root user_loginuid=-1 program=cat 
file=/etc/shadow k8s.pod=falco-test container=falco-test ...)
```

**Why this fires**: `/etc/shadow` stores hashed passwords. No application should be reading it at runtime. This is a classic credential harvesting indicator — an attacker in a container trying to collect password hashes.

---

### Trigger 3 — Write inside /etc

```bash
kubectl exec falco-test -- touch /etc/evil-file
```

**Expected Falco alert:**
```
Error File below /etc opened for writing
(user=root user_loginuid=-1 command=touch /etc/evil-file
k8s.pod=falco-test container=falco-test ...)
```

**Why this fires**: application containers should have read-only root filesystems. Writing to `/etc` at runtime is a persistence technique — attackers modify config files to survive container restarts or to inject malicious configuration.

> **If no alert fires**: the "Write below etc" rule was removed from `falco-rules:5` (Falco 0.38+). The fix is in `falco-values.yaml` — see the [Troubleshooting](#troubleshooting) section below for the full explanation.

---

## Understanding alert priority levels

| Priority | Meaning | Example |
|----------|---------|---------|
| CRITICAL | Immediate response required | Kernel exploit attempt |
| ERROR | High-confidence attack indicator | Write to /etc |
| WARNING | Suspicious, investigate | Read /etc/shadow |
| NOTICE | Unusual but may be legitimate | Shell in container |
| INFO | Informational | Container started |

---

## Filter alerts for your test pod only

In a KIND cluster, Falco generates a lot of background noise from cluster components. Filter to your pod specifically:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco | grep "falco-test"
```

---

## Clean up

```bash
kubectl delete pod falco-test
helm uninstall falco -n falco
kubectl delete namespace falco
```

The cluster stays up for Lab 04.

---

## Troubleshooting

Two issues surfaced during this lab that are worth documenting because they reveal something real about how Falco works.

---

### Issue 1 — Trigger 1 silently produced no alert

**Symptom**: running `kubectl exec falco-test -- bash -c "echo hello"` produced no Falco alert, even though Falco was healthy and the other triggers worked.

**Root cause**: the "Terminal shell in container" rule has the condition `proc.tty != 0`. A TTY is a pseudo-terminal device — it is present when a human opens an interactive session, and absent when a script runs a command non-interactively. `bash -c "echo hello"` runs and exits in milliseconds with no TTY attached (`proc.tty = 0`), so the condition evaluates false and no alert fires.

This is intentional design. If the rule fired on every non-interactive bash invocation, CI pipelines, container init scripts, and health checks would generate constant noise. Falco is specifically watching for a human-style interactive shell — the kind an attacker uses after gaining initial access to a container.

**Fix**: use `-it` to allocate a pseudo-TTY:

```bash
kubectl exec -it falco-test -- bash
# type: exit
```

**Security takeaway**: Falco rules are not "bash ran" — they are "an interactive terminal was attached to a container." This distinction matters when you are tuning rules for production. A rule that fires too broadly gets disabled by ops teams. A rule that fires on the right signal gets acted on.

---

### Issue 2 — Trigger 3 (write to /etc) produced no alert

**Symptom**: `kubectl exec falco-test -- touch /etc/evil-file` created the file successfully but Falco produced no alert.

**Debugging steps**:

1. Confirmed the write actually happened — the file existed, so this was not a permissions issue:
   ```bash
   kubectl exec falco-test -- ls /etc/evil-file
   # /etc/evil-file  ← file is there, write succeeded
   ```

2. Checked which rules Falco loaded — only 26 rules, far fewer than expected:
   ```bash
   kubectl exec -n falco <falco-pod> -- grep '^- rule:' /etc/falco/falco_rules.yaml
   # 26 rules listed — "Write below etc" not among them
   ```

3. Investigated the rules delivery architecture. In Falco 0.44.0, the Helm chart uses two sidecar containers:
   - `falcoctl-artifact-install` (init container): downloads the rules OCI artifact from `ghcr.io/falcosecurity/rules/falco-rules:5` at startup
   - `falcoctl-artifact-follow` (sidecar): keeps them updated

   The downloaded rules land in an `emptyDir` volume shared between the sidecars and the main Falco container. Checking the init container logs confirmed the download succeeded and the signature was verified.

4. Listed all 26 loaded rules and confirmed "Write below etc" was absent. The rule existed in older Falco versions but was removed from `falco-rules:5` — it was considered too noisy in environments where package managers legitimately write to `/etc` during container build or init.

**Fix**: add the rule back as a custom rule in `falco-values.yaml` using the `customRules` stanza, then upgrade the Helm release:

```bash
helm upgrade falco falcosecurity/falco \
  --namespace falco \
  --values falco-values.yaml
```

The custom rule is already in `falco-values.yaml` in this repo. See the `customRules.write_etc_rule.yaml` block.

**Security takeaway**: the default Falco ruleset is intentionally conservative — it ships rules that are high-confidence and low-noise across diverse environments. Security teams are expected to extend it with custom rules tuned to their threat model. In a production environment you would also load the Falco "incubating" rules package (`falco-incubating-rules`) which contains a broader set of detections that are useful but noisier. Knowing that a rule you expected is not loaded is exactly the kind of gap that shows up during a detection coverage review.

---

## What I found / What this means

Three manual triggers, three Falco alerts after working through two real issues. Each alert includes:
- Which rule fired and its priority
- The exact process that triggered it
- The K8S pod and namespace context
- The user and command

**Finding 1 — Rule conditions encode threat model decisions, not just detection logic.**
The `proc.tty != 0` condition on the shell rule is not a technicality — it is a deliberate choice to alert on attacker-style interactive access and ignore legitimate automation. Understanding that condition is the difference between blindly following a runbook and actually knowing what your detection covers.

**Finding 2 — The default ruleset is a starting point, not a complete coverage set.**
`falco-rules:5` ships 26 rules. The "Write below etc" rule — which catches a textbook persistence technique — was removed because it generates too much noise in generic environments. In a real deployment you would audit which rules you need, load the `falco-incubating-rules` package, and write custom rules for your workload's specific normal behaviour. A detection you assume exists but doesn't is a blind spot.

**The bigger picture**: this is the runtime detection layer that Kube-Bench cannot provide. Kube-Bench told us in Lab 02 that there are no NetworkPolicies and no Pod Security policies. Falco catches what happens when those gaps are exploited — a shell being spawned, a sensitive file being read, a persistence attempt via /etc writes.

For an AI workload, Falco is particularly valuable because:
- AI inference pods (Ollama) should never spawn a shell
- Model storage should never have files written at runtime
- Vector DB pods should only make network connections to the inference pod

Any deviation from those expectations is a Falco alert. Lab 09 (AI stack on K8S) will show what normal baseline behaviour looks like — and therefore what an attack looks like against it.

---

## Screenshot checklist

- [ ] `helm install falco` — install output
- [ ] `kubectl get daemonset falco -n falco` — DESIRED == READY (3 pods)
- [ ] Terminal 1: Falco log stream running
- [ ] Terminal 2 + Terminal 1 side by side: each of the 3 triggers firing an alert
- [ ] `kubectl logs -n falco ... | grep falco-test` — all 3 alerts visible

Save screenshots in `lab-03-falco/screenshots/`.
