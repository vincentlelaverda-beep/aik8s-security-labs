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

Falco sits below the container runtime. Even if an attacker fully controls a container, the syscalls it makes are still visible to Falco at the kernel level.

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

Falco ships with ~100 default rules covering the most common attack patterns.

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
kubectl exec falco-test -- bash -c "echo hello"
```

**Expected Falco alert:**
```
Notice A shell was spawned in a container under unusual circumstances
(user=root user_loginuid=-1 k8s.ns=default k8s.pod=falco-test 
container=falco-test shell=bash parent=runc cmdline=bash -c "echo hello" ...)
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

## What I found / What this means

Three manual triggers, three Falco alerts. Each alert includes:
- Which rule fired and its priority
- The exact process that triggered it
- The K8S pod and namespace context
- The user and command

This is the runtime detection layer that Kube-Bench cannot provide. Kube-Bench told us in Lab 02 that there are no NetworkPolicies and no Pod Security policies. Falco catches what happens when those gaps are exploited — a shell being spawned, a sensitive file being read, a persistence attempt via /etc writes.

For an AI workload, Falco is particularly valuable because:
- AI inference pods (Ollama) should never spawn a shell
- Model storage should never have files written at runtime
- Vector DB pods should only make network connections to the inference pod

Any deviation from those expectations is a Falco alert. Lab 09 (AI stack on K8S) will show what normal baseline behavior looks like — and therefore what an attack looks like against it.

---

## Screenshot checklist

- [ ] `helm install falco` — install output
- [ ] `kubectl get daemonset falco -n falco` — DESIRED == READY (3 pods)
- [ ] Terminal 1: Falco log stream running
- [ ] Terminal 2 + Terminal 1 side by side: each of the 3 triggers firing an alert
- [ ] `kubectl logs -n falco ... | grep falco-test` — all 3 alerts visible

Save screenshots in `lab-03-falco/screenshots/`.
