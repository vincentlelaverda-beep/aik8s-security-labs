# Lab 01 — KIND: Local Kubernetes Playground

**Phase**: 1 — K8S Security Foundations  
**Environment**: WSL2 (local, no cloud cost)  
**Time**: ~30 min (including WSL2 install + restart)  
**Next lab**: [Lab 02 — Kube-Bench](../lab-02-kube-bench/)

---

## What is KIND and why does it matter?

KIND (Kubernetes IN Docker) runs a full K8S cluster inside Docker containers. Each "node" is a Docker container running a Linux OS with `kubelet` inside.

Why KIND for security labs:
- **Real K8S API** — everything you do here maps 1:1 to production clusters
- **eBPF-capable** — via WSL2's Linux kernel, Falco (Lab 03) works natively
- **Multi-node** — the config in this lab creates 3 nodes, enabling network policy and scheduling experiments
- **Zero cost** — runs entirely on your laptop, no cloud credits needed
- **Fast teardown** — `kind delete cluster` wipes everything cleanly

In a corporate cloud environment, the equivalent would be a managed K8S service (AKS, EKS, GKE). KIND lets you learn the security primitives locally before applying them at cloud scale.

---

## Architecture of this lab

```
Your WSL2 Linux environment
└── Docker Engine
    ├── Container: security-lab-control-plane  (K8S API server, etcd, scheduler)
    ├── Container: security-lab-worker          (kubelet + workloads)
    └── Container: security-lab-worker2         (kubelet + workloads)
```

Port mappings on the control-plane container (for future ingress labs):
- `localhost:8080` → container port 80
- `localhost:8443` → container port 443

---

## Prerequisites

### Step 1 — Enable and install WSL2

Open **PowerShell as Administrator** on Windows and run:

```powershell
wsl --install
```

This installs WSL2 with Ubuntu by default and enables the required Windows features. **A restart is required.**

After restart, Ubuntu will open automatically and ask you to create a Linux username and password. Do this — it becomes your WSL2 user.

Verify WSL2 is running:

```powershell
wsl --status
# Should show: Default Version: 2
```

### Step 2 — Install Docker Desktop for Windows

Download and install **Docker Desktop** from the official site. During install:
- Enable the **"Use WSL2 based engine"** option
- After install, open Docker Desktop → Settings → Resources → WSL Integration → enable your Ubuntu distro

Verify Docker is accessible from inside WSL2:

```bash
# Run this inside your WSL2 Ubuntu terminal
docker version
# Should show Client and Server versions
```

### Step 3 — Install kubectl inside WSL2

```bash
# Inside WSL2
curl -LO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
kubectl version --client
```

### Step 4 — Install KIND inside WSL2

```bash
# Inside WSL2
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64
chmod +x kind
sudo mv kind /usr/local/bin/
kind version
```

### Step 5 — Install Helm inside WSL2

```bash
# Inside WSL2
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version
```

---

## Create the cluster

Navigate to this lab directory inside WSL2:

```bash
# Inside WSL2 — adjust path to match your Windows username
cd /mnt/c/Users/<your-username>/Claude\ Code\ Project/AIK8S\ Hands\ on\ Labs/lab-01-kind
```

Create the cluster using the provided config:

```bash
kind create cluster --config kind-config.yaml
```

Expected output:
```
Creating cluster "security-lab" ...
 ✓ Ensuring node image (kindest/node:v1.33.x) 🖼
 ✓ Preparing nodes 📦 📦 📦
 ✓ Writing configuration 📜
 ✓ Starting control-plane 🕹️
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾
 ✓ Joining worker nodes 🚜
Set kubectl context to "kind-security-lab"
```

> Note: First run pulls the node image (~1 GB). Subsequent runs are instant.

---

## Verify the cluster

```bash
# Check all 3 nodes are Ready
kubectl get nodes -o wide

# Expected:
# NAME                         STATUS   ROLES           AGE   VERSION
# security-lab-control-plane   Ready    control-plane   2m    v1.33.x
# security-lab-worker          Ready    <none>          90s   v1.33.x
# security-lab-worker2         Ready    <none>          90s   v1.33.x

# Check the K8S API server info
kubectl cluster-info

# List all system namespaces
kubectl get namespaces

# List all pods running in the system namespace
kubectl get pods -n kube-system
```

### What you should see in kube-system

| Pod | Purpose |
|-----|---------|
| `coredns-*` | Internal DNS — resolves service names inside the cluster |
| `etcd-*` | The cluster's key-value store — contains ALL cluster state, a high-value target |
| `kube-apiserver-*` | The control plane API — every `kubectl` command hits this |
| `kube-controller-manager-*` | Reconciles desired vs actual state |
| `kube-scheduler-*` | Decides which node a new Pod lands on |
| `kube-proxy-*` | Manages network rules on each node |
| `kindnet-*` | KIND's built-in CNI (network plugin) |

---

## Security observations — default cluster posture

This is a vanilla KIND cluster with no hardening. Here is what you would expect Kube-Bench (Lab 02) to flag:

| Finding | Why it matters |
|---------|---------------|
| Anonymous auth may be enabled on the API server | Unauthenticated requests could reach the API |
| No PodSecurity admission controller configured | Pods can run as root or with host namespaces by default |
| etcd is not encrypted at rest | Cluster secrets stored in plaintext inside the etcd container |
| No NetworkPolicy exists | All pods in all namespaces can talk to each other freely |
| No audit logging configured | No record of who ran what `kubectl` commands |
| kubelet read-only port may be open (10255) | Exposes node metadata without authentication |

These are expected in a local KIND cluster — they are the reason we run Kube-Bench in Lab 02.

### Quick check: can pods reach each other cross-namespace?

```bash
# Deploy a test pod in the default namespace
kubectl run test-pod --image=busybox --restart=Never -- sleep 3600

# Get the CoreDNS service IP
kubectl get svc -n kube-system kube-dns

# From the test pod, try to reach kube-dns
kubectl exec test-pod -- nslookup kubernetes.default

# Clean up
kubectl delete pod test-pod
```

If the DNS query succeeds, the default pod can reach kube-system services — no network isolation exists. Lab 03 (Falco) will detect this kind of lateral movement; Lab 04 (Checkov) will flag the missing NetworkPolicy in your YAML.

---

## Explore the node security context

```bash
# Inspect the control-plane node
kubectl describe node security-lab-control-plane

# Look at the kubelet configuration
kubectl get --raw /api/v1/nodes/security-lab-control-plane/proxy/configz 2>/dev/null | python3 -m json.tool | head -60
```

---

## Teardown

When done with this lab:

```bash
kind delete cluster --name security-lab
```

This removes all 3 Docker containers and the kubeconfig entry. Docker images are kept locally so the next `kind create cluster` is fast.

---

## What I found / What this means

A fresh KIND cluster has **zero security hardening** — it's a blank slate that passes usability over security. This is fine for a lab environment but would be completely unacceptable in production.

The key insight from this lab: **K8S security is not on by default.** Every control — network policies, pod security, audit logging, etcd encryption, RBAC hardening — has to be explicitly configured. That is exactly what the rest of Phase 1 teaches.

Lab 02 (Kube-Bench) will give you a scored CIS benchmark report against this exact cluster, turning these observations into specific, numbered findings.

---

## Screenshot checklist

Before moving to Lab 02, capture:
- [ ] `kubectl get nodes -o wide` showing 3 nodes Ready
- [ ] `kubectl get pods -n kube-system` showing all system components
- [ ] The cross-namespace DNS test output

Save screenshots in `lab-01-kind/screenshots/`.
