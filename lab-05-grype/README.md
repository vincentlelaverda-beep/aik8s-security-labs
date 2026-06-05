# Lab 05 — Grype: Container Image Vulnerability Scanning

## What is Grype?

Grype is an open-source vulnerability scanner for container images and filesystems, built by Anchore. It scans every layer of a Docker image, inventories all installed packages (OS packages, Python libraries, Node modules, Java JARs, etc.), and cross-references them against multiple CVE databases:

- NVD (National Vulnerability Database)
- GitHub Advisory Database
- RedHat, Debian, Ubuntu, Alpine advisories
- AWS ECR public advisories

Each finding includes the package name, installed version, fixed version (if available), severity, and CVE ID. The fixed version column is what makes Grype actionable — it tells you exactly what to upgrade to.

### Where Grype sits in the security stack

| Layer | Tool | When it runs |
|-------|------|-------------|
| IaC (pre-deploy) | Checkov (Lab 04) | At commit — before any cluster sees the YAML |
| Image (pre-deploy) | **Grype** | After `docker build`, before pushing to registry |
| Cluster config (live) | Kube-Bench (Lab 02) | Against a running cluster |
| Runtime (in-flight) | Falco (Lab 03) | During execution |

Grype is the image scan gate. A CVE in a base image affects every container built from it. Catching it before the image is pushed to the registry means you fix it once — not after it has been deployed across 50 pods.

In a DevSecOps pipeline it sits between the build step and the artifact store (Docker Hub / ECR / ACR). No image with a Critical CVE should pass this gate.

---

## Setup — Install Grype

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype version
```

> Grype runs directly in WSL2. No KIND cluster needed for this lab.

### Update the vulnerability database

Grype maintains a local copy of CVE databases. Update it before scanning:

```bash
grype db update
```

---

## The Test Images

This lab scans two Python images — Python is the dominant language for AI/ML workloads and the most common base image in inference containers.

| Image | Why it's interesting |
|-------|---------------------|
| `python:3.6` | EOL since December 2021 — years of unpatched CVEs accumulate across every installed package |
| `python:3.12-slim` | Current, minimal base — `slim` variant strips non-essential packages, reducing attack surface |

> **AI context**: Teams frequently pin base image versions for reproducibility ("it works in training, don't touch it"). Those pins become a CVE liability over time. Grype is what surfaces that debt before it becomes an incident.

---

## Running Grype

### Scan the vulnerable image

```bash
grype python:3.6
```

Grype will pull the image from Docker Hub if it's not already local, then scan all layers. The first run may take a minute.

Save the output and get a severity summary:

```bash
grype python:3.6 2>&1 | tee /tmp/grype-python36.txt | tail -5
```

Then count findings per severity:

```bash
grep -oE "(Critical|High|Medium|Low|Negligible)" /tmp/grype-python36.txt | sort | uniq -c | sort -rn
```

Take a screenshot of the severity count output.

> Note: redirecting with `>` captures the table rows but drops the interactive summary. Use `tee` to capture everything.

### Scan the hardened image

```bash
grype python:3.12-slim 2>&1 | tee /tmp/grype-python312-slim.txt | tail -5
```

```bash
grep -oE "(Critical|High|Medium|Low|Negligible)" /tmp/grype-python312-slim.txt | sort | uniq -c | sort -rn
```

Take a screenshot of the severity count for comparison with `python:3.6`.

### Generate JSON reports

JSON output is useful for CI pipeline integration — a script can parse it and fail the build if `critical > 0`:

```bash
grype python:3.6 -o json > grype-python36-report.json
grype python:3.12-slim -o json > grype-python312-slim-report.json
```

### Filter by severity — Critical only

```bash
grype python:3.6 --fail-on critical
```

This exits with code 1 if any Critical CVE is found — the exact behaviour you want in a CI pipeline gate. A non-zero exit code blocks the pipeline.

### Bonus — scan an AI-specific image

```bash
grype tensorflow/tensorflow:1.14.0
```

TensorFlow 1.14.0 was released in 2019. This scan shows what happens when an AI team pins a training image and never updates it. Expect 300+ findings.

---

## Understanding the Output

A Grype result looks like this:

```
NAME              INSTALLED   FIXED-IN    TYPE       VULNERABILITY   SEVERITY
libssl1.1         1.1.1n-0    1.1.1n-0+   deb        CVE-2023-0464   High
pip               9.0.1       h23.3        python     CVE-2018-20225  Medium
setuptools        39.0.1      65.5.1      python     CVE-2022-40897  Medium
```

Each row has:
- **NAME** — the vulnerable package
- **INSTALLED** — the version currently in the image
- **FIXED-IN** — the version that patches it (blank = no fix yet)
- **TYPE** — package type (deb = OS package, python = pip package, java-archive = JAR)
- **VULNERABILITY** — CVE ID, searchable on nvd.nist.gov
- **SEVERITY** — Critical / High / Medium / Low / Negligible / Unknown

The summary at the bottom shows counts per severity — this is your pipeline gate metric.

---

## What I Found / What This Means

### `python:3.6` — the vulnerable image

Expected: **200–400+ findings**, including Critical and High severity CVEs across:
- OpenSSL — cryptographic library used by almost everything
- pip / setuptools — Python package managers (ironic: the tools that install packages have CVEs)
- libc — the C standard library
- curl / libcurl — used for HTTP in many packages

The Critical findings are not theoretical. OpenSSL CVEs like CVE-2023-0464 enable remote code execution. A container running `python:3.6` in production is exploitable.

### `python:3.12-slim` — the hardened image

Expected: **< 30 findings**, most Low or Negligible. The `slim` variant removes:
- Documentation packages
- Build tools (gcc, make)
- Extra locales and timezone data

Fewer packages = smaller attack surface = fewer CVEs. This is the principle of minimal base images applied directly.

### The key insight

Grype doesn't care about your application code. It cares about what's in the image layers below it. A perfectly written FastAPI inference server running on `python:3.6` inherits every CVE in that base image. The attacker doesn't need to find a bug in your code — they exploit OpenSSL, and your container falls.

**In a production AI stack** (Ollama + OpenWebUI + Milvus on K8S), each component runs as a separate pod with its own base image. Grype runs at build time for each image, and a Critical finding blocks the push to ECR. The same scan also runs nightly on images already in the registry — because new CVEs are published daily against images that passed the gate last week.

### The vulnerable vs hardened K8S deployments

`vulnerable-deployment.yaml` and `hardened-deployment.yaml` in this folder show the same workload using each image, with the hardened version also applying the security context lessons from Lab 04 (Checkov). A full scan of the hardened deployment with Checkov should pass all checks.

---

## Cleanup

No cluster resources were created in this lab. The KIND cluster is unaffected.

The pulled images (`python:3.6`, `python:3.12-slim`) remain in your local Docker cache. To remove them:

```bash
docker rmi python:3.6 python:3.12-slim
```

---

## Next Lab

**Lab 06 — Bandit**: Python SAST scanning. Bandit scans Python source code for security issues — hardcoded credentials, use of dangerous functions (`exec`, `eval`), weak cryptography, SQL injection patterns. We will scan the AI training code from Bill Ho's repo.
