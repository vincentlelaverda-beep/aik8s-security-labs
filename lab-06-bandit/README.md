# Lab 06 — Bandit: Python SAST on AI Training Code

## What is Bandit?

Bandit is an open-source static analysis tool for Python, maintained by PyCQA (Python Code Quality Authority). It parses Python source files into an Abstract Syntax Tree and runs a set of plugins against it — one plugin per vulnerability class. It does not execute the code; it reads it, pattern-matches against known security antipatterns, and reports each finding with two independent dimensions:

- **Severity**: HIGH / MEDIUM / LOW — how bad if exploited
- **Confidence**: HIGH / MEDIUM / LOW — how certain Bandit is this is a real issue

Both dimensions matter. A HIGH severity / LOW confidence finding may be a false positive. A LOW severity / HIGH confidence finding may represent a real risk in context. The pair together tells you where to focus.

### Where Bandit sits in the security stack

| Layer | Tool | When it runs |
|-------|------|-------------|
| Source code (pre-build) | **Bandit** | At commit — before any container is built |
| Image (pre-deploy) | Grype (Lab 05) | After `docker build`, before pushing to registry |
| IaC (pre-deploy) | Checkov (Lab 04) | At commit — before any cluster sees the YAML |
| Cluster config (live) | Kube-Bench (Lab 02) | Against a running cluster |
| Runtime (in-flight) | Falco (Lab 03) | During execution |

Bandit is the furthest-left gate in the pipeline. It fires on source code before anything is built or deployed. It catches vulnerabilities that no image scanner or IaC tool can see — because they live in the application logic itself.

### Why AI training code is a high-risk target

AI training code is typically written by data scientists whose primary focus is model accuracy, not security hygiene. It routinely exhibits patterns that no production engineer would accept in a web application:

- **Pickle everywhere**: Models, datasets, and preprocessors serialized with `pickle` because it is fast and familiar. Pickle can execute arbitrary Python code on deserialization. A tampered dataset file becomes a code execution vector.
- **eval() for flexibility**: Hyperparameter configs passed as strings and evaluated at runtime. Opens a code injection path if any of that input comes from outside the script.
- **Credentials in source**: API keys, database passwords, and S3 tokens hardcoded in training scripts that get committed to shared repos.
- **Unverified downloads**: Model weights downloaded with SSL verification disabled to work around corporate proxy issues. Stays disabled in production.
- **shell=True in subprocess**: Command strings assembled from variables — command injection waiting to happen.

These patterns persist because training scripts are treated as throwaway code. When those scripts run in a shared K8S training cluster — with GPU access, mounted storage volumes, and network connectivity to production systems — throwaway becomes exploitable.

---

## Setup — Install Bandit

```bash
pip install bandit
bandit --version
```

> Bandit runs in WSL2 on any Python 3.x environment. No KIND cluster needed for this lab.

---

## The Test Code

This lab scans two Python files representing the same AI training workflow:

| File | Description |
|------|-------------|
| `vulnerable_training.py` | Realistic training script with 9 distinct security issues across HIGH / MEDIUM / LOW severity |
| `hardened_training.py` | Same script, every issue fixed — used to verify the pipeline gate goes green |

The vulnerable script covers the attack patterns most common in AI/ML codebases: pickle deserialization, `eval()`, shell injection, hardcoded credentials, weak cryptography, SQL injection, and unverified HTTP downloads. Each issue is real — not contrived. Pull any AI training repo from GitHub and you will find most of them.

---

## Running Bandit

### Scan the vulnerable script

```bash
bandit vulnerable_training.py
```

Bandit prints each finding with file path, line number, severity, confidence, CWE ID, and the offending code snippet.

Save the full output:

```bash
bandit vulnerable_training.py 2>&1 | tee /tmp/bandit-vulnerable.txt
```

Take a screenshot of the terminal output.

### Count findings by severity

```bash
grep "Severity:" /tmp/bandit-vulnerable.txt | sort | uniq -c
```

### Generate JSON output

JSON output is machine-parseable for CI pipeline integration:

```bash
bandit vulnerable_training.py -f json -o bandit-report.json
cat bandit-report.json | python3 -m json.tool | head -80
```

### Filter — HIGH severity + HIGH confidence only

```bash
bandit vulnerable_training.py -l -i
```

`-l` sets minimum severity to HIGH. `-i` sets minimum confidence to HIGH. These are the findings you cannot argue past in a code review.

### Pipeline gate — fail on HIGH severity

```bash
bandit vulnerable_training.py --severity-level high
echo "Exit code: $?"
```

Bandit exits with code 1 if any findings meet or exceed the severity threshold. A non-zero exit code blocks the CI pipeline.

### Scan the hardened script — verify the gate goes green

```bash
bandit hardened_training.py --severity-level high
echo "Exit code: $?"
```

Expected: no HIGH findings, exit code 0.

Take a screenshot showing the clean result alongside the vulnerable scan output.

---

## Understanding the Output

A Bandit finding looks like this:

```
>> Issue: [B301:pickle] Pickle and modules that wrap it can be unsafe when used to
   deserialize untrusted data, possible security issue.
   Severity: Medium   Confidence: High
   CWE: CWE-502 (https://cwe.mitre.org/data/definitions/502.html)
   Location: vulnerable_training.py:22:16
22          return pickle.load(f)
```

Each finding has:
- **Issue ID** — `[B301:pickle]` — unique identifier, searchable in Bandit docs
- **Description** — what the check is looking for and why
- **Severity** — HIGH / MEDIUM / LOW
- **Confidence** — HIGH / MEDIUM / LOW
- **CWE** — maps to the Common Weakness Enumeration standard
- **Location** — exact file and line number
- **Code** — the offending snippet

The summary at the bottom shows total counts by severity and confidence — your pipeline gate metrics.

---

## What I Found / What This Means

### Expected findings on `vulnerable_training.py`

| Issue ID | Severity | Confidence | Pattern | Attack Path |
|----------|----------|------------|---------|-------------|
| B602 | HIGH | HIGH | `subprocess.call(..., shell=True)` ×3 | Command injection — any variable reaching the shell string is a vector |
| B501 | HIGH | HIGH | `requests.get(url, verify=False)` | MITM — attacker intercepts model download, serves malicious weights |
| B301 | MEDIUM | HIGH | `pickle.load(f)` | Deserialization RCE — tampered dataset or model file executes arbitrary code |
| B307 | MEDIUM | HIGH | `eval(config_string)` | Code injection — attacker controls the hyperparameter string |
| B324 | MEDIUM | HIGH | `hashlib.md5()` | Weak model integrity check — collision attack lets a tampered model pass validation |
| B608 | MEDIUM | MEDIUM | SQL string formatting | SQL injection in metric logging |
| B403 | LOW | HIGH | `import pickle` | Flags presence of pickle in the codebase |
| B311 | LOW | HIGH | `random.randint()` | Predictable experiment IDs — not suitable for security-sensitive use |
| B101 | LOW | HIGH | `assert` for validation ×2 | Security assertions stripped by Python's `-O` optimisation flag |

Expected summary:
```
Total issues (by severity):
   High: 4
   Medium: 4
   Low: 5
```

### The findings that matter most for AI workloads

**B301 — pickle.load() (MEDIUM/HIGH)**

This is the AI-specific finding with no equivalent in standard web application SAST. Pickle can call arbitrary Python constructors during deserialization. A dataset file (`dataset.pkl`) tampered via supply chain attack, a compromised S3 bucket, or a malicious pull request becomes a remote code execution payload the moment your training job loads it. The model file has the same risk: a `model.pkl` published by an attacker on a shared repository executes code when loaded. This is not theoretical — it is the exact mechanism behind real ML supply chain attacks. It is also why Lab 07 (Modelscan) exists.

**B602 — subprocess with shell=True (HIGH/HIGH) × 3**

Three separate subprocess calls assemble shell command strings from variable inputs: the data directory path, the S3 bucket name, the GPU query. Any of those variables reaching the shell string becomes a command injection vector. In a training environment where paths come from a config file, a CI variable, or a user-supplied experiment config — all three are potentially attacker-controlled. `shell=True` is almost never necessary. The fix is always the same: pass arguments as a list.

**B501 — verify=False (HIGH/HIGH)**

Pre-trained model weights are downloaded from remote storage at training time. Disabling SSL verification means an attacker on the same network can intercept the download and serve a trojanized model. The legitimate weights arrive — and so does the malicious payload embedded alongside them. This matters more in AI than in standard application security because model files are large, opaque, and trusted implicitly. Nobody inspects the bytes in a weights file. They load it and run it. The verify=False finding connects directly to the threat Modelscan addresses in Lab 07.

**B307 — eval() (MEDIUM/HIGH)**

Hyperparameter configs passed as strings and evaluated at runtime appear in nearly every Jupyter-derived training codebase. `eval()` executes arbitrary Python expressions. If an experiment configuration ever comes from a shared config file, a database, an API, or a CI environment variable, any of those is a code injection vector. `json.loads()` does the same job with no execution capability.

### The hardened script — fix summary

`hardened_training.py` replaces every finding:

| Vulnerable pattern | Hardened replacement |
|-------------------|---------------------|
| `pickle.load(f)` | `numpy.load(path, allow_pickle=False)` / `joblib.dump()` |
| `subprocess.call(..., shell=True)` | `subprocess.run([...], shell=False)` at all three call sites |
| `requests.get(url, verify=False)` | `requests.get(url, verify=True)` + `raise_for_status()` |
| `eval(config_string)` | `json.loads(config_string)` |
| `hashlib.md5()` | `hashlib.sha256()` |
| SQL string formatting `%` | Parameterized query `(?, ?, ?)` |
| Hardcoded credentials | `os.environ.get("VAR_NAME")` |
| `random.randint()` | `secrets.token_hex(8)` |
| `assert` for validation | `if / raise ValueError` |

---

## The Pipeline Gate

```bash
# Fails — HIGH findings present
bandit vulnerable_training.py --severity-level high
echo "Exit code: $?"   # 1

# Passes — no HIGH findings
bandit hardened_training.py --severity-level high
echo "Exit code: $?"   # 0
```

In a CI pipeline, Bandit runs at the source code step — before the Docker image is built. A training script with a HIGH severity finding never makes it to a container. In GitHub Actions:

```yaml
- name: Python SAST — Bandit
  run: bandit -r . --severity-level high --confidence-level high -c bandit.yaml
```

The `--severity-level` threshold is a policy decision. A common starting point: fail on HIGH, report MEDIUM as warnings, treat LOW as informational. The JSON output allows a pipeline script to parse findings and route them to the developer who introduced them.

---

## Cleanup

No cluster resources were created in this lab. No Docker images were pulled.

```bash
rm -f /tmp/bandit-vulnerable.txt bandit-report.json
```

---

## Next Lab

**Lab 07 — ProtectAI Modelscan**: ML model backdoor detection. Modelscan scans serialized model files for malicious payloads — the exact attack vector that Bandit's B301 warning points to. We will scan a benign Keras model and a trojanized version from Bill Ho's lab repo to see what a real model backdoor looks like at the byte level.
