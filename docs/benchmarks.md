# Benchmarks

> **Scope**: quick, reproducible measurements for academic review (MEXT) and repo credibility.  
> **Ethics**: only scan local, deliberately vulnerable apps (Juice Shop, DVWA) or hosts you own.

---

## Environment
- **Machine**: `<fill in CPU/GPU/RAM>`
- **OS**: `<Ubuntu / WSL / other>`
- **Python**: `<python --version>`
- **Commit**: `<git rev-parse --short HEAD>`
- **Command**:  
  ```bash
  python bench/run_bench.py
Targets
TestPHP.vulnweb.com — intentionally vulnerable testbed

(optional later) DVWA / Juice Shop

Metrics
Seconds → runtime per target

Findings → total and by category

Flags → _vulnerable columns mark whether a class of issues was confirmed

(optional later) CPU/RSS, FP/FN vs. labeled ground truth

Results (auto-generated)
URL	Status	Seconds	Total Vulns	cmd_injection	sqli	xss	open_redirect	headers	cookies	errors	cmd_injection_vuln	sqli_vuln	xss_vuln	open_redirect_vuln	headers_vuln	cookies_vuln	errors_vuln	error
http://testphp.vulnweb.com	ok	15.78	6	6	0	0	0	0	0	0	True	False	False	False	False	False	False	

Detailed Findings (from JSON scan)
Command Injection

6 payloads triggered (;, &&, |, backticks, $(), ||).

Vulnerable endpoint: search.php?test=query (POST searchFor parameter).

Missing Security Headers

Strict-Transport-Security, X-Frame-Options, Content-Security-Policy,
X-Content-Type-Options, Permissions-Policy, Referrer-Policy.

SQL Injection → not detected.

XSS → not detected.

Open Redirect → not detected.

Notes
Results above are reproducible via bench/run_bench.py.

For credibility, always include the Git commit hash and Python version used.

More targets (DVWA, Juice Shop) may be added later for broader coverage.