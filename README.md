# Web Vulnerability Scanner (Educational)

A modular **educational web vulnerability scanner** for authorized testing of common issues:  
XSS, SQL Injection, Blind SQLi, Command Injection, Open Redirect, CSRF, Directory Traversal, Misconfigurations, and Security Headers/Cookies checks.  

⚠️ **Disclaimer**: For **educational and research use only**. Run against your own apps or deliberately vulnerable labs (e.g., DVWA, Juice Shop, TestPHP.vulnweb).  
Unauthorized scanning of third-party systems is illegal.

---

## ✨ Features
- Modular design with separate scanners (`scanners/`)
- JSON payload sets for reproducible fuzzing
- Multiple output formats (`txt`, `csv`, `html`, `json`)
- Benchmarks (`bench/`) with structured results (`docs/`)
- Tested with `pytest` (`tests/`)

---

## 📦 Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/<Kartik7Karma >/web-vuln-scanner.git
cd web-vuln-scanner
python3 -m venv venv
source venv/bin/activate
pip install -e .
🚀 Quickstart
Run the full scanner:

bash
python full_scan.py
Output reports:

report.txt

report.csv

report.html

results.json

📊 Benchmarks
Benchmarks are stored under docs/.
They test runtime and vulnerability detection on deliberately vulnerable sites.

Config: bench/

Results: docs/bench_results.md, docs/bench_results.csv

Raw scans: bench/raw/

Run benchmarks yourself:

bash
python bench/run_bench.py
Example result:

URL	Status	Seconds	Total Vulns	SQLi	XSS	Command Injection
http://testphp.vulnweb.com	ok	15.78	6	6	0	✅

🧪 Testing
Run unit tests:

bash
pytest -q
📂 Project Structure
web-vuln-scanner/
├── bench/               # Benchmark runner + targets
├── core/                # Core utilities (forms, logger, scanner, utils)
├── docs/                # Benchmark results + documentation
├── payloads/            # Payload libraries (XSS, SQLi, etc.)
├── reports/             # Report generators (CSV, HTML, TXT)
├── scanners/            # Individual vulnerability scanners
├── tests/               # Unit tests
├── full_scan.py         # Main entrypoint for scanning
├── LICENSE              # MIT License
├── README.md            # Project documentation
└── pyproject.toml       # Build + dependencies
📖 Citation
A CITATION file (CITATION.cff) is included.
Please cite this project if you use it in academic work:


cff-version: 1.2.0
title: Web Vulnerability Scanner (Educational)
authors:
  - family-names: "Budhlakoti"
    given-names: "Kartik"
version: "0.1.0"
date-released: "2025-01-09"
license: MIT
message: "If you use this software, please cite it as below."
📢 Contributing
See CONTRIBUTING.md.
Security policy: SECURITY.md.

📜 License
MIT License. See LICENSE.

