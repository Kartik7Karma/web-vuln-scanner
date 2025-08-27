# Web Vulnerability Scanner (Educational)

A modular scanner for educational, authorized testing of common web issues (XSS, SQLi, Blind SQLi, Command Injection, Open Redirect, CSRF checks, Dir Traversal, headers/cookies checks).

## Quickstart
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest -q

python full_scan.py

---

### CITATION.cff 
cat > CITATION.cff << 'EOF'
cff-version: 1.2.0
title: Web Vulnerability Scanner (Educational)
authors:
  - family-names: "Budhlakoti"
    given-names: "Kartik"
version: "0.1.0"
date-released: "2025-01-09"
license: MIT
message: "If you use this software, please cite it as below."
