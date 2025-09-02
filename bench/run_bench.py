#!/usr/bin/env python3
import csv, json, os, re, subprocess, sys, time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
URLS = REPO / "bench" / "urls.txt"
RAW  = REPO / "bench" / "raw"
OUT_CSV = REPO / "docs" / "bench_results.csv"
OUT_MD  = REPO / "docs" / "bench_results.md"

# Define all known categories (scanner modules) you want columns for
KNOWN_CATS = [
    "cmd_injection",
    "sqli",
    "xss",
    "open_redirect",
    "headers",
    "cookies",
    "errors",
]

def slug(url: str) -> str:
    s = re.sub(r"^https?://", "", url).strip().strip("/")
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s) or "target"

def run_scan(url: str, json_path: Path):
    cmd = [sys.executable, "-m", "core.scanner", "--url", url, "--output-json", str(json_path)]
    t0 = time.perf_counter()
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(REPO))
    dt = time.perf_counter() - t0
    return p.returncode, dt, p.stdout, p.stderr

def count_findings(scan_json):
    items = scan_json if isinstance(scan_json, list) else [scan_json]
    total = 0
    cats = {cat: 0 for cat in KNOWN_CATS}
    vuln_flags = {f"{cat}_vulnerable": False for cat in KNOWN_CATS}

    for it in items:
        for k, v in (it or {}).items():
            # Case 1: Old-style results (list under *_results)
            if isinstance(v, list) and k.endswith("_results"):
                n = len(v)
                total += n
                base = k.replace("_results", "")
                cats[base] = cats.get(base, 0) + n
                if n > 0:
                    vuln_flags[f"{base}_vulnerable"] = True

            # Case 2: Vulnerability dicts (with "vulnerabilities" key)
            elif isinstance(v, dict) and "vulnerabilities" in v:
                vulns_list = v.get("vulnerabilities", [])
                n = len(vulns_list)
                total += n
                cats[k] = cats.get(k, 0) + n
                if n > 0:
                    vuln_flags[f"{k}_vulnerable"] = True

    return total, cats, vuln_flags

def main():
    RAW.mkdir(parents=True, exist_ok=True)
    urls = [u.strip() for u in URLS.read_text().splitlines() if u.strip() and not u.strip().startswith("#")]
    rows = []

    for url in urls:
        tag = slug(url)
        json_file = RAW / f"{tag}.json"
        print(f"[*] Scanning {url} -> {json_file.name}")
        rc, secs, out, err = run_scan(url, json_file)
        status = "ok" if rc == 0 and json_file.exists() else "fail"

        vulns, cats, vuln_flags = (0, {cat: 0 for cat in KNOWN_CATS}, {f"{cat}_vulnerable": False for cat in KNOWN_CATS})
        error_msg = ""
        if json_file.exists():
            try:
                data = json.loads(json_file.read_text())
                vulns, cats, vuln_flags = count_findings(data)
            except Exception as e:
                error_msg = f"[parse error] {e}"

        row = {
            "url": url,
            "status": status,
            "seconds": f"{secs:.2f}",
            "vulns_total": vulns,
            "error": error_msg,
        }
        row.update({f"cat:{k}": v for k, v in sorted(cats.items())})
        row.update(vuln_flags)
        rows.append(row)

        if status != "ok":
            print("--- STDOUT ---\n", out)
            print("--- STDERR ---\n", err)

    # Collect keys for CSV (consistent ordering)
    keys = ["url", "status", "seconds", "vulns_total", "error"] + \
           [f"cat:{c}" for c in KNOWN_CATS] + \
           [f"{c}_vulnerable" for c in KNOWN_CATS]

    # CSV
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)

    # Markdown table
    md_lines = []
    md_lines.append("| URL | Status | Seconds | Total Vulns | " +
                    " | ".join(f"{c}" for c in KNOWN_CATS) + " | " +
                    " | ".join(f"{c}_vuln" for c in KNOWN_CATS) + " | error |")
    md_lines.append("|---|---|---:|---:|" +
                    "|".join("---:" for _ in KNOWN_CATS) + "|" +
                    "|".join("---:" for _ in KNOWN_CATS) + "|---|")

    for r in rows:
        md_lines.append("| " + " | ".join(str(r.get(k, "")) for k in keys) + " |")

    OUT_MD.write_text("\n".join(md_lines))
    print(f"[✓] Wrote {OUT_CSV} and {OUT_MD}")

if __name__ == "__main__":
    main()
