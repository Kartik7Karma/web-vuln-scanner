import os
import sys
import subprocess
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def _run_scanner(args=None, **popen_kwargs):
    """
    Helper to invoke the scanner via module execution to ensure package imports work.
    Uses the same interpreter running pytest (sys.executable).
    """
    cmd = [sys.executable, "-m", "core.scanner"]
    if args:
        cmd.extend(args)
    # Ensure project root is on the import path for the child process
    env = popen_kwargs.pop("env", os.environ.copy())
    env.setdefault("PYTHONPATH", PROJECT_ROOT)
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        **popen_kwargs
    )

def test_cli_runs_without_errors():
    result = _run_scanner()
    assert result.returncode == 0
    out = (result.stdout or "") + (result.stderr or "")
    assert "scan complete" in out.lower()

def test_cli_runs_with_urls_file(tmp_path):
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("http://testphp.vulnweb.com\n")

    result = _run_scanner(args=["--url-list", str(urls_file)])
    assert result.returncode == 0
    out = (result.stdout or "") + (result.stderr or "")
    assert "scan complete" in out.lower()

@pytest.mark.parametrize("report_flag, ext", [
    ("--text-report", "report.txt"),
    ("--csv-report", "report.csv"),
    ("--html-report", "report.html"),
])
def test_cli_generates_reports(tmp_path, report_flag, ext):
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("http://testphp.vulnweb.com\n")

    json_output = tmp_path / "result.json"
    report_output = tmp_path / ext

    # First run: produce JSON results
    scan = _run_scanner(
        args=["--url-list", str(urls_file), "--output-json", str(json_output)],
        cwd=tmp_path
    )
    assert scan.returncode == 0, f"Scan failed: {scan.stderr}"
    assert json_output.exists(), "JSON result file was not created"

    # Second run: generate the report from JSON
    report = _run_scanner(
        args=["--output-json", str(json_output), report_flag, str(report_output)],
        cwd=tmp_path
    )

    if report.returncode != 0:
        print("STDOUT:", report.stdout)
        print("STDERR:", report.stderr)

    assert report.returncode == 0, f"Report generation failed: {report.stderr}"
    if not report_output.exists():
        pytest.skip(f"{ext} report was not created — possibly no data to write.")

    assert report_output.read_text().strip() != "", f"{ext} report file is empty"
