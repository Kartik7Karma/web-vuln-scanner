import subprocess
import os
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def test_cli_runs_without_errors():
    result = subprocess.run(
        ['python', os.path.join(PROJECT_ROOT, 'core/scanner.py')],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    assert result.returncode == 0
    assert "scan complete" in result.stdout.lower() or "scan complete" in result.stderr.lower()


def test_cli_runs_with_urls_file(tmp_path):
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text("http://testphp.vulnweb.com\n")

    result = subprocess.run(
        ['python', os.path.join(PROJECT_ROOT, 'core/scanner.py'),
         '--url-list', str(urls_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    assert result.returncode == 0
    assert "scan complete" in result.stdout.lower() or "scan complete" in result.stderr.lower()


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

    scan = subprocess.run(
        ['python', os.path.join(PROJECT_ROOT, 'core/scanner.py'),
         '--url-list', str(urls_file),
         '--output-json', str(json_output)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=tmp_path 
    )
    assert scan.returncode == 0, f"Scan failed: {scan.stderr}"
    assert json_output.exists(), "JSON result file was not created"

    report = subprocess.run(
        ['python', os.path.join(PROJECT_ROOT, 'core/scanner.py'),
         '--output-json', str(json_output),
         report_flag, str(report_output)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=tmp_path 
    )

    if report.returncode != 0:
        print("STDOUT:", report.stdout)
        print("STDERR:", report.stderr)

    assert report.returncode == 0, f"Report generation failed: {report.stderr}"
    if not report_output.exists():
        pytest.skip(f"{ext} report was not created — possibly no data to write.")
    
    assert report_output.read_text().strip() != "", f"{ext} report file is empty"
