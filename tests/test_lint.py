import os
import sys

from snmpsim.commands.lint import main as lint_main

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def run_lint(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["snmpsim-lint-records"] + list(args))
    return lint_main()


def test_lint_reports_broken_and_repaired_records(monkeypatch, capsys):
    data_dir = os.path.join(BASE_DIR, "data", "short-oid")

    rc = run_lint(monkeypatch, data_dir)

    out = capsys.readouterr().out

    assert rc == 1
    assert "public.snmprec:5: WARNING: short OID value '0' is served as 0.0" in out
    assert "public.snmprec:6: ERROR" in out


def test_lint_accepts_valid_records(monkeypatch, capsys):
    data_dir = os.path.join(BASE_DIR, "data", "UPS")

    rc = run_lint(monkeypatch, data_dir)

    out = capsys.readouterr().out

    assert rc == 0
    assert "ERROR" not in out
    assert "WARNING" not in out


def test_lint_strict_fails_on_warnings(monkeypatch, capsys, tmp_path):
    data_file = tmp_path / "public.snmprec"
    data_file.write_text("1.3.6.1.2.1.47.1.1.1.1.3.1|6|0\n")

    assert run_lint(monkeypatch, str(data_file)) == 0
    assert run_lint(monkeypatch, "--strict", str(data_file)) == 1

    assert "WARNING" in capsys.readouterr().out


def test_lint_skips_variation_records(monkeypatch, capsys):
    data_dir = os.path.join(BASE_DIR, "data", "writecache")

    rc = run_lint(monkeypatch, data_dir)

    assert rc == 0
    assert "ERROR" not in capsys.readouterr().out
