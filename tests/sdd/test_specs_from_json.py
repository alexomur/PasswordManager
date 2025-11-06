from __future__ import annotations
import json
from pathlib import Path
import pwman
from tests.conftest import run_cli

SPECS_JSON = Path(__file__).resolve().parents[2] / "specs" / "password_cases.json"


def _load_cases(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = data.get("cases", [])
    # Нормализуем поля и типы
    norm = []
    for c in cases:
        norm.append({
            "case_id": c.get("case_id"),
            "action": (c.get("action") or "").strip(),
            "service": c.get("service") or "",
            "username": c.get("username") or "",
            "password": c.get("password") or "",
            "notes": c.get("notes") or "",
            "expect": (c.get("expect") or "").strip(),
            "exit": int(c.get("exit") if c.get("exit") is not None else pwman.EXIT_OK),
        })
    return norm


def test_specs_cli(tmp_db):
    for row in _load_cases(SPECS_JSON):
        case_id = row["case_id"]
        action  = row["action"]
        svc     = row["service"]
        user    = row["username"]
        pwd     = row["password"]
        notes   = row["notes"]
        expect  = row["expect"]
        exp_exit = row["exit"]

        if action == "add":
            args = ["add", svc]
            if user:
                args.append(user)
            if pwd:
                args += ["--password", pwd]
            if notes:
                args += ["--notes", notes]
            r = run_cli(args, tmp_db)
            assert r.returncode == exp_exit, f"case {case_id}: rc={r.returncode}, out={r.stdout}, err={r.stderr}"
            if expect == "ERROR_EXISTS":
                assert r.returncode == pwman.EXIT_EXISTS
            elif expect == "ERROR":
                assert r.returncode == pwman.EXIT_DATAERR

        elif action == "get":
            r = run_cli(["get", svc, user], tmp_db)
            assert r.returncode == exp_exit, f"case {case_id}: rc={r.returncode}, out={r.stdout}, err={r.stderr}"
            if exp_exit == pwman.EXIT_OK:
                assert r.stdout.strip() == expect
            elif expect == "ERROR_NOT_FOUND":
                assert r.returncode == pwman.EXIT_NOT_FOUND

        elif action == "list":
            r = run_cli(["list", "--service", svc], tmp_db)
            assert r.returncode == exp_exit, f"case {case_id}: rc={r.returncode}, out={r.stdout}, err={r.stderr}"
            if expect == "EMPTY":
                assert r.stdout.strip() == ""
            else:
                assert r.stdout.strip() == expect

        else:
            raise AssertionError(f"Unknown action in case {case_id}: {action}")
