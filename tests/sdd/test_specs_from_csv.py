from __future__ import annotations
import csv
from pathlib import Path
import pwman
from tests.conftest import run_cli

SPECS = Path(__file__).resolve().parents[2] / "specs" / "password_cases.csv"


def _expected_exit_from_expect(expect: str) -> int:
    mapping = {
        "OK": pwman.EXIT_OK,
        "OK_SERVICE_ONLY": pwman.EXIT_OK,
        "EMPTY": pwman.EXIT_OK,
        "ERROR": pwman.EXIT_DATAERR,
        "ERROR_NOT_FOUND": pwman.EXIT_NOT_FOUND,
        "ERROR_EXISTS": pwman.EXIT_EXISTS,
    }
    return mapping.get(expect.strip(), pwman.EXIT_OK)


def _read_rows(path: Path):
    """Читаем CSV, игнорируя закомментированный заголовок и пустые строки.
    Используем csv.reader, чтобы быть устойчивыми к «лишним» пустым столбцам.
    """
    with path.open("r", encoding="utf-8") as f:
        lines = [ln for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    # Теперь обычный reader по «чистым» строкам
    for row in csv.reader(lines):
        # Ожидаемый формат: case_id, action, service, username, password, notes, expect, exit
        # Но в данных могут быть лишние пустые поля; берём ключевые по индексам/с хвоста.
        if len(row) < 4:
            # слишком короткая строка — пропустим
            continue
        case_id = (row[0] or "").strip()
        action = (row[1] or "").strip()
        service = (row[2] or "").strip()
        username = (row[3] or "").strip()
        password = (row[4] if len(row) > 4 else "") or ""
        notes = (row[5] if len(row) > 5 else "") or ""
        # expect берём как предпоследний столбец, независимо от лишних пустых значений
        expect = (row[-2] if len(row) >= 2 else "").strip()
        yield {
            "case_id": case_id,
            "action": action,
            "service": service,
            "username": username,
            "password": password,
            "notes": notes,
            "expect": expect,
        }


def test_specs_cli(tmp_db):
    for row in _read_rows(SPECS):
        case_id = row["case_id"]
        action = row["action"]
        svc = row["service"]
        user = row["username"]
        pwd = row["password"]
        notes = row["notes"]
        expect = row["expect"]
        exp_exit = _expected_exit_from_expect(expect)

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
            raise AssertionError(f"Unknown action: {action}")
