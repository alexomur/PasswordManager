import pwman
from tests.conftest import run_cli


def test_cli_add_get(tmp_db):
    r1 = run_cli(["add", "test_service", "test_login", "--password", "test_password"], tmp_db)
    assert r1.returncode == pwman.EXIT_OK, r1.stderr
    r2 = run_cli(["get", "test_service", "test_login"], tmp_db)
    assert r2.returncode == pwman.EXIT_OK
    assert r2.stdout.strip() == "test_password"


def test_cli_service_only_and_list(tmp_db):
    r1 = run_cli(["add", "news"], tmp_db)
    assert r1.returncode == pwman.EXIT_OK
    r2 = run_cli(["list", "--service", "news"], tmp_db)
    assert r2.returncode == pwman.EXIT_OK
    assert r2.stdout.strip() == ""  # EMPTY


def test_cli_validation_and_duplicates(tmp_db):
    r_bad = run_cli(["add", "bad service", "u", "--password", "p"], tmp_db)
    assert r_bad.returncode == pwman.EXIT_DATAERR

    r_ok = run_cli(["add", "svc", "u", "--password", "p"], tmp_db)
    assert r_ok.returncode == pwman.EXIT_OK
    r_dup = run_cli(["add", "svc", "u", "--password", "p"], tmp_db)
    assert r_dup.returncode == pwman.EXIT_EXISTS
