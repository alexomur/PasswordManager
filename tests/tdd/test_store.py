from __future__ import annotations
import pytest
import pwman


def test_add_and_get(store):
    store.add(pwman.Entry(service="test_service", username="test_login", password="test_password"))
    got = store.get("test_service", "test_login")
    assert got["password"] == "test_password"


def test_duplicate(store):
    store.add(pwman.Entry(service="svc", username="u", password="p"))
    with pytest.raises(pwman.EntryExistsError):
        store.add(pwman.Entry(service="svc", username="u", password="p2"))


def test_not_found(store):
    with pytest.raises(pwman.EntryNotFoundError):
        store.get("unknown", "u")


def test_service_validation(store):
    with pytest.raises(pwman.ValidationError):
        store.add(pwman.Entry(service="bad service", username="", password=""))

def test_master_init_and_access(tmp_path):
    db = tmp_path / "db.json"

    # Инициализируем БД и ставим мастер-пароль
    store = pwman.PasswordStore(pwman.JsonStorage(db))
    store.init_master("secret")

    # Без мастера доступ запрещён
    with pytest.raises(pwman.StorageAccessError):
        pwman.PasswordStore(pwman.JsonStorage(db)).list()

    # С неверным мастером тоже
    with pytest.raises(pwman.StorageAccessError):
        pwman.PasswordStore(pwman.JsonStorage(db, master="wrong")).list()

    # С верным мастером всё работает
    s2 = pwman.PasswordStore(pwman.JsonStorage(db, master="secret"))
    s2.add(pwman.Entry("svc", "u", "p"))
    assert s2.get("svc", "u")["password"] == "p"
