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
