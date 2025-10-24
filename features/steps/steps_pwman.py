from __future__ import annotations
from behave import given, when, then  # noqa


@given('сохранён пароль для сервиса "{service}" и логина "{username}" со значением "{password}"')
def _(context, service, username, password):
    import pwman
    context.store.add(pwman.Entry(service=service, username=username, password=password))


@when('запрашиваю пароль для сервиса "{service}" и логина "{username}"')
def _(context, service, username):
    context.result = context.store.get(service, username)


@then('я получаю пароль "{password}"')
def _(context, password):
    assert context.result["password"] == password
