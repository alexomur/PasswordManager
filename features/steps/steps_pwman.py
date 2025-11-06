from behave import given, when, then  # noqa


def _ensure_store(context):
    """
    Гарантирует, что context.store создан с учётом наличия master.
    Вызывается в шагах перед использованием store.
    """
    import pwman
    master = getattr(context, "master", None)
    if not hasattr(context, "store") or context.store is None:
        storage = pwman.JsonStorage(context.tmp_db, master=master) if master else pwman.JsonStorage(context.tmp_db)
        context.store = pwman.PasswordStore(storage)


@given('установлен мастер-пароль "{master}"')
def _(context, master):
    """
    Сначала создаём БД без мастера, устанавливаем мастер,
    затем пересоздаём store уже с мастером.
    """
    import pwman
    # init без мастер-доступа
    context.master = master
    tmp_store = pwman.PasswordStore(pwman.JsonStorage(context.tmp_db))
    tmp_store.init_master(master)
    # основной store с мастер-доступом
    context.store = pwman.PasswordStore(pwman.JsonStorage(context.tmp_db, master=master))


@given('сохранён пароль для сервиса "{service}" и логина "{username}" со значением "{password}"')
def _(context, service, username, password):
    import pwman
    _ensure_store(context)
    context.store.add(pwman.Entry(service=service, username=username, password=password))


@when('запрашиваю пароль для сервиса "{service}" и логина "{username}"')
def _(context, service, username):
    _ensure_store(context)
    context.result = context.store.get(service, username)


@when('запрашиваю пароль для сервиса "{service}" и логина "{username}" с мастер-паролем')
def _(context, service, username):
    _ensure_store(context)
    context.result = context.store.get(service, username)


@then('я получаю пароль "{password}"')
def _(context, password):
    assert context.result["password"] == password
