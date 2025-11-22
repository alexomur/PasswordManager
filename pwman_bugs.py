import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Dict, Any, Optional, Callable, List
import math  # BUG_FOR_LAB: неиспользуемый импорт

# -------------------- Коды выхода --------------------
EXIT_OK = 0
EXIT_USAGE = 64
EXIT_DATAERR = 65
EXIT_IOERR = 74
EXIT_NOT_FOUND = 2
EXIT_EXISTS = 17

DB_VERSION = 2

# -------------------- ИСКУССТВЕННЫЕ ОШИБКИ ДЛЯ ЛАБЫ --------------------
# 1) Захардкоженный пароль
HARDCODED_PASSWORD = "SuperSecret123"  # BUG_FOR_LAB: hardcoded password

# 2) Конфликт типов + неиспользуемая переменная
def _debug_add_ints(a: int, b: int) -> int:
    return a + b

debug_str: str = _debug_add_ints(1, 2)  # BUG_FOR_LAB: несовместимый тип (int -> str)

# 3) Небезопасный eval
def _debug_eval(expr: str) -> Any:  # BUG_FOR_LAB: использование eval
    return eval(expr)

# 4) Небезопасный mktemp
def _insecure_tempfile() -> str:  # BUG_FOR_LAB: использование tempfile.mktemp()
    return tempfile.mktemp()

_LEAK_BUCKET: List[bytes] = []  # BUG_FOR_LAB: глобальное хранилище, никогда не очищается

def run_leak_demo(iterations: int = 100) -> None:
    """
    BUG_FOR_LAB: искусственная утечка памяти.
    На каждой итерации добавляем ~100 KB в глобальный список и немного ждём.
    """
    import time
    for i in range(iterations):
        _LEAK_BUCKET.append(b"x" * 100_000)  # +~100 KB на шаг
        time.sleep(0.05)  # всего ~5 секунд работы
    print("done!")

def cmd_leak_demo(args: argparse.Namespace) -> None:
    """Команда для лабораторной работы: запускает сценарий с утечкой памяти."""
    run_leak_demo()

# -------------------- Ошибки --------------------
class PwmanError(Exception): ...
class EntryExistsError(PwmanError): ...
class EntryNotFoundError(PwmanError): ...
class StorageAccessError(PwmanError): ...
class DataFormatError(PwmanError): ...
class ValidationError(PwmanError): ...

# -------------------- Валидация --------------------
_SERVICE_RE = re.compile(r"^[^\s/\\]+$")  # без пробелов и / \

def validate_service(service: str) -> str:
    s = (service or "").strip()
    if not s:
        raise ValidationError("service не должен быть пустым")
    # BUG_FOR_LAB: ошибка в валидации — пропускаем проверку формата service
    # (разрешаем пробелы и недопустимые символы)
    # if not _SERVICE_RE.match(s):
    #     raise ValidationError("service содержит пробелы или слэши")
    return s

def validate_username(u: str) -> str:
    return (u or "").strip()

def validate_password(p: str) -> str:
    return (p or "")

def validate_notes(n: str) -> str:
    return (n or "")

# -------------------- Путь БД по умолчанию (рядом со скриптом) --------------------
def default_db_path() -> Path:
    env = os.environ.get("PWMAN_DB")
    if env:
        p = Path(env).expanduser()
        if p.is_dir() or env.endswith(os.sep):
            return p / "db.json"
        return p
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
    else:
        base = Path(__file__).resolve().parent
    return base / "db.json"

# -------------------- Модель --------------------
@dataclass
class Entry:
    service: str
    username: str
    password: str
    notes: str = ""
    updated_at: str = ""  # ISO8601 UTC

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

# -------------------- Мастер-пароль (НЕ шифрование, только проверка доступа) --------------------
def _mk_master_hash(master: str) -> Dict[str, str]:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + (master or "")).encode("utf-8")).hexdigest()
    return {"salt": salt, "hash": h}

def _check_master(master: str, rec: Dict[str, str]) -> bool:
    salt = rec.get("salt", "")
    expected = rec.get("hash", "")
    got = hashlib.sha256((salt + (master or "")).encode("utf-8")).hexdigest()
    return secrets.compare_digest(got, expected)

# -------------------- Общие утилиты --------------------
def _ensure_version(data: Dict[str, Any]) -> None:
    """Гарантируем актуальную версию при записи."""
    if isinstance(data, dict):
        data["version"] = DB_VERSION

def _prompt_secret(prompt_hidden: str, prompt_visible: str) -> str:
    """
    Безопасный ввод с фоллбеком:
      - пробуем getpass();
      - если терминал не поддерживает скрытый ввод или EOF — падаем на input().
    """
    try:
        val = getpass(prompt_hidden)
        # Если вдруг в редких окружениях getpass «повис» без эха — пользователь всё равно введёт и нажмёт Enter
        return val
    except (Exception, KeyboardInterrupt, EOFError):
        # Фоллбек (видимый ввод)
        try:
            return input(prompt_visible)
        except (KeyboardInterrupt, EOFError):
            return ""

# -------------------- Хранилище --------------------
class JsonStorage:
    """Работа с JSON-файлом. Если в БД установлен master, то при доступе требуется верный master."""

    def __init__(self, path: Path, master: Optional[str] = None) -> None:
        self.path = Path(path)
        self.master = master

    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": DB_VERSION, "services": {}}
        try:
            with self.path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise DataFormatError(f"Ошибка чтения JSON: {e}") from e
        except OSError as e:
            raise StorageAccessError(f"Ошибка доступа к БД: {e}") from e

        if not isinstance(data, dict) or "services" not in data:
            raise DataFormatError("Неверный формат базы паролей")

        # Проверка мастера, если он есть
        meta = data.get("meta", {})
        master_rec = meta.get("master")
        if master_rec:
            if self.master is None:
                raise StorageAccessError("Требуется мастер-пароль")
            if not _check_master(self.master, master_rec):
                raise StorageAccessError("Неверный мастер-пароль")
        return data

    def save(self, data: Dict[str, Any]) -> None:
        try:
            _ensure_version(data)
            self._atomic_write_json(data)
        except OSError as e:
            raise StorageAccessError(f"Ошибка записи БД: {e}") from e

    def _ensure_parent_dir(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _atomic_write_json(self, data: Dict[str, Any]) -> None:
        self._ensure_parent_dir()
        tmp_fd, tmp_name = tempfile.mkstemp(prefix="pwman_", suffix=".json", dir=str(self.path.parent))
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp_name, self.path)
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.remove(tmp_name)
            except OSError:
                pass

# -------------------- Домен --------------------
class PasswordStore:
    def __init__(self, storage: JsonStorage) -> None:
        self.storage = storage

    # ---- мастер-пароль ----
    def init_master(self, master: str) -> None:
        """Устанавливает мастер-пароль, если он ещё не установлен."""
        data = self.storage.load()
        meta = data.setdefault("meta", {})
        if meta.get("master"):
            raise ValidationError("Мастер-пароль уже установлен")
        meta["master"] = _mk_master_hash(master)
        _ensure_version(data)
        self.storage.save(data)

    # ---- CRUD ----
    def add(self, e: Entry, overwrite: bool = False) -> None:
        e.service = validate_service(e.service)
        e.username = validate_username(e.username)
        e.password = validate_password(e.password)
        e.notes = validate_notes(e.notes)

        data = self.storage.load()
        services = data.setdefault("services", {})

        # «Только сервис»: username/password/notes пустые
        if e.username == "" and e.password == "" and e.notes == "":
            services.setdefault(e.service, {})
            _ensure_version(data)
            self.storage.save(data)
            return

        service_map: Dict[str, Dict[str, Any]] = services.setdefault(e.service, {})
        # BUG_FOR_LAB: дубликаты не считаем ошибкой — молча перезаписываем запись
        # if not overwrite and e.username in service_map:
        #     raise EntryExistsError(f"{e.service}/{e.username}")
        e.updated_at = Entry.now_iso()
        service_map[e.username] = asdict(e)
        _ensure_version(data)
        self.storage.save(data)

    def ensure_service(self, service: str) -> None:
        s = validate_service(service)
        data = self.storage.load()
        data.setdefault("services", {}).setdefault(s, {})
        _ensure_version(data)
        self.storage.save(data)

    def get(self, service: str, username: str) -> Dict[str, Any]:
        service = validate_service(service)
        username = validate_username(username)
        data = self.storage.load()
        entry = data.get("services", {}).get(service, {}).get(username)
        # BUG_FOR_LAB: вместо ошибки при отсутствии записи возвращаем пустой словарь
        if not entry:
            return {}
        return entry

    def update(self, service: str, username: str, *, password: Optional[str] = None, notes: Optional[str] = None) -> None:
        service = validate_service(service)
        username = validate_username(username)
        data = self.storage.load()
        services = data.get("services", {})
        if service not in services or username not in services[service]:
            raise EntryNotFoundError(f"{service}/{username}")
        entry = services[service][username]
        if password is not None:
            entry["password"] = validate_password(password)
        if notes is not None:
            entry["notes"] = validate_notes(notes)
        entry["updated_at"] = Entry.now_iso()
        _ensure_version(data)
        self.storage.save(data)

    def delete(self, service: str, username: str) -> None:
        service = validate_service(service)
        username = validate_username(username)
        data = self.storage.load()
        services = data.get("services", {})
        if service not in services or username not in services[service]:
            raise EntryNotFoundError(f"{service}/{username}")
        del services[service][username]
        if not services[service]:
            del services[service]
        _ensure_version(data)
        self.storage.save(data)

    def list(self, service: Optional[str] = None) -> List[str]:
        data = self.storage.load()
        services = data.get("services", {})
        if service:
            s = validate_service(service)
            return sorted(services.get(s, {}).keys())
        res: List[str] = []
        for svc in sorted(services):
            for user in sorted(services[svc]):
                res.append(f"{svc}/{user}")
        return res

# -------------------- Ввод секретов --------------------
def read_password(args: argparse.Namespace, *, prompt_hidden: str = "Пароль: ", prompt_plain: str = "Пароль (видимый): ") -> str:
    if getattr(args, "password", None):
        return args.password
    if getattr(args, "password_stdin", False):
        return sys.stdin.read().rstrip("\n")
    if getattr(args, "password_input", False):
        return input(prompt_plain)
    return _prompt_secret(prompt_hidden, prompt_plain)

# -------------------- Команды CLI --------------------
def cmd_add(args: argparse.Namespace) -> None:
    store = PasswordStore(JsonStorage(args.db))
    username = (args.username or "").strip()
    notes = args.notes or ""
    service_only = (username == "") and (not args.password) and (not args.password_stdin) and (not args.password_input) and (notes == "")
    if service_only:
        store.ensure_service(args.service)
        print(f"OK: создан пустой сервис '{validate_service(args.service)}'")
        return
    pwd = read_password(args)
    e = Entry(service=args.service, username=username, password=pwd, notes=notes)
    store.add(e, overwrite=args.overwrite)
    print(f"OK: сохранено {validate_service(args.service)}/{username}")

def cmd_get(args: argparse.Namespace) -> None:
    store = PasswordStore(JsonStorage(args.db))
    entry = store.get(args.service, args.username)
    if args.show:
        print(json.dumps(entry, ensure_ascii=False, indent=2))
    else:
        print(entry["password"])

def cmd_update(args: argparse.Namespace) -> None:
    store = PasswordStore(JsonStorage(args.db))
    new_pwd: Optional[str] = None
    if args.password is not None or args.password_stdin or args.ask_password or args.password_input:
        if args.password is not None:
            new_pwd = args.password
        elif args.password_stdin:
            new_pwd = sys.stdin.read().rstrip("\n")
        elif args.password_input:
            new_pwd = input("Новый пароль (видимый): ")
        else:
            new_pwd = _prompt_secret("Новый пароль: ", "Новый пароль (видимый): ")
    store.update(args.service, args.username, password=new_pwd, notes=args.notes)
    print(f"OK: обновлено {validate_service(args.service)}/{args.username}")

def cmd_delete(args: argparse.Namespace) -> None:
    store = PasswordStore(JsonStorage(args.db))
    store.delete(args.service, args.username)
    print(f"OK: удалено {validate_service(args.service)}/{args.username}")

def cmd_list(args: argparse.Namespace) -> None:
    store = PasswordStore(JsonStorage(args.db))
    if args.service:
        users = store.list(args.service)
        for u in users:
            print(u)
        return
    items = store.list()
    for item in items:
        print(item)

# -------------------- Wizard (input). При запуске без аргументов — бесконечный цикл. --------------------
def cmd_wizard(args: argparse.Namespace, *, inp: Callable[[str], str] = input, out: Callable[[str], None] = print) -> bool:
    """
    Интерактивный режим. Команды:
      add / get / update / delete / list / init-master / exit
    """
    storage = JsonStorage(args.db)  # без мастера; если потребуется — спросим
    store = PasswordStore(storage)

    out("Выберите операцию: add / get / update / delete / list / init-master / exit")
    try:
        op = inp("> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        out("Выход.")
        return False

    if op in ("exit", "quit", "q"):
        out("Выход.")
        return False

    try:
        if op == "init-master":
            # Если мастер уже установлен, load() без master выбросит ошибку доступа — считаем, что уже стоит
            try:
                data = storage.load()
                if data.get("meta", {}).get("master"):
                    out("ОШИБКА: мастер-пароль уже установлен")
                    return True
            except StorageAccessError:
                out("ОШИБКА: мастер-пароль уже установлен")
                return True

            m1 = _prompt_secret("Новый мастер-пароль: ", "Новый мастер-пароль (видимый): ")
            if m1 == "":
                out("ОШИБКА: пустой мастер-пароль")
                return True
            m2 = _prompt_secret("Повторите мастер-пароль: ", "Повторите мастер-пароль (видимый): ")
            if m1 != m2:
                out("ОШИБКА: пароли не совпадают")
                return True
            PasswordStore(JsonStorage(args.db)).init_master(m1)
            out("OK: мастер-пароль установлен")
            return True

        elif op == "add":
            service = inp("Сервис: ").strip()
            username = inp("Логин (можно пусто): ").strip()
            if username == "":
                try:
                    store.ensure_service(service)
                except StorageAccessError:
                    m = _prompt_secret("Мастер-пароль: ", "Мастер-пароль (видимый): ")
                    store = PasswordStore(JsonStorage(args.db, master=m))
                    store.ensure_service(service)
                out(f"OK: создан пустой сервис '{validate_service(service)}'")
                return True
            password = inp("Пароль (видимый): ")
            notes = inp("Примечания (необязательно): ")
            try:
                store.add(Entry(service, username, password, notes))
            except StorageAccessError:
                m = _prompt_secret("Мастер-пароль: ", "Мастер-пароль (видимый): ")
                store = PasswordStore(JsonStorage(args.db, master=m))
                store.add(Entry(service, username, password, notes))
            out(f"OK: сохранено {validate_service(service)}/{username}")

        elif op == "get":
            service = inp("Сервис: ").strip()
            username = inp("Логин: ").strip()
            try:
                out(store.get(service, username)["password"])
            except StorageAccessError:
                m = _prompt_secret("Мастер-пароль: ", "Мастер-пароль (видимый): ")
                store = PasswordStore(JsonStorage(args.db, master=m))
                out(store.get(service, username)["password"])

        elif op == "update":
            service = inp("Сервис: ").strip()
            username = inp("Логин: ").strip()
            new_pwd = inp("Новый пароль (пусто — без изменения): ")
            new_notes = inp("Новые примечания (пусто — без изменения): ")
            try:
                store.update(
                    service,
                    username,
                    password=(new_pwd if new_pwd else None),
                    notes=(new_notes if new_notes else None),
                )
            except StorageAccessError:
                m = _prompt_secret("Мастер-пароль: ", "Мастер-пароль (видимый): ")
                store = PasswordStore(JsonStorage(args.db, master=m))
                store.update(
                    service,
                    username,
                    password=(new_pwd if new_pwd else None),
                    notes=(new_notes if new_notes else None),
                )
            out(f"OK: обновлено {validate_service(service)}/{username}")

        elif op == "delete":
            service = inp("Сервис: ").strip()
            username = inp("Логин: ").strip()
            try:
                store.delete(service, username)
            except StorageAccessError:
                m = _prompt_secret("Мастер-пароль: ", "Мастер-пароль (видимый): ")
                store = PasswordStore(JsonStorage(args.db, master=m))
                store.delete(service, username)
            out(f"OK: удалено {validate_service(service)}/{username}")

        elif op == "list":
            svc = inp("Сервис (пусто — все): ").strip()
            try:
                items = store.list(svc or None)
            except StorageAccessError:
                m = _prompt_secret("Мастер-пароль: ", "Мастер-пароль (видимый): ")
                store = PasswordStore(JsonStorage(args.db, master=m))
                items = store.list(svc or None)
            for it in items:
                out(it)

        else:
            out("Неизвестная операция")
    except (ValidationError, EntryExistsError, EntryNotFoundError, StorageAccessError, DataFormatError) as e:
        out(f"ОШИБКА: {e}")
    return True

# -------------------- Аргументы --------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Простой локальный менеджер паролей (JSON)")
    p.add_argument(
        "--db",
        type=Path,
        default=default_db_path(),
        help="Путь к JSON-базе (по умолчанию рядом со скриптом/EXE).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("add", help="Создать запись: add <service> [username]")
    pa.add_argument("service")
    pa.add_argument("username", nargs="?", default="")
    pa.add_argument("--notes", default="", help="Примечания")
    pa.add_argument("--password", help="Пароль в аргументе")
    pa.add_argument("--password-stdin", action="store_true", help="Читать пароль из STDIN")
    pa.add_argument("--password-input", action="store_true", help="Спросить пароль через input()")
    pa.add_argument("--overwrite", action="store_true", help="Перезаписать существующую запись")
    pa.set_defaults(func=cmd_add)

    pg = sub.add_parser("get", help="Извлечь: get <service> <username>")
    pg.add_argument("service")
    pg.add_argument("username")
    pg.add_argument("--show", action="store_true", help="Показать всю запись JSON")
    pg.set_defaults(func=cmd_get)

    pu = sub.add_parser(
        "update",
        help="Обновить: update <service> <username> [--password ...] [--notes ...]",
    )
    pu.add_argument("service")
    pu.add_argument("username")
    pu.add_argument("--password", help="Новый пароль")
    pu.add_argument("--password-stdin", action="store_true", help="Новый пароль из STDIN")
    pu.add_argument("--password-input", action="store_true", help="Новый пароль через input()")
    pu.add_argument("--ask-password", action="store_true", help="Спросить новый пароль скрыто (getpass)")
    pu.add_argument("--notes", help="Новые примечания (полная замена)")
    pu.set_defaults(func=cmd_update)

    pd = sub.add_parser("delete", help="Удалить: delete <service> <username>")
    pd.add_argument("service")
    pd.add_argument("username")
    pd.set_defaults(func=cmd_delete)

    pl = sub.add_parser("list", help="Список записей")
    pl.add_argument("--service", help="Только логины указанного сервиса")
    pl.set_defaults(func=cmd_list)

    pw = sub.add_parser("wizard", help="Интерактивный режим (input())")
    pw.set_defaults(func=cmd_wizard)

    plk = sub.add_parser("leak-demo", help="ДЕМО: искусственная утечка памяти для mprof")
    plk.set_defaults(func=cmd_leak_demo)

    return p

# -------------------- main --------------------
def _reorder_global_db(argv: list[str]) -> list[str]:
    """Переносит '--db PATH' (или '--db=PATH') в начало, чтобы оно работало даже если указано после подкоманды."""
    if not argv:
        return argv
    db_path = None
    rest: list[str] = []
    skip = 0
    for i, a in enumerate(argv):
        if skip:
            skip -= 1
            continue
        if a == "--db" and i + 1 < len(argv):
            db_path = argv[i + 1]
            skip = 1
            continue
        if a.startswith("--db="):
            db_path = a.split("=", 1)[1]
            continue
        rest.append(a)
    if db_path is not None:
        return ["--db", db_path, *rest]
    return argv

def main(argv: Optional[list[str]] = None) -> int:
    raw_argv = argv if argv is not None else sys.argv[1:]
    # если без аргументов — бесконечный wizard с пунктом init-master
    if len(raw_argv) == 0:
        args = argparse.Namespace(db=default_db_path())
        try:
            while True:
                if not cmd_wizard(args):
                    break
            return EXIT_OK
        except KeyboardInterrupt:
            return 130

    parser = build_parser()
    reordered = _reorder_global_db(list(raw_argv))
    try:
        args = parser.parse_args(reordered)
        _ = args.func(args)
        return EXIT_OK
    except EntryExistsError as e:
        print(f"Ошибка: запись уже существует: {e}", file=sys.stderr)
        return EXIT_EXISTS
    except EntryNotFoundError as e:
        print(f"Ошибка: нет записи: {e}", file=sys.stderr)
        return EXIT_NOT_FOUND
    except (ValidationError, DataFormatError) as e:
        print(f"Ошибка данных: {e}", file=sys.stderr)
        return EXIT_DATAERR
    except StorageAccessError as e:
        print(f"Ошибка доступа к хранилищу: {e}", file=sys.stderr)
        return EXIT_IOERR
    except KeyboardInterrupt:
        return 130
    except SystemExit as e:
        try:
            return int(e.code) if e.code is not None else EXIT_USAGE
        except Exception:
            return EXIT_USAGE

if __name__ == "__main__":
    raise SystemExit(main())
