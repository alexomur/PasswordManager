from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pwman  # noqa


def before_scenario(context, scenario):
    context.tmp_db = ROOT / ".bdd_db.json"
    if context.tmp_db.exists():
        context.tmp_db.unlink()
    context.master = None  # по умолчанию без мастера
    context.store = pwman.PasswordStore(pwman.JsonStorage(context.tmp_db))


def after_scenario(context, scenario):
    if getattr(context, "tmp_db", None) and context.tmp_db.exists():
        context.tmp_db.unlink()
