"""Execute the bundled synthetic login investigation in an in-memory database."""
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def investigate():
    with sqlite3.connect(':memory:') as db:
        db.row_factory = sqlite3.Row
        db.executescript((ROOT / 'schema.sql').read_text())
        return [dict(row) for row in db.execute((ROOT / 'query.sql').read_text())]

if __name__ == '__main__':
    print(json.dumps(investigate(), indent=2))
