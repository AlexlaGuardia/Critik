"""Safe data-access + process patterns. Should NOT flag injection."""
import subprocess


def get_user(cursor, user_id):
    # Parameterized query — the safe pattern, not string concatenation.
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()


def search(cursor, term):
    cursor.execute("SELECT * FROM posts WHERE title LIKE %s", (f"%{term}%",))
    return cursor.fetchall()


def list_dir(path):
    # List form, shell=False (default) — no shell injection surface.
    return subprocess.run(["ls", "-la", path], capture_output=True, text=True)


def parse_config(raw):
    # Real parsing, not eval() of untrusted input.
    import json
    return json.loads(raw)
