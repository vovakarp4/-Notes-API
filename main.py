"""
Notes API — простое (и намеренно уязвимое) приложение для заметок.
Всё в одном файле. Просто вставь и запусти.
"""
import sqlite3
import hashlib
import subprocess
import sys
from flask import (
    Flask, request, jsonify, render_template_string,
    redirect, url_for, make_response, g
)

app = Flask(__name__)
DB = "notes.db"


# ============================================================
#  БАЗА ДАННЫХ
# ============================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            body TEXT
        );
    """)
    # Тестовые пользователи (только если их ещё нет)
    cur = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    if cur[0] == 0:
        md5 = lambda s: hashlib.md5(s.encode()).hexdigest()
        conn.executemany(
            "INSERT INTO users (login, password, is_admin) VALUES (?,?,?)",
            [("admin", md5("admin123"), 1),
             ("alice", md5("password"), 0),
             ("bob",   md5("qwerty"),   0)]
        )
        conn.executemany(
            "INSERT INTO notes (user_id, title, body) VALUES (?,?,?)",
            [(1, "Секретная заметка", "FLAG{sql_injection_master}"),
             (2, "Список покупок",    "Молоко, хлеб, яйца"),
             (2, "Пароль от Wi-Fi",   "SuperSecret123"),
             (3, "Идеи",              "Сделать свой пентест-стенд")]
        )
    conn.commit()
    conn.close()


# ============================================================
#  ОБЩИЙ HTML-КАРКАС
# ============================================================
def page(title, body, user=None):
    if user:
        nav = f"Привет, {user['login']} | <a href='/notes'>Мои заметки</a> | <a href='/logout'>Выйти</a>"
    else:
        nav = "<a href='/login'>Вход</a> | <a href='/register'>Регистрация</a>"
    return f"""
    <!doctype html><html><head><meta charset="utf-8">
    <title>{title}</title>
    <style>
      body {{ font-family: system-ui, sans-serif; max-width: 820px;
              margin: 0 auto; padding: 16px; background:#f7f7fa; color:#222; }}
      header {{ display:flex; justify-content:space-between; align-items:center;
                padding:12px 0; border-bottom:1px solid #ddd; margin-bottom:24px; }}
      a {{ color:#4a4af0; }}
      input, textarea, button {{ padding:8px 10px; font-size:1rem;
                border:1px solid #ccc; border-radius:6px; width:100%;
                box-sizing:border-box; margin-bottom:8px; }}
      button {{ background:#4a4af0; color:#fff; border:none; cursor:pointer; }}
      button:hover {{ background:#3737c9; }}
      .note {{ background:#fff; padding:12px 16px; margin-bottom:12px;
               border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,.08); }}
      .error {{ color:#c00; }}
      pre {{ background:#111; color:#0f0; padding:12px; border-radius:6px;
             overflow-x:auto; }}
      form {{ max-width:400px; }}
    </style></head><body>
    <header><a href="/" style="font-weight:700;text-decoration:none;color:#333;">📝 Notes</a>
    <nav>{nav}</nav></header>
    <main>{body}</main>
    </body></html>
    """


def current_user():
    uid = request.cookies.get("uid")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


# ============================================================
#  СТРАНИЦЫ
# ============================================================
@app.route("/")
def index():
    user = current_user()
    body = "<h1>Notes API</h1><p>Простое приложение для заметок.</p>"
    if user:
        body += "<p><a href='/notes'>Перейти к заметкам →</a></p>"
    else:
        body += "<p><a href='/login'>Войти</a> или <a href='/register'>зарегистрироваться</a>.</p>"
    body += """
    <h2>Диагностика (ping)</h2>
    <form action="/ping" method="get">
      <input name="host" value="127.0.0.1">
      <button>Ping</button>
    </form>
    """
    return page("Главная", body, user)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        login = request.form.get("login", "")
        password = request.form.get("password", "")
        pw = hashlib.md5(password.encode()).hexdigest()
        try:
            conn = get_db()
            conn.execute("INSERT INTO users (login,password) VALUES (?,?)", (login, pw))
            conn.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            error = "Логин занят"
    body = f"""
    <h1>Регистрация</h1>
    {f'<p class="error">{error}</p>' if error else ''}
    <form method="post">
      <input name="login" placeholder="Логин" required>
      <input name="password" type="password" placeholder="Пароль" required>
      <button>Создать аккаунт</button>
    </form>
    """
    return page("Регистрация", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        login = request.form.get("login", "")
        password = request.form.get("password", "")
        pw = hashlib.md5(password.encode()).hexdigest()
        # УЯЗВИМОСТЬ: SQL-инъекция (f-string)
        q = f"SELECT * FROM users WHERE login='{login}' AND password='{pw}'"
        try:
            user = get_db().execute(q).fetchone()
        except sqlite3.Error as e:
            error = f"SQL error: {e}"
            user = None
        if user:
            resp = make_response(redirect(url_for("notes_page")))
            resp.set_cookie("uid", str(user["id"]))
            return resp
        if not error:
            error = "Неверный логин или пароль"
    body = f"""
    <h1>Вход</h1>
    {f'<p class="error">{error}</p>' if error else ''}
    <form method="post">
      <input name="login" placeholder="Логин" required>
      <input name="password" type="password" placeholder="Пароль" required>
      <button>Войти</button>
    </form>
    <p>Тестовые: <b>alice / password</b>, <b>admin / admin123</b></p>
    """
    return page("Вход", body)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("uid")
    return resp


@app.route("/notes")
def notes_page():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    body = """
    <h1>Мои заметки</h1>
    <div id="notes">Загрузка...</div>
    <h2>Новая заметка</h2>
    <form id="new-note">
      <input id="title" placeholder="Заголовок" required>
      <textarea id="body" placeholder="Текст"></textarea>
      <button>Сохранить</button>
    </form>
    <script>
    async function load() {
      const r = await fetch('/api/notes');
      const data = await r.json();
      const box = document.getElementById('notes');
      box.innerHTML = '';
      data.forEach(n => {
        const d = document.createElement('div');
        d.className = 'note';
        d.innerHTML = `<h3>${n.title}</h3><p>${n.body}</p>
          <a href="/note/${n.id}">Открыть</a>
          <button onclick="del(${n.id})" style="width:auto;display:inline-block;">Удалить</button>`;
        box.appendChild(d);
      });
    }
    async function del(id) {
      await fetch('/api/notes/' + id, {method:'DELETE'});
      load();
    }
    document.getElementById('new-note').addEventListener('submit', async e => {
      e.preventDefault();
      await fetch('/api/notes', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          title: document.getElementById('title').value,
          body: document.getElementById('body').value
        })
      });
      document.getElementById('title').value = '';
      document.getElementById('body').value = '';
      load();
    });
    load();
    </script>
    """
    return page("Мои заметки", body, user)


@app.route("/note/<int:note_id>")
def note_view(note_id):
    # УЯЗВИМОСТЬ: нет проверки владельца (IDOR) + XSS (|safe)
    note = get_db().execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    if not note:
        return "Not found", 404
    return render_template_string("""
      <!doctype html><html><head><meta charset="utf-8">
      <title>{{ t }}</title></head><body style="font-family:sans-serif;max-width:820px;margin:0 auto;padding:16px;">
      <h1>{{ t }}</h1>
      <div>{{ b|safe }}</div>
      <p><a href="/notes">← Назад</a></p>
      </body></html>
    """, t=note["title"], b=note["body"])


@app.route("/render")
def render():
    # УЯЗВИМОСТЬ: SSTI
    tpl = request.args.get("tpl", "Hello! Попробуй ?tpl={{7*7}}")
    return render_template_string(tpl)


@app.route("/ping")
def ping():
    # УЯЗВИМОСТЬ: Command Injection
    host = request.args.get("host", "127.0.0.1")
    try:
        if sys.platform.startswith("win"):
            cmd = f"ping -n 1 {host}"
            encoding = "cp866"
        else:
            cmd = f"ping -c 1 {host}"
            encoding = "utf-8"
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=5
        ).decode(encoding, errors="replace")
    except subprocess.CalledProcessError as e:
        out = e.output.decode(encoding if 'encoding' in dir() else "utf-8", errors="replace")
    except Exception as e:
        out = str(e)
    return f"<pre>{out}</pre>"


# ============================================================
#  JSON API
# ============================================================
@app.route("/api/notes", methods=["GET"])
def api_notes():
    uid = request.cookies.get("uid")
    if not uid:
        return jsonify({"error": "unauthorized"}), 401
    # УЯЗВИМОСТЬ: SQL-инъекция через uid
    rows = get_db().execute(
        f"SELECT id, title, body FROM notes WHERE user_id={uid}"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/notes", methods=["POST"])
def api_note_create():
    uid = request.cookies.get("uid")
    if not uid:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    title = data.get("title", "Без названия")
    body = data.get("body", "")
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO notes (user_id, title, body) VALUES (?,?,?)",
        (uid, title, body)
    )
    conn.commit()
    return jsonify({"id": cur.lastrowid, "title": title, "body": body}), 201


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
def api_note_delete(note_id):
    uid = request.cookies.get("uid")
    if not uid:
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    conn.execute("DELETE FROM notes WHERE id=?", (note_id,))
    conn.commit()
    return jsonify({"ok": True})


@app.route("/api/users")
def api_users():
    # УЯЗВИМОСТЬ: утечка хешей
    rows = get_db().execute(
        "SELECT id, login, password, is_admin FROM users"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ============================================================
#  ЗАПУСК
# ============================================================
if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" Notes API запущен:  http://localhost:5000")
    print(" Пользователи: admin/admin123, alice/password, bob/qwerty")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)