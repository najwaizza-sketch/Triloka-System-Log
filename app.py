# Layanan login Lab Terisolasi - CYB-04 (Flask + SQLite)
import sqlite3, math
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, g
from werkzeug.security import generate_password_hash, check_password_hash

# ===== Pengaturan aturan (hasil analisis keamanan vs kemudahan) =====
BATAS_GAGAL = 3       # kunci jika gagal LEBIH DARI 3 kali
JENDELA_MENIT = 10     # ...dalam 10 menit terakhir
KUNCI_MENIT = 10       # lama akun dikunci
# ===== Jaringan lab =====
HOST = "127.0.0.1"     # GANTI ke IP jaringan lab (jangan 0.0.0.0)
PORT = 5000

DB = "database.db"
FMT = "%Y-%m-%d %H:%M:%S"
app = Flask(__name__)
app.secret_key = "ganti-kunci-ini-di-lab"

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def tutup(e):
    d = g.pop("db", None)
    if d:
        d.close()

def sekarang():
    return datetime.now().strftime(FMT)

def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE,
        password TEXT, role TEXT, locked_until TEXT, reset_at TEXT);
    CREATE TABLE IF NOT EXISTS login_log(id INTEGER PRIMARY KEY, waktu TEXT,
        username TEXT, ip TEXT, hasil TEXT);
    CREATE TABLE IF NOT EXISTS notifikasi(id INTEGER PRIMARY KEY, waktu TEXT,
        username TEXT, pesan TEXT);
    """)
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        akun = [("mhs00%d" % i, "mhs00%dpass" % i, "mahasiswa") for i in range(1, 6)]
        akun += [("asisten01", "asisten01pass", "asisten"), ("admin01", "admin01pass", "admin")]
        for u, p, r in akun:
            c.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                      (u, generate_password_hash(p), r))
    c.commit()
    c.close()

def catat(username, ip, hasil):
    db().execute("INSERT INTO login_log(waktu,username,ip,hasil) VALUES(?,?,?,?)",
                 (sekarang(), username, ip, hasil))
    db().commit()

def hitung_gagal(username, reset_at):
    awal = (datetime.now() - timedelta(minutes=JENDELA_MENIT)).strftime(FMT)
    r = db().execute("SELECT MAX(waktu) m FROM login_log WHERE username=? AND hasil='sukses'",
                     (username,)).fetchone()
    for batas in (r["m"], reset_at):      # login sukses / buka kunci manual mereset hitungan
        if batas and batas > awal:
            awal = batas
    return db().execute("SELECT COUNT(*) c FROM login_log WHERE username=? AND hasil='gagal' AND waktu>?",
                        (username, awal)).fetchone()["c"]

def sisa_menit(locked_until):
    detik = (datetime.strptime(locked_until, FMT) - datetime.now()).total_seconds()
    return max(1, math.ceil(detik / 60))

@app.route("/", methods=["GET", "POST"])
def login():
    pesan = None
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        ip = request.remote_addr
        user = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if user and user["locked_until"] and sekarang() < user["locked_until"]:
            catat(u, ip, "terkunci")      # respons memengaruhi autentikasi
            pesan = "Akun terkunci sementara, coba lagi dalam %d menit." % sisa_menit(user["locked_until"])
        elif user and check_password_hash(user["password"], p):
            catat(u, ip, "sukses")
            session["user"], session["role"] = u, user["role"]
            return redirect("/dashboard")
        else:
            catat(u, ip, "gagal")
            if user and hitung_gagal(u, user["reset_at"]) > BATAS_GAGAL:
                sampai = (datetime.now() + timedelta(minutes=KUNCI_MENIT)).strftime(FMT)
                db().execute("UPDATE users SET locked_until=? WHERE username=?", (sampai, u))
                db().execute("INSERT INTO notifikasi(waktu,username,pesan) VALUES(?,?,?)",
                             (sekarang(), u, "Akun %s dikunci %d menit: gagal login lebih dari %d kali dalam %d menit (IP %s)."
                              % (u, KUNCI_MENIT, BATAS_GAGAL, JENDELA_MENIT, ip)))
                db().commit()
                pesan = "Akun terkunci sementara, coba lagi dalam %d menit." % KUNCI_MENIT
            else:
                pesan = "Username atau password salah."
    return render_template("login.html", pesan=pesan)

@app.route("/dashboard")
def dashboard():
    return redirect("/" + session["role"]) if "role" in session else redirect("/")

@app.route("/mahasiswa")
def mahasiswa():
    if session.get("role") != "mahasiswa":
        return redirect("/")
    return render_template("mahasiswa.html", user=session["user"])

@app.route("/asisten")
def asisten():
    if session.get("role") != "asisten":
        return redirect("/")
    rows = db().execute("SELECT username, role, locked_until FROM users ORDER BY id").fetchall()
    now = sekarang()
    akun = [(r["username"], r["role"], "terkunci" if r["locked_until"] and now < r["locked_until"] else "aktif") for r in rows]
    return render_template("asisten.html", user=session["user"], akun=akun)

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return redirect("/")
    log = db().execute("SELECT * FROM login_log ORDER BY id DESC LIMIT 50").fetchall()
    notif = db().execute("SELECT * FROM notifikasi ORDER BY id DESC LIMIT 20").fetchall()
    now = sekarang()
    terkunci = [r["username"] for r in db().execute("SELECT username, locked_until FROM users").fetchall()
                if r["locked_until"] and now < r["locked_until"]]
    return render_template("admin.html", user=session["user"], log=log, notif=notif, terkunci=terkunci)

@app.route("/admin/buka/<username>", methods=["POST"])
def buka(username):
    if session.get("role") == "admin":
        db().execute("UPDATE users SET locked_until=NULL, reset_at=? WHERE username=?", (sekarang(), username))
        db().commit()
    return redirect("/admin")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(host=HOST, port=PORT, debug=False)
