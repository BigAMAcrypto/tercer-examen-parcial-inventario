import csv
import io
import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cambia-esta-clave-en-produccion")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inventario.db")
ROLES = ("administrador", "gerente", "tecnico")

SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  usuario TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  rol TEXT NOT NULL CHECK(rol IN ('administrador','gerente','tecnico'))
);
CREATE TABLE IF NOT EXISTS piezas(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  codigo TEXT NOT NULL UNIQUE,
  nombre TEXT NOT NULL,
  categoria TEXT NOT NULL,
  cantidad INTEGER NOT NULL DEFAULT 0 CHECK(cantidad >= 0),
  minimo INTEGER NOT NULL DEFAULT 5,
  ubicacion TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS solicitudes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pieza_id INTEGER NOT NULL REFERENCES piezas(id) ON DELETE CASCADE,
  tecnico_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  cantidad INTEGER NOT NULL CHECK(cantidad > 0),
  motivo TEXT NOT NULL,
  estado TEXT NOT NULL DEFAULT 'pendiente',
  fecha TEXT NOT NULL,
  gerente_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  fecha_resolucion TEXT
);
CREATE TABLE IF NOT EXISTS movimientos(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pieza_id INTEGER NOT NULL REFERENCES piezas(id) ON DELETE CASCADE,
  tipo TEXT NOT NULL CHECK(tipo IN ('entrada','salida')),
  cantidad INTEGER NOT NULL,
  usuario_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
  motivo TEXT,
  fecha TEXT NOT NULL
);
"""

PIEZAS = [
    ("RB-001", "Rodamiento rígido 6204", "Rodamientos", 40, 10, "A-01"),
    ("RB-002", "Rodamiento cónico 30206", "Rodamientos", 8, 10, "A-02"),
    ("RB-003", "Rodamiento axial 51105", "Rodamientos", 0, 5, "A-03"),
    ("BN-001", "Banda trapezoidal B-52", "Bandas", 25, 8, "B-01"),
    ("BN-002", "Banda dentada HTD 8M", "Bandas", 6, 8, "B-02"),
    ("FL-001", "Filtro de aceite hidráulico", "Filtros", 30, 10, "C-01"),
    ("FL-002", "Filtro de aire industrial", "Filtros", 12, 6, "C-02"),
    ("FL-003", "Filtro de combustible", "Filtros", 4, 6, "C-03"),
    ("SL-001", "Sello mecánico 1.5\"", "Sellos", 15, 5, "D-01"),
    ("SL-002", "Oring NBR 50x3", "Sellos", 200, 50, "D-02"),
    ("SL-003", "Retén de aceite 35x52x7", "Sellos", 3, 10, "D-03"),
    ("EL-001", "Contactor 3P 25A", "Eléctrico", 10, 4, "E-01"),
    ("EL-002", "Relevador térmico 9-13A", "Eléctrico", 7, 4, "E-02"),
    ("EL-003", "Sensor inductivo M18", "Eléctrico", 18, 5, "E-03"),
    ("EL-004", "Variador de frecuencia 5HP", "Eléctrico", 2, 2, "E-04"),
    ("HD-001", "Manguera hidráulica 1/2\"", "Hidráulica", 50, 15, "F-01"),
    ("HD-002", "Válvula solenoide 24V", "Hidráulica", 9, 4, "F-02"),
    ("HD-003", "Bomba de engranes", "Hidráulica", 1, 2, "F-03"),
    ("TR-001", "Tornillo hexagonal M12x50", "Tornillería", 500, 100, "G-01"),
    ("TR-002", "Tuerca de seguridad M12", "Tornillería", 450, 100, "G-02"),
    ("LB-001", "Grasa industrial EP2 (cubeta)", "Lubricantes", 14, 5, "H-01"),
    ("LB-002", "Aceite hidráulico ISO 68 (20 L)", "Lubricantes", 0, 4, "H-02"),
]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        for nombre, user, pw, rol in [
            ("Ana Administradora", "admin", "admin123", "administrador"),
            ("Gabriel Gerente", "gerente", "gerente123", "gerente"),
            ("Tomás Técnico", "tecnico", "tecnico123", "tecnico"),
            ("Teresa Técnica", "tecnico2", "tecnico123", "tecnico"),
        ]:
            conn.execute("INSERT INTO usuarios(nombre,usuario,password_hash,rol) VALUES(?,?,?,?)",
                         (nombre, user, generate_password_hash(pw), rol))
        for p in PIEZAS:
            cur = conn.execute("INSERT INTO piezas(codigo,nombre,categoria,cantidad,minimo,ubicacion) "
                               "VALUES(?,?,?,?,?,?)", p)
            if p[3] > 0:
                conn.execute("INSERT INTO movimientos(pieza_id,tipo,cantidad,usuario_id,motivo,fecha) "
                             "VALUES(?,?,?,?,?,?)", (cur.lastrowid, "entrada", p[3], 1, "Inventario inicial", now()))
    conn.commit()
    conn.close()


def login_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if "uid" not in session:
                return redirect(url_for("login"))
            if roles and session["rol"] not in roles:
                abort(403)
            return f(*a, **k)
        return wrapper
    return deco


def entero(valor, minimo=0):
    try:
        n = int(valor)
    except (TypeError, ValueError):
        return None
    return n if n >= minimo else None


# ---------- Autenticación ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM usuarios WHERE usuario=?",
                         (request.form.get("usuario", "").strip(),)).fetchone()
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            session.clear()
            session.update(uid=u["id"], nombre=u["nombre"], rol=u["rol"])
            return redirect(url_for("dashboard"))
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- Dashboard ----------
@app.route("/")
@login_required()
def dashboard():
    d = db()
    q = lambda sql, *p: d.execute(sql, p).fetchone()[0]
    stats = {
        "piezas": q("SELECT COUNT(*) FROM piezas"),
        "unidades": q("SELECT COALESCE(SUM(cantidad),0) FROM piezas"),
        "agotadas": q("SELECT COUNT(*) FROM piezas WHERE cantidad=0"),
        "bajas": q("SELECT COUNT(*) FROM piezas WHERE cantidad>0 AND cantidad<=minimo"),
    }
    if session["rol"] == "tecnico":
        stats["pendientes"] = q("SELECT COUNT(*) FROM solicitudes WHERE estado='pendiente' AND tecnico_id=?",
                                session["uid"])
    else:
        stats["pendientes"] = q("SELECT COUNT(*) FROM solicitudes WHERE estado='pendiente'")
    alertas = d.execute("SELECT * FROM piezas WHERE cantidad<=minimo ORDER BY cantidad, nombre").fetchall()
    movs = d.execute("""SELECT m.*, p.codigo, p.nombre, u.nombre AS usuario FROM movimientos m
                        JOIN piezas p ON p.id=m.pieza_id LEFT JOIN usuarios u ON u.id=m.usuario_id
                        ORDER BY m.id DESC LIMIT 8""").fetchall()
    return render_template("dashboard.html", stats=stats, alertas=alertas, movs=movs)


# ---------- Piezas ----------
@app.route("/piezas")
@login_required()
def piezas():
    q = request.args.get("q", "").strip()
    cat = request.args.get("categoria", "")
    sql, params = "SELECT * FROM piezas WHERE (codigo LIKE ? OR nombre LIKE ? OR ubicacion LIKE ?)", [f"%{q}%"] * 3
    if cat:
        sql += " AND categoria=?"
        params.append(cat)
    lista = db().execute(sql + " ORDER BY codigo", params).fetchall()
    cats = [r[0] for r in db().execute("SELECT DISTINCT categoria FROM piezas ORDER BY 1")]
    return render_template("piezas.html", piezas=lista, q=q, cat=cat, cats=cats)


def _datos_pieza():
    f = request.form
    datos = dict(codigo=f.get("codigo", "").strip().upper(), nombre=f.get("nombre", "").strip(),
                 categoria=f.get("categoria", "").strip(), ubicacion=f.get("ubicacion", "").strip(),
                 cantidad=entero(f.get("cantidad")), minimo=entero(f.get("minimo")))
    if not all([datos["codigo"], datos["nombre"], datos["categoria"], datos["ubicacion"]]) \
            or datos["cantidad"] is None or datos["minimo"] is None:
        return None
    return datos


@app.route("/piezas/nueva", methods=["GET", "POST"])
@login_required("administrador")
def pieza_nueva():
    if request.method == "POST":
        p = _datos_pieza()
        if not p:
            flash("Completa todos los campos con valores válidos.", "error")
            return render_template("pieza_form.html", p=request.form, nueva=True)
        try:
            cur = db().execute("INSERT INTO piezas(codigo,nombre,categoria,cantidad,minimo,ubicacion) "
                               "VALUES(:codigo,:nombre,:categoria,:cantidad,:minimo,:ubicacion)", p)
        except sqlite3.IntegrityError:
            flash("Ya existe una pieza con ese código.", "error")
            return render_template("pieza_form.html", p=request.form, nueva=True)
        if p["cantidad"] > 0:
            db().execute("INSERT INTO movimientos(pieza_id,tipo,cantidad,usuario_id,motivo,fecha) VALUES(?,?,?,?,?,?)",
                         (cur.lastrowid, "entrada", p["cantidad"], session["uid"], "Alta de pieza", now()))
        db().commit()
        flash("Pieza registrada.", "ok")
        return redirect(url_for("piezas"))
    return render_template("pieza_form.html", p={}, nueva=True)


@app.route("/piezas/<int:pid>/editar", methods=["GET", "POST"])
@login_required("administrador")
def pieza_editar(pid):
    actual = db().execute("SELECT * FROM piezas WHERE id=?", (pid,)).fetchone() or abort(404)
    if request.method == "POST":
        p = _datos_pieza()
        if not p:
            flash("Completa todos los campos con valores válidos.", "error")
            return render_template("pieza_form.html", p=request.form, nueva=False, pid=pid)
        try:
            db().execute("UPDATE piezas SET codigo=:codigo,nombre=:nombre,categoria=:categoria,"
                         "cantidad=:cantidad,minimo=:minimo,ubicacion=:ubicacion WHERE id=%d" % pid, p)
        except sqlite3.IntegrityError:
            flash("Ya existe una pieza con ese código.", "error")
            return render_template("pieza_form.html", p=request.form, nueva=False, pid=pid)
        dif = p["cantidad"] - actual["cantidad"]
        if dif:
            db().execute("INSERT INTO movimientos(pieza_id,tipo,cantidad,usuario_id,motivo,fecha) VALUES(?,?,?,?,?,?)",
                         (pid, "entrada" if dif > 0 else "salida", abs(dif), session["uid"], "Ajuste manual", now()))
        db().commit()
        flash("Pieza actualizada.", "ok")
        return redirect(url_for("piezas"))
    return render_template("pieza_form.html", p=actual, nueva=False, pid=pid)


@app.route("/piezas/<int:pid>/entrada", methods=["POST"])
@login_required("administrador")
def pieza_entrada(pid):
    n = entero(request.form.get("cantidad"), 1)
    if n is None:
        flash("Cantidad inválida.", "error")
    else:
        db().execute("UPDATE piezas SET cantidad=cantidad+? WHERE id=?", (n, pid))
        db().execute("INSERT INTO movimientos(pieza_id,tipo,cantidad,usuario_id,motivo,fecha) VALUES(?,?,?,?,?,?)",
                     (pid, "entrada", n, session["uid"], request.form.get("motivo") or "Reabastecimiento", now()))
        db().commit()
        flash("Entrada registrada.", "ok")
    return redirect(url_for("piezas"))


@app.route("/piezas/<int:pid>/eliminar", methods=["POST"])
@login_required("administrador")
def pieza_eliminar(pid):
    db().execute("DELETE FROM piezas WHERE id=?", (pid,))
    db().commit()
    flash("Pieza eliminada.", "ok")
    return redirect(url_for("piezas"))


# ---------- Usuarios ----------
@app.route("/usuarios")
@login_required("administrador")
def usuarios():
    return render_template("usuarios.html", usuarios=db().execute("SELECT * FROM usuarios ORDER BY rol, nombre").fetchall())


@app.route("/usuarios/nuevo", methods=["GET", "POST"])
@app.route("/usuarios/<int:uid>/editar", methods=["GET", "POST"])
@login_required("administrador")
def usuario_form(uid=None):
    u = db().execute("SELECT * FROM usuarios WHERE id=?", (uid,)).fetchone() if uid else None
    if uid and not u:
        abort(404)
    if request.method == "POST":
        f = request.form
        nombre, user, pw, rol = f.get("nombre", "").strip(), f.get("usuario", "").strip(), f.get("password", ""), f.get("rol")
        if not nombre or not user or rol not in ROLES or (not u and len(pw) < 6) or (pw and len(pw) < 6):
            flash("Datos inválidos (la contraseña debe tener al menos 6 caracteres).", "error")
            return render_template("usuario_form.html", u=f, editando=bool(u))
        try:
            if u:
                db().execute("UPDATE usuarios SET nombre=?,usuario=?,rol=? WHERE id=?", (nombre, user, rol, uid))
                if pw:
                    db().execute("UPDATE usuarios SET password_hash=? WHERE id=?", (generate_password_hash(pw), uid))
            else:
                db().execute("INSERT INTO usuarios(nombre,usuario,password_hash,rol) VALUES(?,?,?,?)",
                             (nombre, user, generate_password_hash(pw), rol))
            db().commit()
        except sqlite3.IntegrityError:
            flash("Ese nombre de usuario ya existe.", "error")
            return render_template("usuario_form.html", u=f, editando=bool(u))
        flash("Usuario guardado.", "ok")
        return redirect(url_for("usuarios"))
    return render_template("usuario_form.html", u=u or {}, editando=bool(u))


@app.route("/usuarios/<int:uid>/eliminar", methods=["POST"])
@login_required("administrador")
def usuario_eliminar(uid):
    if uid == session["uid"]:
        flash("No puedes eliminar tu propia cuenta.", "error")
    else:
        db().execute("DELETE FROM usuarios WHERE id=?", (uid,))
        db().commit()
        flash("Usuario eliminado.", "ok")
    return redirect(url_for("usuarios"))


# ---------- Solicitudes ----------
@app.route("/solicitudes")
@login_required("tecnico", "gerente")
def solicitudes():
    sql = """SELECT s.*, p.codigo, p.nombre AS pieza, p.cantidad AS stock, t.nombre AS tecnico, g.nombre AS gerente
             FROM solicitudes s JOIN piezas p ON p.id=s.pieza_id JOIN usuarios t ON t.id=s.tecnico_id
             LEFT JOIN usuarios g ON g.id=s.gerente_id"""
    params = []
    if session["rol"] == "tecnico":
        sql += " WHERE s.tecnico_id=?"
        params.append(session["uid"])
    lista = db().execute(sql + " ORDER BY (s.estado='pendiente') DESC, s.id DESC", params).fetchall()
    return render_template("solicitudes.html", solicitudes=lista)


@app.route("/solicitudes/nueva", methods=["GET", "POST"])
@login_required("tecnico")
def solicitud_nueva():
    disponibles = db().execute("SELECT * FROM piezas WHERE cantidad>0 ORDER BY nombre").fetchall()
    if request.method == "POST":
        pieza = db().execute("SELECT * FROM piezas WHERE id=?", (request.form.get("pieza_id"),)).fetchone()
        n = entero(request.form.get("cantidad"), 1)
        motivo = request.form.get("motivo", "").strip()
        if not pieza or n is None or not motivo:
            flash("Completa todos los campos.", "error")
        elif n > pieza["cantidad"]:
            flash(f"Solo hay {pieza['cantidad']} unidades disponibles.", "error")
        else:
            db().execute("INSERT INTO solicitudes(pieza_id,tecnico_id,cantidad,motivo,fecha) VALUES(?,?,?,?,?)",
                         (pieza["id"], session["uid"], n, motivo, now()))
            db().commit()
            flash("Solicitud enviada al gerente.", "ok")
            return redirect(url_for("solicitudes"))
    return render_template("solicitud_nueva.html", piezas=disponibles, sel=request.args.get("pieza", type=int))


@app.route("/solicitudes/<int:sid>/resolver", methods=["POST"])
@login_required("gerente")
def solicitud_resolver(sid):
    d = db()
    s = d.execute("SELECT * FROM solicitudes WHERE id=?", (sid,)).fetchone() or abort(404)
    accion = request.form.get("accion")
    if s["estado"] != "pendiente":
        flash("Esa solicitud ya fue resuelta.", "error")
    elif accion == "aprobar":
        pieza = d.execute("SELECT * FROM piezas WHERE id=?", (s["pieza_id"],)).fetchone()
        if pieza["cantidad"] < s["cantidad"]:
            flash(f"Existencias insuficientes ({pieza['cantidad']} disponibles).", "error")
        else:
            d.execute("UPDATE piezas SET cantidad=cantidad-? WHERE id=?", (s["cantidad"], s["pieza_id"]))
            d.execute("UPDATE solicitudes SET estado='aprobada',gerente_id=?,fecha_resolucion=? WHERE id=?",
                      (session["uid"], now(), sid))
            d.execute("INSERT INTO movimientos(pieza_id,tipo,cantidad,usuario_id,motivo,fecha) VALUES(?,?,?,?,?,?)",
                      (s["pieza_id"], "salida", s["cantidad"], s["tecnico_id"], f"Solicitud #{sid}", now()))
            d.commit()
            flash("Solicitud aprobada y existencias actualizadas.", "ok")
    elif accion == "rechazar":
        d.execute("UPDATE solicitudes SET estado='rechazada',gerente_id=?,fecha_resolucion=? WHERE id=?",
                  (session["uid"], now(), sid))
        d.commit()
        flash("Solicitud rechazada.", "ok")
    return redirect(url_for("solicitudes"))


# ---------- Movimientos y reportes ----------
def _movimientos(tipo=""):
    sql = """SELECT m.*, p.codigo, p.nombre, u.nombre AS usuario FROM movimientos m
             JOIN piezas p ON p.id=m.pieza_id LEFT JOIN usuarios u ON u.id=m.usuario_id"""
    params = []
    if tipo in ("entrada", "salida"):
        sql += " WHERE m.tipo=?"
        params.append(tipo)
    return db().execute(sql + " ORDER BY m.id DESC", params).fetchall()


@app.route("/movimientos")
@login_required("administrador", "gerente")
def movimientos():
    tipo = request.args.get("tipo", "")
    return render_template("movimientos.html", movs=_movimientos(tipo), tipo=tipo)


@app.route("/reportes")
@login_required("administrador", "gerente")
def reportes():
    d = db()
    por_cat = d.execute("SELECT categoria, COUNT(*) piezas, SUM(cantidad) unidades FROM piezas "
                        "GROUP BY categoria ORDER BY unidades DESC").fetchall()
    top = d.execute("""SELECT p.codigo, p.nombre, SUM(m.cantidad) total FROM movimientos m
                       JOIN piezas p ON p.id=m.pieza_id WHERE m.tipo='salida'
                       GROUP BY p.id ORDER BY total DESC LIMIT 5""").fetchall()
    resumen = d.execute("SELECT estado, COUNT(*) n FROM solicitudes GROUP BY estado").fetchall()
    criticas = d.execute("SELECT * FROM piezas WHERE cantidad<=minimo ORDER BY cantidad").fetchall()
    return render_template("reportes.html", por_cat=por_cat, top=top, resumen=resumen, criticas=criticas)


def _csv(nombre, cabecera, filas):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cabecera)
    w.writerows(filas)
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={nombre}"})


@app.route("/reportes/inventario.csv")
@login_required("administrador", "gerente")
def csv_inventario():
    filas = db().execute("SELECT codigo,nombre,categoria,cantidad,minimo,ubicacion FROM piezas ORDER BY codigo").fetchall()
    return _csv("inventario.csv", ["Código", "Nombre", "Categoría", "Cantidad", "Mínimo", "Ubicación"], filas)


@app.route("/reportes/movimientos.csv")
@login_required("administrador", "gerente")
def csv_movimientos():
    filas = [(m["fecha"], m["codigo"], m["nombre"], m["tipo"], m["cantidad"], m["usuario"], m["motivo"])
             for m in _movimientos()]
    return _csv("movimientos.csv", ["Fecha", "Código", "Pieza", "Tipo", "Cantidad", "Usuario", "Motivo"], filas)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
