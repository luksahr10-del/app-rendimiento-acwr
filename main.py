"""
App de monitoreo de rendimiento físico — Club de básquet semipro (v3, PostgreSQL).

Migrada de SQLite a PostgreSQL (Supabase). Los datos ahora viven en la nube.

Requisitos previos:
  1. Tener un archivo .env en esta carpeta con:
         DATABASE_URL=postgresql://usuario:password@host:puerto/postgres
     (la cadena "URI" que copiaste de Supabase → Project Settings → Database)
  2. pip install -r requirements.txt

Corré con:  uvicorn main:app --reload --host 0.0.0.0 --port 8000
  - Jugador:    http://<tu-ip>:8000/
  - Entrenador: http://<tu-ip>:8000/panel     (PIN por defecto: 1234)
  - Admin:      http://<tu-ip>:8000/admin      (mismo PIN)

------------------------------------------------------------------------------
QUÉ CAMBIÓ RESPECTO A SQLITE (para que entiendas la migración):
  * Ya no usamos el módulo sqlite3 ni el archivo datos.db; usamos psycopg (Postgres).
  * La conexión sale de DATABASE_URL leída del .env (nunca escrita en el código).
  * Usamos un POOL de conexiones: abrir una conexión nueva a un Postgres remoto
    por cada consulta es lento y agota el límite de Supabase. El pool las reutiliza.
  * Los marcadores de parámetros cambian de  ?  (SQLite)  a  %s  (Postgres).
  * AUTOINCREMENT  ->  SERIAL  (forma de Postgres de generar IDs).
  * El error de nombre duplicado ahora es psycopg.errors.UniqueViolation.
  * ON CONFLICT ... DO UPDATE (el "upsert") funciona igual: nació en Postgres.
------------------------------------------------------------------------------
"""

import csv
import html
import io
import os
import secrets
from datetime import date, datetime
from pathlib import Path
from urllib.parse import quote

import bcrypt
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from dotenv import load_dotenv

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from metrics import acwr_de, carga, readiness

# ---------------------------------------------------------------------------
# Configuración: credenciales desde .env (NUNCA en el código)
# ---------------------------------------------------------------------------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "Falta DATABASE_URL. Creá un archivo .env en esta carpeta con:\n"
        "    DATABASE_URL=postgresql://usuario:password@host:puerto/postgres"
    )

PIN_ENTRENADOR = os.getenv("PIN_ENTRENADOR", "1234")  # también puede ir en el .env

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "Falta SECRET_KEY (firma las cookies de sesión de los jugadores).\n"
        "Generá una y agregala al .env, por ejemplo con:\n"
        '    python -c "import secrets; print(secrets.token_hex(32))"'
    )

# Pool de conexiones. prepare_threshold=None desactiva los "prepared statements",
# necesario para ser compatible con el pooler de Supabase (modo transacción).
pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=1,
    max_size=5,
    kwargs={"row_factory": dict_row, "prepare_threshold": None},
    open=False,
)
pool.open()

# En Render (HTTPS) la cookie de sesión va con el flag Secure. Para probar
# local por http, poné SECURE_COOKIES=false en el .env de tu máquina.
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "true").lower() != "false"

app = FastAPI(title="Monitoreo Rendimiento")
app.add_middleware(
    SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=SECURE_COOKIES
)

# Carpeta para archivos estáticos (el escudo del club va acá como escudo.png).
# Se crea sola si no existe, así el montaje nunca falla al arrancar.
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def conn():
    """Pide una conexión prestada al pool. Se devuelve sola al salir del `with`."""
    return pool.connection()


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def check_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())


def generar_csrf(request: Request) -> str:
    """Token anti-CSRF ligado a la sesión: uno por navegador, se reusa entre GETs."""
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["csrf"] = tok
    return tok


def csrf_valido(request: Request, token: str) -> bool:
    return secrets.compare_digest(request.session.get("csrf", ""), token or "")


# ===========================================================================
#  BASE DE DATOS
# ===========================================================================
def init_db():
    with conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS jugadores (
                id SERIAL PRIMARY KEY,
                nombre TEXT UNIQUE NOT NULL,
                posicion TEXT DEFAULT '',
                activo INTEGER NOT NULL DEFAULT 1
            )
        """)
        # Cuenta propia por jugador: email + contraseña (hash bcrypt).
        c.execute("ALTER TABLE jugadores ADD COLUMN IF NOT EXISTS email TEXT UNIQUE")
        c.execute("ALTER TABLE jugadores ADD COLUMN IF NOT EXISTS password_hash TEXT")
        c.execute("""
            CREATE TABLE IF NOT EXISTS registros (
                id SERIAL PRIMARY KEY,
                jugador_id INTEGER NOT NULL REFERENCES jugadores (id),
                fecha TEXT NOT NULL,
                entreno INTEGER NOT NULL,
                rpe INTEGER,
                minutos INTEGER,
                fatiga INTEGER,
                sueno REAL,
                comida TEXT,
                rutina_ok INTEGER,
                molestias TEXT,
                creado TEXT NOT NULL,
                UNIQUE (jugador_id, fecha)
            )
        """)


init_db()


def jugador_logueado(request: Request):
    """Devuelve la fila del jugador logueado según la cookie de sesión, o None."""
    jid = request.session.get("jugador_id")
    if not jid:
        return None
    with conn() as c:
        return c.execute(
            "SELECT * FROM jugadores WHERE id=%s AND activo=1", (jid,)
        ).fetchone()


# ===========================================================================
#  MÉTRICAS (ciencias del deporte) — ver metrics.py (carga, readiness, acwr_de)
# ===========================================================================
def datos_jugador(jid):
    """Junta registros + métricas derivadas de un jugador."""
    with conn() as c:
        j = c.execute("SELECT * FROM jugadores WHERE id=%s", (jid,)).fetchone()
        if not j:
            return None
        regs = c.execute(
            "SELECT * FROM registros WHERE jugador_id=%s ORDER BY fecha", (jid,)
        ).fetchall()

    cargas_por_fecha = {}
    serie = []
    for r in regs:
        cg = carga(r["rpe"], r["minutos"])
        cargas_por_fecha[r["fecha"]] = cargas_por_fecha.get(r["fecha"], 0) + cg
        serie.append({
            "fecha": r["fecha"], "carga": cg, "rpe": r["rpe"],
            "fatiga": r["fatiga"], "sueno": r["sueno"],
            "readiness": readiness(r["sueno"], r["fatiga"], r["molestias"]),
            "rutina_ok": r["rutina_ok"], "molestias": r["molestias"],
        })

    hoy = date.today()
    acwr = acwr_de(cargas_por_fecha, hoy) if cargas_por_fecha else None

    alertas = []
    ult = serie[-5:]
    if len(ult) >= 3 and all(x["fatiga"] and x["fatiga"] >= 4 for x in ult[-3:]):
        alertas.append("Fatiga alta 3+ días seguidos: considerar descarga.")
    if acwr is not None and acwr > 1.5:
        alertas.append(f"ACWR {acwr} en zona de riesgo (>1.5): pico de carga.")
    if acwr is not None and acwr < 0.8:
        alertas.append(f"ACWR {acwr} bajo (<0.8): posible desentrenamiento.")
    if ult and ult[-1]["readiness"] is not None and ult[-1]["readiness"] < 50:
        alertas.append("Disponibilidad baja hoy (<50).")

    return {
        "jugador": dict(j),
        "serie": serie,
        "acwr": acwr,
        "readiness_actual": serie[-1]["readiness"] if serie else None,
        "alertas": alertas,
    }


# ===========================================================================
#  RUTAS — JUGADOR
# ===========================================================================
@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def formulario(request: Request):
    if request.method == "HEAD":
        return HTMLResponse("")
    j = jugador_logueado(request)
    if not j:
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse(
        PAGINA_JUGADOR.replace("{{NOMBRE}}", j["nombre"])
        .replace("{{HOY}}", date.today().isoformat())
        .replace("{{CSRF}}", generar_csrf(request))
    )


@app.post("/registrar")
def registrar(
    request: Request,
    csrf_token: str = Form(...),
    fecha: str = Form(...),
    entreno: int = Form(...),
    rpe: int = Form(0),
    minutos: int = Form(0),
    fatiga: int = Form(3),
    sueno: float = Form(0),
    comida: str = Form(""),
    rutina_ok: int = Form(0),
    molestias: str = Form(""),
):
    j = jugador_logueado(request)
    if not j:
        return RedirectResponse("/login", status_code=303)
    if not csrf_valido(request, csrf_token):
        return HTMLResponse("Sesión expirada. Volvé a cargar la página e intentá de nuevo.", status_code=403)
    with conn() as c:
        # Upsert: un registro por jugador por día (si repite, actualiza)
        c.execute(
            """INSERT INTO registros
               (jugador_id, fecha, entreno, rpe, minutos, fatiga, sueno, comida,
                rutina_ok, molestias, creado)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (jugador_id, fecha) DO UPDATE SET
                 entreno=EXCLUDED.entreno, rpe=EXCLUDED.rpe, minutos=EXCLUDED.minutos,
                 fatiga=EXCLUDED.fatiga, sueno=EXCLUDED.sueno, comida=EXCLUDED.comida,
                 rutina_ok=EXCLUDED.rutina_ok, molestias=EXCLUDED.molestias,
                 creado=EXCLUDED.creado""",
            (j["id"], fecha, entreno, rpe, minutos, fatiga, sueno, comida,
             rutina_ok, molestias, datetime.now().isoformat(timespec="seconds")),
        )
    r = readiness(sueno, fatiga, molestias)
    return HTMLResponse(PAGINA_OK.replace("{{READY}}", str(r)))


# ===========================================================================
#  RUTAS — CUENTA DEL JUGADOR (registro / login / logout)
# ===========================================================================
@app.get("/registro", response_class=HTMLResponse)
def registro_form(request: Request, error: str = ""):
    msg = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return HTMLResponse(
        PAGINA_REGISTRO.replace("{{ERROR}}", msg).replace("{{CSRF}}", generar_csrf(request))
    )


@app.post("/registro")
def registro(
    request: Request,
    csrf_token: str = Form(...),
    nombre: str = Form(...),
    posicion: str = Form(""),
    email: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
):
    if not csrf_valido(request, csrf_token):
        return HTMLResponse("Sesión expirada. Volvé a cargar la página e intentá de nuevo.", status_code=403)
    nombre = nombre.strip()
    email = email.strip().lower()
    if not nombre or "@" not in email:
        return RedirectResponse(
            "/registro?error=" + quote("Completá tu nombre y un email válido."), status_code=303
        )
    if len(password) < 6:
        return RedirectResponse(
            "/registro?error=" + quote("La contraseña debe tener al menos 6 caracteres."), status_code=303
        )
    if password != password2:
        return RedirectResponse(
            "/registro?error=" + quote("Las contraseñas no coinciden."), status_code=303
        )
    try:
        with conn() as c:
            fila = c.execute(
                """INSERT INTO jugadores (nombre, posicion, email, password_hash)
                   VALUES (%s,%s,%s,%s) RETURNING id""",
                (nombre, posicion.strip(), email, hash_password(password)),
            ).fetchone()
    except psycopg.errors.UniqueViolation:
        return RedirectResponse(
            "/registro?error=" + quote("Ya existe una cuenta con ese nombre o email."), status_code=303
        )
    request.session["jugador_id"] = fila["id"]
    return RedirectResponse("/", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str = ""):
    msg = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return HTMLResponse(
        PAGINA_LOGIN.replace("{{ERROR}}", msg).replace("{{CSRF}}", generar_csrf(request))
    )


@app.post("/login")
def login(request: Request, csrf_token: str = Form(...), email: str = Form(...), password: str = Form(...)):
    if not csrf_valido(request, csrf_token):
        return RedirectResponse("/login?error=" + quote("Sesión expirada, probá de nuevo."), status_code=303)
    email = email.strip().lower()
    with conn() as c:
        j = c.execute("SELECT * FROM jugadores WHERE email=%s AND activo=1", (email,)).fetchone()
    if not j or not j["password_hash"] or not check_password(password, j["password_hash"]):
        return RedirectResponse("/login?error=" + quote("Email o contraseña incorrectos."), status_code=303)
    request.session["jugador_id"] = j["id"]
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ===========================================================================
#  RUTAS — ENTRENADOR / PANEL
# ===========================================================================
@app.get("/panel", response_class=HTMLResponse)
def panel(pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return HTMLResponse(PAGINA_PIN)
    return PAGINA_PANEL


@app.get("/jugador/{jid}", response_class=HTMLResponse)
def ficha(jid: int, pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return HTMLResponse(PAGINA_PIN)
    return PAGINA_FICHA


@app.get("/api/datos")
def api_datos(pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    with conn() as c:
        jugadores = c.execute("SELECT * FROM jugadores ORDER BY nombre").fetchall()
    resumen = []
    for j in jugadores:
        d = datos_jugador(j["id"])
        if not d:
            continue
        serie = d["serie"]
        hoy = date.today().isoformat()
        carga_hoy = sum(x["carga"] for x in serie if x["fecha"] == hoy)
        resumen.append({
            "id": j["id"], "nombre": j["nombre"], "posicion": j["posicion"],
            "activo": j["activo"],
            "acwr": d["acwr"], "readiness": d["readiness_actual"],
            "carga_hoy": carga_hoy,
            "ultimo": serie[-1]["fecha"] if serie else None,
            "alertas": d["alertas"],
            "n_registros": len(serie),
        })
    return {"jugadores": resumen}


@app.get("/api/jugador/{jid}")
def api_jugador(jid: int, pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    d = datos_jugador(jid)
    if not d:
        return JSONResponse({"error": "No existe"}, status_code=404)
    return d


@app.get("/api/export.csv")
def export_csv(pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    with conn() as c:
        filas = c.execute("""
            SELECT j.nombre, j.posicion, r.*
            FROM registros r JOIN jugadores j ON j.id = r.jugador_id
            ORDER BY r.fecha, j.nombre
        """).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["nombre", "posicion", "fecha", "entreno", "rpe", "minutos",
                "carga", "fatiga", "sueno", "readiness", "rutina_ok",
                "molestias", "comida"])
    for f in filas:
        w.writerow([f["nombre"], f["posicion"], f["fecha"], f["entreno"],
                    f["rpe"], f["minutos"], carga(f["rpe"], f["minutos"]),
                    f["fatiga"], f["sueno"],
                    readiness(f["sueno"], f["fatiga"], f["molestias"]),
                    f["rutina_ok"], f["molestias"], f["comida"]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=rendimiento.csv"},
    )


# ===========================================================================
#  RUTAS — ADMIN DE JUGADORES
# ===========================================================================
@app.get("/admin", response_class=HTMLResponse)
def admin(pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return HTMLResponse(PAGINA_PIN)
    return PAGINA_ADMIN


@app.get("/api/jugadores")
def api_jugadores(pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    with conn() as c:
        js = c.execute("SELECT * FROM jugadores ORDER BY nombre").fetchall()
    return {"jugadores": [dict(j) for j in js]}


@app.post("/admin/agregar")
def admin_agregar(pin: str = Form(...), nombre: str = Form(...), posicion: str = Form("")):
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    nombre = nombre.strip()
    if not nombre:
        return JSONResponse({"error": "Nombre vacío"}, status_code=400)
    try:
        with conn() as c:
            c.execute("INSERT INTO jugadores (nombre, posicion) VALUES (%s,%s)",
                      (nombre, posicion.strip()))
    except psycopg.errors.UniqueViolation:
        # El nombre ya existe (columna UNIQUE). El pool hace rollback al salir del with.
        return JSONResponse({"error": "Ya existe un jugador con ese nombre"}, status_code=400)
    return {"ok": True}


@app.post("/admin/estado")
def admin_estado(pin: str = Form(...), jugador_id: int = Form(...), activo: int = Form(...)):
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    with conn() as c:
        c.execute("UPDATE jugadores SET activo=%s WHERE id=%s", (activo, jugador_id))
    return {"ok": True}


# ===========================================================================
#  ESTILO COMPARTIDO
# ===========================================================================
ESTILO = """
<style>
  :root{
    --tinta:#141b2e; --gris:#5b6577; --linea:#e4e7ee;
    --acento:#e8603c; --acento2:#1f6feb; --ok:#1a7f5a; --rojo:#c0402a; --ambar:#c98a00;
    --fondo:#f6f7fb; --card:#fff;
  }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       background:var(--fondo);color:var(--tinta);line-height:1.45}
  a{color:var(--acento2);text-decoration:none}
  .wrap{max-width:520px;margin:0 auto;padding:20px 16px 60px}
  .wide{max-width:1000px}
  header.top{display:flex;align-items:center;gap:10px;margin-bottom:18px}
  .bola{width:34px;height:34px;border-radius:50%;background:var(--acento);
        display:grid;place-items:center;color:#fff;font-weight:800;flex:none}
  h1{font-size:1.25rem;margin:0}
  .sub{color:var(--gris);font-size:.86rem;margin:2px 0 0}
  .card{background:var(--card);border:1px solid var(--linea);border-radius:16px;
        padding:16px;margin-bottom:14px}
  label{display:block;font-weight:600;font-size:.9rem;margin:14px 0 6px}
  label:first-child{margin-top:0}
  select,input,textarea{width:100%;padding:12px;border:1px solid var(--linea);
        border-radius:10px;font-size:1rem;font-family:inherit;background:#fff}
  textarea{min-height:60px;resize:vertical}
  .fila{display:flex;gap:10px}.fila>div{flex:1}
  .seg{display:flex;gap:6px;flex-wrap:wrap}
  .seg input{display:none}
  .seg label{flex:1;min-width:38px;margin:0;text-align:center;padding:11px 0;
        border:1px solid var(--linea);border-radius:10px;cursor:pointer;font-weight:700;
        background:#fff;transition:.12s}
  .seg input:checked+label{background:var(--acento);color:#fff;border-color:var(--acento)}
  .ayuda{color:var(--gris);font-size:.78rem;margin-top:4px}
  button.enviar{width:100%;padding:15px;border:0;border-radius:12px;
        background:var(--tinta);color:#fff;font-size:1.05rem;font-weight:700;
        margin-top:22px;cursor:pointer}
  button.enviar:active{transform:scale(.99)}
  .exito{text-align:center;padding:50px 20px}
  .exito .big{font-size:3rem}
  .nav{display:flex;gap:14px;margin-bottom:16px;font-size:.9rem;font-weight:600}
  table{width:100%;border-collapse:collapse;font-size:.85rem;background:#fff}
  th,td{padding:9px 10px;border-bottom:1px solid var(--linea);text-align:left;white-space:nowrap}
  th{background:#fafbfe;font-size:.72rem;text-transform:uppercase;letter-spacing:.03em;color:var(--gris)}
  .tabla-wrap{overflow-x:auto;border:1px solid var(--linea);border-radius:12px}
  .badge{display:inline-block;padding:2px 9px;border-radius:20px;font-weight:700;font-size:.75rem}
  .b-ok{background:#e2f4ec;color:var(--ok)} .b-rojo{background:#fde8e2;color:var(--rojo)}
  .b-ambar{background:#fdf1d8;color:var(--ambar)} .b-gris{background:#eef0f5;color:var(--gris)}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
  .kpi{background:#fff;border:1px solid var(--linea);border-radius:14px;padding:14px}
  .kpi .n{font-size:1.8rem;font-weight:800} .kpi .l{color:var(--gris);font-size:.8rem}
  .btn{display:inline-block;padding:9px 14px;border-radius:10px;border:1px solid var(--linea);
       background:#fff;font-weight:600;cursor:pointer;font-size:.85rem}
  .btn-p{background:var(--tinta);color:#fff;border-color:var(--tinta)}
  .alerta{background:#fde8e2;border:1px solid #f3c3b6;color:var(--rojo);
          padding:10px 12px;border-radius:10px;margin-bottom:8px;font-size:.86rem}
  .chart{width:100%;height:170px;background:#fff;border:1px solid var(--linea);border-radius:12px}
  .chart-t{font-weight:700;font-size:.85rem;margin:14px 0 6px}
</style>
"""

# ===========================================================================
#  PÁGINAS
# ===========================================================================
# NOTA: string normal (no f-string) a propósito, para no tener que escapar las
# llaves { } de CSS y JavaScript. Los marcadores {{OPCIONES}} y {{HOY}} se
# reemplazan desde la ruta con .replace().
PAGINA_JUGADOR = """<!doctype html>
<html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey · Mi día</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Saira:wght@500;600;700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --azul:#214EE0; --azul-800:#1A3EB0; --azul-050:#EDF1FE;
    --negro:#111318; --gris:#6B7280; --linea:#E6E8EE; --blanco:#FFFFFF; --fondo:#F5F7FB;
  }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  html,body{margin:0}
  body{font-family:"Inter",system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    background:var(--fondo);color:var(--negro);line-height:1.45;-webkit-font-smoothing:antialiased}
  .app{max-width:440px;margin:0 auto;min-height:100vh}
  .hero{background:var(--azul);color:#fff;padding:22px 20px 0;position:relative;overflow:hidden}
  .hero .marca{display:flex;align-items:center;gap:12px}
  .escudo{width:44px;height:44px;border-radius:11px;flex:none;background:rgba(255,255,255,.14);
    display:grid;place-items:center;overflow:hidden;border:1px solid rgba(255,255,255,.25)}
  .escudo img{width:100%;height:100%;object-fit:contain}
  .escudo .mono{font-family:"Saira";font-weight:800;font-size:24px;color:#fff}
  .wordmark{font-family:"Saira";font-weight:800;font-size:26px;letter-spacing:.06em;line-height:1}
  .wordmark small{display:block;font-weight:500;font-size:11px;letter-spacing:.18em;opacity:.7;margin-top:3px}
  .salir{margin-left:auto;color:#fff;opacity:.85;font-size:.78rem;font-weight:600;text-decoration:none;
    border:1px solid rgba(255,255,255,.4);border-radius:20px;padding:6px 12px;flex:none}
  .hero h1{font-family:"Saira";font-weight:700;font-size:34px;line-height:1;margin:20px 0 4px}
  .hero .fecha{font-size:13px;opacity:.85;margin:0 0 20px;text-transform:capitalize}
  .cancha{height:26px;border-top:2px solid rgba(255,255,255,.35);position:relative;margin:0 -20px}
  .cancha::before{content:"";position:absolute;top:-14px;left:50%;transform:translateX(-50%);
    width:26px;height:26px;border:2px solid rgba(255,255,255,.35);border-radius:50%;background:var(--azul)}
  .hoja{background:var(--blanco);border-radius:20px 20px 0 0;margin-top:-8px;padding:22px 20px 120px;
    position:relative;box-shadow:0 -2px 20px rgba(17,19,24,.04)}
  .campo{margin-bottom:18px}
  .campo > label{display:block;font-weight:600;font-size:.9rem;margin-bottom:8px}
  select,input[type=date],input[type=number],textarea{width:100%;padding:13px 12px;
    border:1.5px solid var(--linea);border-radius:12px;font-size:1rem;font-family:inherit;background:#fff;color:var(--negro)}
  select:focus,input:focus,textarea:focus{outline:none;border-color:var(--azul);box-shadow:0 0 0 4px var(--azul-050)}
  textarea{min-height:64px;resize:vertical}
  .par{display:flex;gap:12px}.par>div{flex:1}
  .sep{height:1px;background:var(--linea);margin:22px 0}
  .titulo-sec{font-family:"Saira";font-weight:700;font-size:1.05rem;margin:0 0 12px}
  .toggle{display:flex;gap:8px}
  .toggle input{position:absolute;opacity:0;pointer-events:none}
  .toggle label{flex:1;text-align:center;padding:12px;border:1.5px solid var(--linea);border-radius:12px;
    font-weight:600;cursor:pointer;transition:.12s;background:#fff}
  .toggle input:checked + label{background:var(--negro);color:#fff;border-color:var(--negro)}
  .chips{display:grid;gap:8px}
  .chips.diez{grid-template-columns:repeat(5,1fr)}
  .chips.cinco{grid-template-columns:repeat(5,1fr)}
  .chips input{position:absolute;opacity:0;pointer-events:none}
  .chips label{aspect-ratio:1/1;display:grid;place-items:center;cursor:pointer;
    border:1.5px solid var(--linea);border-radius:12px;background:#fff;
    font-family:"Saira";font-weight:700;font-size:1.15rem;color:var(--negro);
    transition:transform .08s, background .12s, border-color .12s}
  .chips label:active{transform:scale(.94)}
  .chips input:checked + label{background:var(--azul);border-color:var(--azul);color:#fff;
    box-shadow:0 4px 12px rgba(33,78,224,.35)}
  .chips .extremo{font-size:.7rem;color:var(--gris);display:flex;justify-content:space-between;
    grid-column:1/-1;margin-top:2px;font-weight:500}
  .barra{position:fixed;left:0;right:0;bottom:0;max-width:440px;margin:0 auto;
    padding:14px 20px calc(14px + env(safe-area-inset-bottom));
    background:linear-gradient(to top, #fff 70%, rgba(255,255,255,0))}
  .guardar{width:100%;padding:16px;border:0;border-radius:14px;background:var(--azul);color:#fff;
    font-family:"Saira";font-weight:700;font-size:1.1rem;cursor:pointer;
    transition:transform .08s, background .12s;box-shadow:0 6px 18px rgba(33,78,224,.35)}
  .guardar:hover{background:var(--azul-800)}
  .guardar:active{transform:scale(.99)}
  @media (prefers-reduced-motion: reduce){*{transition:none!important}}
</style></head>
<body><div class="app">
  <header class="hero">
    <div class="marca">
      <div class="escudo">
        <img src="/static/escudo.png" alt="Escudo Corey" onerror="this.style.display='none';this.nextElementSibling.style.display='grid'">
        <span class="mono" style="display:none">C</span>
      </div>
      <div class="wordmark">COREY<small>RENDIMIENTO</small></div>
      <a href="/logout" class="salir">Salir</a>
    </div>
    <h1>Hola, {{NOMBRE}}</h1>
    <p class="fecha" id="fecha">—</p>
    <div class="cancha"></div>
  </header>
  <main class="hoja">
    <form action="/registrar" method="post">
      <input type="hidden" name="csrf_token" value="{{CSRF}}">
      <div class="campo">
        <label for="fechaIn">Fecha</label>
        <input type="date" id="fechaIn" name="fecha" value="{{HOY}}" required>
      </div>
      <div class="campo">
        <label>¿Entrenaste hoy?</label>
        <div class="toggle">
          <input type="radio" name="entreno" id="ent1" value="1" checked><label for="ent1">Sí</label>
          <input type="radio" name="entreno" id="ent0" value="0"><label for="ent0">No</label>
        </div>
      </div>
      <div class="sep"></div>
      <h3 class="titulo-sec">Intensidad del entrenamiento</h3>
      <div class="chips diez">
        <input type="radio" name="rpe" id="rpe1" value="1"><label for="rpe1">1</label>
        <input type="radio" name="rpe" id="rpe2" value="2"><label for="rpe2">2</label>
        <input type="radio" name="rpe" id="rpe3" value="3"><label for="rpe3">3</label>
        <input type="radio" name="rpe" id="rpe4" value="4"><label for="rpe4">4</label>
        <input type="radio" name="rpe" id="rpe5" value="5"><label for="rpe5">5</label>
        <input type="radio" name="rpe" id="rpe6" value="6"><label for="rpe6">6</label>
        <input type="radio" name="rpe" id="rpe7" value="7"><label for="rpe7">7</label>
        <input type="radio" name="rpe" id="rpe8" value="8"><label for="rpe8">8</label>
        <input type="radio" name="rpe" id="rpe9" value="9"><label for="rpe9">9</label>
        <input type="radio" name="rpe" id="rpe10" value="10"><label for="rpe10">10</label>
        <div class="extremo"><span>Muy suave</span><span>Máximo esfuerzo</span></div>
      </div>
      <div class="par" style="margin-top:18px">
        <div class="campo" style="margin:0">
          <label for="minutos">Minutos</label>
          <input type="number" id="minutos" name="minutos" min="0" value="0" inputmode="numeric">
        </div>
        <div class="campo" style="margin:0">
          <label for="sueno">Horas de sueño</label>
          <input type="number" id="sueno" name="sueno" step="0.5" min="0" value="8" inputmode="decimal">
        </div>
      </div>
      <div class="campo" style="margin-top:18px">
        <label>Nivel de cansancio</label>
        <div class="chips cinco">
          <input type="radio" name="fatiga" id="fat1" value="1"><label for="fat1">1</label>
          <input type="radio" name="fatiga" id="fat2" value="2"><label for="fat2">2</label>
          <input type="radio" name="fatiga" id="fat3" value="3" checked><label for="fat3">3</label>
          <input type="radio" name="fatiga" id="fat4" value="4"><label for="fat4">4</label>
          <input type="radio" name="fatiga" id="fat5" value="5"><label for="fat5">5</label>
          <div class="extremo"><span>Fresco</span><span>Agotado</span></div>
        </div>
      </div>
      <div class="sep"></div>
      <div class="campo">
        <label>¿Completaste tu rutina?</label>
        <div class="toggle">
          <input type="radio" name="rutina_ok" id="rut1" value="1" checked><label for="rut1">Sí</label>
          <input type="radio" name="rutina_ok" id="rut0" value="0"><label for="rut0">No</label>
        </div>
      </div>
      <div class="campo">
        <label for="comida">¿Qué comiste hoy?</label>
        <textarea id="comida" name="comida" placeholder="Desayuno, almuerzo, cena, snacks…"></textarea>
      </div>
      <div class="campo">
        <label for="molestias">Molestias o dolores</label>
        <textarea id="molestias" name="molestias" placeholder="Ej: molestia en rodilla derecha (opcional)"></textarea>
      </div>
      <div class="barra">
        <button class="guardar" type="submit">Guardar mi día</button>
      </div>
    </form>
  </main>
</div>
<script>
  var hoy = new Date();
  document.getElementById('fecha').textContent =
    hoy.toLocaleDateString('es-AR', {weekday:'long', day:'numeric', month:'long'});
</script>
</body></html>"""

PAGINA_OK = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey · Guardado</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Saira:wght@600;700;800&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0}
  body{font-family:"Inter",system-ui,sans-serif;background:#214EE0;color:#fff;
    min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;
    text-align:center;padding:40px;-webkit-font-smoothing:antialiased}
  .tic{width:80px;height:80px;border-radius:50%;background:#fff;color:#214EE0;font-size:42px;
    display:grid;place-items:center;margin-bottom:20px}
  h2{font-family:"Saira";font-weight:800;font-size:2rem;margin-bottom:8px}
  .disp{font-family:"Saira";font-weight:700;font-size:1.1rem;opacity:.95;margin-bottom:28px}
  a{background:#fff;color:#214EE0;text-decoration:none;padding:14px 28px;border-radius:12px;
    font-family:"Saira";font-weight:700;font-size:1rem}
</style></head>
<body>
  <div class="tic">✓</div>
  <h2>¡Día guardado!</h2>
  <p class="disp">Tu disponibilidad de hoy: {{READY}}/100</p>
  <a href="/">Cargar otro</a>
</body></html>"""

_ESTILO_CUENTA = """
<style>
  *{box-sizing:border-box}
  body{margin:0;font-family:"Inter",system-ui,sans-serif;background:#214EE0;min-height:100vh;
    display:flex;align-items:center;justify-content:center;padding:24px;-webkit-font-smoothing:antialiased}
  .card{background:#fff;border-radius:20px;padding:32px 26px;max-width:380px;width:100%;
    box-shadow:0 20px 50px rgba(17,19,24,.25)}
  h1{font-family:"Saira";font-weight:800;font-size:1.6rem;margin:0 0 4px;color:#111318}
  p.sub{color:#6B7280;font-size:.9rem;margin:0 0 22px}
  label{display:block;font-weight:600;font-size:.88rem;margin:14px 0 6px;color:#111318}
  input{width:100%;padding:12px;border:1.5px solid #E6E8EE;border-radius:10px;font-size:1rem;font-family:inherit}
  input:focus{outline:none;border-color:#214EE0;box-shadow:0 0 0 4px #EDF1FE}
  .par{display:flex;gap:10px}.par>div{flex:1}
  button{width:100%;padding:14px;border:0;border-radius:12px;background:#214EE0;color:#fff;
    font-family:"Saira";font-weight:700;font-size:1.02rem;margin-top:20px;cursor:pointer}
  .error{background:#fde8e2;color:#c0402a;padding:10px 12px;border-radius:10px;font-size:.85rem;margin:0 0 8px}
  .alt{text-align:center;margin-top:18px;font-size:.88rem;color:#6B7280}
  .alt a{color:#214EE0;font-weight:600;text-decoration:none}
</style>"""

_HEAD_FUENTES = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Saira:wght@700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">"""

PAGINA_LOGIN = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey · Ingresar</title>{_HEAD_FUENTES}{_ESTILO_CUENTA}</head>
<body>
  <div class="card">
    <h1>Bienvenido de vuelta</h1>
    <p class="sub">Ingresá para cargar tu día</p>
    {{{{ERROR}}}}
    <form method="post" action="/login">
      <input type="hidden" name="csrf_token" value="{{{{CSRF}}}}">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" required autofocus>
      <label for="password">Contraseña</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Ingresar</button>
    </form>
    <p class="alt">¿No tenés cuenta? <a href="/registro">Registrate</a></p>
  </div>
</body></html>"""

PAGINA_REGISTRO = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey · Crear cuenta</title>{_HEAD_FUENTES}{_ESTILO_CUENTA}</head>
<body>
  <div class="card">
    <h1>Creá tu cuenta</h1>
    <p class="sub">Para registrar tu día a día</p>
    {{{{ERROR}}}}
    <form method="post" action="/registro">
      <input type="hidden" name="csrf_token" value="{{{{CSRF}}}}">
      <label for="nombre">Nombre y apellido</label>
      <input type="text" id="nombre" name="nombre" required autofocus>
      <label for="posicion">Posición (opcional)</label>
      <input type="text" id="posicion" name="posicion" placeholder="Base, Escolta, Alero…">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" required>
      <div class="par">
        <div>
          <label for="password">Contraseña</label>
          <input type="password" id="password" name="password" minlength="6" required>
        </div>
        <div>
          <label for="password2">Repetir</label>
          <input type="password" id="password2" name="password2" minlength="6" required>
        </div>
      </div>
      <button type="submit">Crear cuenta</button>
    </form>
    <p class="alt">¿Ya tenés cuenta? <a href="/login">Ingresá</a></p>
  </div>
</body></html>"""

PAGINA_PIN = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{ESTILO}</head>
<body><div class="wrap"><header class="top"><div class="bola">🔒</div>
<div><h1>Acceso cuerpo técnico</h1><p class="sub">Ingresá el PIN</p></div></header>
<div class="card"><form action="/panel" method="get">
<label>PIN</label><input type="password" name="pin" required autofocus>
<button class="enviar" type="submit">Entrar</button></form></div></div></body></html>"""

PAGINA_PANEL = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Panel — Cuerpo técnico</title>{ESTILO}</head>
<body><div class="wrap wide">
<header class="top"><div class="bola">📊</div>
<div><h1>Panel del cuerpo técnico</h1><p class="sub">Monitoreo de carga y disponibilidad</p></div></header>
<div class="nav" id="nav"></div>
<div id="alertas"></div>
<div class="kpis" id="kpis"></div>
<div class="tabla-wrap"><table id="tabla">
<thead><tr><th>Jugador</th><th>Pos</th><th>Disponib.</th><th>ACWR</th>
<th>Carga hoy</th><th>Último</th><th>Estado</th><th></th></tr></thead>
<tbody></tbody></table></div>
<p class="sub" style="margin-top:14px">
Disponibilidad = índice 0-100 (sueño+fatiga+molestias). ACWR = carga aguda/crónica;
ideal 0.8-1.3, riesgo &gt;1.5. Tocá un jugador para ver su ficha.</p>
</div>
<script>
const pin = new URLSearchParams(location.search).get('pin');
const P = encodeURIComponent(pin);
document.getElementById('nav').innerHTML =
  `<a href="/admin?pin=${{P}}">⚙️ Gestionar jugadores</a>
   <a href="/api/export.csv?pin=${{P}}">⬇️ Exportar CSV</a>`;

function acwrBadge(a){{
  if(a===null||a===undefined) return '<span class="badge b-gris">—</span>';
  let cls='b-ok'; if(a>1.5||a<0.8) cls='b-rojo'; else if(a>1.3) cls='b-ambar';
  return `<span class="badge ${{cls}}">${{a}}</span>`;
}}
function readyBadge(r){{
  if(r===null||r===undefined) return '<span class="badge b-gris">—</span>';
  let cls = r>=70?'b-ok':(r>=50?'b-ambar':'b-rojo');
  return `<span class="badge ${{cls}}">${{r}}</span>`;
}}

fetch('/api/datos?pin='+P).then(r=>r.json()).then(d=>{{
  const js = d.jugadores||[];
  const tb = document.querySelector('#tabla tbody');
  let cargaHoy=0, enRiesgo=0, dispBaja=0, alertasHTML='';
  js.forEach(j=>{{
    cargaHoy += j.carga_hoy||0;
    if(j.acwr!==null && (j.acwr>1.5||j.acwr<0.8)) enRiesgo++;
    if(j.readiness!==null && j.readiness<50) dispBaja++;
    (j.alertas||[]).forEach(a=> alertasHTML+=`<div class="alerta"><b>${{j.nombre}}:</b> ${{a}}</div>`);
    const tr=document.createElement('tr');
    tr.innerHTML=`
      <td><b>${{j.nombre}}</b></td><td>${{j.posicion||'—'}}</td>
      <td>${{readyBadge(j.readiness)}}</td>
      <td>${{acwrBadge(j.acwr)}}</td>
      <td>${{j.carga_hoy||'—'}}</td>
      <td>${{j.ultimo||'—'}}</td>
      <td>${{j.activo?'<span class="badge b-ok">activo</span>':'<span class="badge b-gris">baja</span>'}}</td>
      <td><a href="/jugador/${{j.id}}?pin=${{P}}">Ver ficha →</a></td>`;
    tb.appendChild(tr);
  }});
  document.getElementById('alertas').innerHTML = alertasHTML;
  document.getElementById('kpis').innerHTML=`
    <div class="kpi"><div class="n">${{js.length}}</div><div class="l">Jugadores</div></div>
    <div class="kpi"><div class="n">${{cargaHoy}}</div><div class="l">Carga total hoy</div></div>
    <div class="kpi"><div class="n">${{enRiesgo}}</div><div class="l">ACWR en riesgo</div></div>
    <div class="kpi"><div class="n">${{dispBaja}}</div><div class="l">Disponibilidad baja</div></div>`;
}}).catch(()=>{{document.body.innerHTML='<div class="wrap"><p>Error: PIN inválido o servidor caído.</p></div>'}});
</script></body></html>"""

PAGINA_FICHA = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ficha — Jugador</title>{ESTILO}</head>
<body><div class="wrap wide">
<div class="nav" id="nav"></div>
<header class="top"><div class="bola">👤</div>
<div><h1 id="nombre">…</h1><p class="sub" id="pos"></p></div></header>
<div id="alertas"></div>
<div class="kpis" id="kpis"></div>
<div class="chart-t">Carga de entrenamiento (RPE × min) — últimos 14 registros</div>
<svg class="chart" id="c_carga"></svg>
<div class="chart-t">Nivel de cansancio (1-5)</div>
<svg class="chart" id="c_fatiga"></svg>
<div class="chart-t">Horas de sueño</div>
<svg class="chart" id="c_sueno"></svg>
<div class="tabla-wrap" style="margin-top:16px"><table id="tabla">
<thead><tr><th>Fecha</th><th>Carga</th><th>RPE</th><th>Fatiga</th>
<th>Sueño</th><th>Disponib.</th><th>Rutina</th><th>Molestias</th></tr></thead>
<tbody></tbody></table></div>
</div>
<script>
const pin = new URLSearchParams(location.search).get('pin');
const P = encodeURIComponent(pin);
const jid = location.pathname.split('/').pop();
document.getElementById('nav').innerHTML = `<a href="/panel?pin=${{P}}">← Volver al panel</a>`;

function dibujar(id, valores, color, opt){{
  opt = opt||{{}};
  const tipo = opt.tipo||'linea';
  const svg=document.getElementById(id);
  const W=svg.clientWidth||600, H=170, pad=24;
  svg.setAttribute('viewBox','0 0 '+W+' '+H);
  if(!valores.length){{ svg.innerHTML='<text x="'+(W/2)+'" y="'+(H/2)+'" fill="#5b6577" font-size="12" text-anchor="middle">Sin datos aún</text>'; return; }}
  const ys = valores.map(v=>v.y);
  const max = opt.maxY || Math.max.apply(null, ys.concat([1]));
  const n = valores.length;
  const x = i => pad + (n===1? (W-2*pad)/2 : i*(W-2*pad)/(n-1));
  const y = v => H-pad - (v/max)*(H-2*pad);
  let s='<line x1="'+pad+'" y1="'+(H-pad)+'" x2="'+(W-pad)+'" y2="'+(H-pad)+'" stroke="#e4e7ee"/>';
  if(tipo==='barra'){{
    const bw = Math.max(4,(W-2*pad)/n*0.6);
    valores.forEach((v,i)=>{{ const h=(v.y/max)*(H-2*pad);
      s+='<rect x="'+(x(i)-bw/2)+'" y="'+(H-pad-h)+'" width="'+bw+'" height="'+h+'" rx="2" fill="'+color+'"/>'; }});
  }} else {{
    let path = valores.map((v,i)=>(i?'L':'M')+x(i)+','+y(v.y)).join(' ');
    s+='<path d="'+path+'" fill="none" stroke="'+color+'" stroke-width="2.5"/>';
    valores.forEach((v,i)=> s+='<circle cx="'+x(i)+'" cy="'+y(v.y)+'" r="3" fill="'+color+'"/>');
  }}
  svg.innerHTML=s;
}}

fetch('/api/jugador/'+jid+'?pin='+P).then(r=>r.json()).then(d=>{{
  const j=d.jugador, serie=d.serie||[];
  document.getElementById('nombre').textContent=j.nombre;
  document.getElementById('pos').textContent=(j.posicion||'—')+' · '+serie.length+' registros';
  document.getElementById('alertas').innerHTML=(d.alertas||[]).map(a=>'<div class="alerta">'+a+'</div>').join('');
  const rd=d.readiness_actual, ac=d.acwr;
  const rcls = rd===null?'b-gris':(rd>=70?'b-ok':rd>=50?'b-ambar':'b-rojo');
  const acls = ac===null?'b-gris':((ac>1.5||ac<0.8)?'b-rojo':ac>1.3?'b-ambar':'b-ok');
  document.getElementById('kpis').innerHTML=
    '<div class="kpi"><div class="n"><span class="badge '+rcls+'">'+(rd==null?'—':rd)+'</span></div><div class="l">Disponibilidad hoy</div></div>'+
    '<div class="kpi"><div class="n"><span class="badge '+acls+'">'+(ac==null?'—':ac)+'</span></div><div class="l">ACWR (riesgo)</div></div>';

  const ult = serie.slice(-14);
  dibujar('c_carga', ult.map(x=>({{y:x.carga}})), '#e8603c', {{tipo:'barra'}});
  dibujar('c_fatiga', ult.map(x=>({{y:x.fatiga||0}})), '#c0402a', {{maxY:5}});
  dibujar('c_sueno', ult.map(x=>({{y:x.sueno||0}})), '#1f6feb', {{maxY:12}});

  const tb=document.querySelector('#tabla tbody');
  serie.slice().reverse().forEach(x=>{{
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+x.fecha+'</td><td><b>'+(x.carga||'—')+'</b></td><td>'+(x.rpe||'—')+'</td>'+
      '<td>'+(x.fatiga>=4?'<span class="badge b-rojo">'+x.fatiga+'</span>':(x.fatiga||'—'))+'</td>'+
      '<td>'+(x.sueno||'—')+'h</td><td>'+(x.readiness==null?'—':x.readiness)+'</td>'+
      '<td>'+(x.rutina_ok?'✅':'❌')+'</td><td>'+(x.molestias||'—')+'</td>';
    tb.appendChild(tr);
  }});
}}).catch(()=>{{document.body.innerHTML='<div class="wrap"><p>Error: PIN inválido o jugador inexistente.</p></div>'}});
</script></body></html>"""

PAGINA_ADMIN = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gestionar jugadores</title>{ESTILO}</head>
<body><div class="wrap">
<div class="nav" id="nav"></div>
<header class="top"><div class="bola">⚙️</div>
<div><h1>Gestionar jugadores</h1><p class="sub">Alta y baja del plantel</p></div></header>
<div class="card">
  <label>Nombre del jugador</label>
  <input id="nombre" placeholder="Nombre y apellido">
  <label>Posición (opcional)</label>
  <input id="posicion" placeholder="Base, Escolta, Alero, Ala-Pívot, Pívot">
  <button class="enviar" id="btnAdd">Agregar jugador</button>
  <p class="ayuda" id="msg"></p>
</div>
<div class="tabla-wrap"><table id="tabla">
<thead><tr><th>Nombre</th><th>Posición</th><th>Estado</th><th></th></tr></thead>
<tbody></tbody></table></div>
</div>
<script>
const pin = new URLSearchParams(location.search).get('pin');
const P = encodeURIComponent(pin);
document.getElementById('nav').innerHTML = '<a href="/panel?pin='+P+'">← Volver al panel</a>';

function cargar(){{
  fetch('/api/jugadores?pin='+P).then(r=>r.json()).then(d=>{{
    const tb=document.querySelector('#tabla tbody'); tb.innerHTML='';
    (d.jugadores||[]).forEach(j=>{{
      const tr=document.createElement('tr');
      const estado = j.activo
        ? '<span class="badge b-ok">activo</span>'
        : '<span class="badge b-gris">baja</span>';
      const btn = j.activo
        ? '<button class="btn" onclick="estado('+j.id+',0)">Dar de baja</button>'
        : '<button class="btn btn-p" onclick="estado('+j.id+',1)">Reactivar</button>';
      tr.innerHTML='<td><b>'+j.nombre+'</b></td><td>'+(j.posicion||'—')+'</td><td>'+estado+'</td><td>'+btn+'</td>';
      tb.appendChild(tr);
    }});
  }});
}}
function estado(id,activo){{
  const fd=new FormData(); fd.append('pin',pin); fd.append('jugador_id',id); fd.append('activo',activo);
  fetch('/admin/estado',{{method:'POST',body:fd}}).then(()=>cargar());
}}
document.getElementById('btnAdd').onclick=function(){{
  const nombre=document.getElementById('nombre').value;
  const posicion=document.getElementById('posicion').value;
  const msg=document.getElementById('msg');
  if(!nombre.trim()){{ msg.textContent='Poné un nombre.'; return; }}
  const fd=new FormData(); fd.append('pin',pin); fd.append('nombre',nombre); fd.append('posicion',posicion);
  fetch('/admin/agregar',{{method:'POST',body:fd}}).then(r=>r.json()).then(res=>{{
    if(res.error){{ msg.textContent=res.error; return; }}
    document.getElementById('nombre').value=''; document.getElementById('posicion').value='';
    msg.textContent='Agregado ✔'; cargar();
  }});
}};
cargar();
</script></body></html>"""