"""
App de monitoreo de rendimiento físico — Club de básquet semipro (v3, PostgreSQL).

Migrada de SQLite a PostgreSQL (Supabase). Los datos ahora viven en la nube.

Requisitos previos:
  1. Tener un archivo .env en esta carpeta con:
         DATABASE_URL=postgresql://usuario:password@host:puerto/postgres
     (la cadena "URI" que copiaste de Supabase → Project Settings → Database)
  2. pip install -r requirements.txt

Correr con:  uvicorn main:app --reload --host 0.0.0.0 --port 8000
  - Jugador:    http://<tu-ip>:8000/            (cuenta propia: email + clave)
  - Entrenador: http://<tu-ip>:8000/panel       (cuenta propia; para crearla hace
                falta el PIN, ver /entrenador/registro)
  - Admin:      http://<tu-ip>:8000/admin       (PIN, por defecto 1234)

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
import re
import secrets
import time
from collections import defaultdict
from datetime import date, datetime, timedelta
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

from metrics import acwr_de, carga, clamp, readiness

# ---------------------------------------------------------------------------
# Configuración: credenciales desde .env (NUNCA en el código)
# ---------------------------------------------------------------------------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "Falta DATABASE_URL. Crea un archivo .env en esta carpeta con:\n"
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


# ---------------------------------------------------------------------------
# Rate limiting de /login: en memoria, alcanza para una sola instancia como
# la que corre esta app en Render. Si algún día hay más de un worker/dyno,
# esto habría que moverlo a algo compartido (ej. Redis).
# ---------------------------------------------------------------------------
LOGIN_MAX_INTENTOS_IP = 15      # por IP: cubre una red compartida (gimnasio, wifi del club)
LOGIN_MAX_INTENTOS_EMAIL = 5    # por cuenta: más estricto, es un solo jugador
LOGIN_VENTANA_SEG = 5 * 60

_intentos_por_ip = defaultdict(list)
_intentos_por_email = defaultdict(list)


def _ip_cliente(request: Request) -> str:
    return request.client.host if request.client else "desconocido"


def _contar_recientes(bucket: dict, key: str) -> int:
    ahora = time.time()
    intentos = bucket[key]
    intentos[:] = [t for t in intentos if ahora - t < LOGIN_VENTANA_SEG]
    return len(intentos)


def login_bloqueado(request: Request, email: str) -> bool:
    return (
        _contar_recientes(_intentos_por_ip, _ip_cliente(request)) >= LOGIN_MAX_INTENTOS_IP
        or _contar_recientes(_intentos_por_email, email) >= LOGIN_MAX_INTENTOS_EMAIL
    )


def registrar_intento_fallido(request: Request, email: str):
    ahora = time.time()
    _intentos_por_ip[_ip_cliente(request)].append(ahora)
    _intentos_por_email[email].append(ahora)


def limpiar_intentos(request: Request, email: str):
    _intentos_por_ip.pop(_ip_cliente(request), None)
    _intentos_por_email.pop(email, None)


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
        # Cuenta propia por entrenador. Para crearla hace falta el PIN (ver
        # /entrenador/registro): es la forma de que no cualquiera se anote
        # como cuerpo técnico y vea los datos de salud de todo el plantel.
        c.execute("""
            CREATE TABLE IF NOT EXISTS entrenadores (
                id SERIAL PRIMARY KEY,
                nombre TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
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
        # Rutina de entrenamiento: una sesión por jugador y día (la rutina
        # cambia día a día), con bloques (Calentamiento, Bloque principal,
        # etc.) y dentro de cada bloque varios ejercicios.
        #
        # Migración única: la primera versión de esto era "rutinas" (una
        # sola por jugador, sin fecha). Si "sesiones" todavía no existe,
        # tiramos las tablas viejas y las recreamos con la forma nueva. No
        # vuelve a correr una vez migrado (a partir de ahí "sesiones" ya
        # existe, así que esta rama nunca se repite).
        existe_sesiones = c.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables WHERE table_name = 'sesiones'
            )
        """).fetchone()
        if not existe_sesiones["exists"]:
            c.execute("DROP TABLE IF EXISTS ejercicios")
            c.execute("DROP TABLE IF EXISTS bloques")
            c.execute("DROP TABLE IF EXISTS rutinas")

        c.execute("""
            CREATE TABLE IF NOT EXISTS sesiones (
                id SERIAL PRIMARY KEY,
                jugador_id INTEGER NOT NULL REFERENCES jugadores (id),
                fecha TEXT NOT NULL,
                enfoque TEXT DEFAULT '',
                rpe_final TEXT DEFAULT '',
                objetivo TEXT DEFAULT '',
                objetivo_nota TEXT DEFAULT '',
                actualizado TEXT NOT NULL,
                UNIQUE (jugador_id, fecha)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS bloques (
                id SERIAL PRIMARY KEY,
                sesion_id INTEGER NOT NULL REFERENCES sesiones (id) ON DELETE CASCADE,
                orden INTEGER NOT NULL,
                nombre TEXT NOT NULL,
                minutos INTEGER
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS ejercicios (
                id SERIAL PRIMARY KEY,
                bloque_id INTEGER NOT NULL REFERENCES bloques (id) ON DELETE CASCADE,
                orden INTEGER NOT NULL,
                actividad TEXT NOT NULL,
                dosificacion TEXT DEFAULT '',
                clave TEXT DEFAULT '',
                youtube_url TEXT DEFAULT ''
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


def entrenador_logueado(request: Request):
    """Devuelve la fila del entrenador logueado según la cookie de sesión, o None."""
    eid = request.session.get("entrenador_id")
    if not eid:
        return None
    with conn() as c:
        return c.execute("SELECT * FROM entrenadores WHERE id=%s", (eid,)).fetchone()


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


_YOUTUBE_RE = re.compile(
    r"^https://(www\.)?(youtube\.com/(watch\?v=|shorts/)|youtu\.be/)[\w-]+"
)


def youtube_valida(url: str) -> bool:
    """El link es opcional (vacío es válido); si hay algo, tiene que ser YouTube
    de verdad, para no guardar cualquier URL como si fuera técnica del ejercicio."""
    return not url or bool(_YOUTUBE_RE.match(url.strip()))


def obtener_sesion(jid: int, fecha: str):
    """Sesión de entrenamiento de un jugador para un día puntual (datos de la
    sesión + bloques + ejercicios, en orden) o None si ese día no tiene nada
    cargado todavía."""
    with conn() as c:
        s = c.execute(
            "SELECT * FROM sesiones WHERE jugador_id=%s AND fecha=%s", (jid, fecha)
        ).fetchone()
        if not s:
            return None
        bloques = c.execute(
            "SELECT * FROM bloques WHERE sesion_id=%s ORDER BY orden", (s["id"],)
        ).fetchall()
        resultado = []
        for b in bloques:
            ejercicios = c.execute(
                "SELECT * FROM ejercicios WHERE bloque_id=%s ORDER BY orden", (b["id"],)
            ).fetchall()
            resultado.append({
                "nombre": b["nombre"],
                "minutos": b["minutos"],
                "ejercicios": [
                    {"actividad": e["actividad"], "dosificacion": e["dosificacion"],
                     "clave": e["clave"], "youtube_url": e["youtube_url"]}
                    for e in ejercicios
                ],
            })
    return {
        "fecha": s["fecha"], "enfoque": s["enfoque"], "rpe_final": s["rpe_final"],
        "objetivo": s["objetivo"], "objetivo_nota": s["objetivo_nota"],
        "bloques": resultado,
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
        return HTMLResponse(PAGINA_BIENVENIDA)
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
        return HTMLResponse("Sesión expirada. Vuelve a cargar la página e intentá de nuevo.", status_code=403)

    try:
        fecha_dt = datetime.strptime(fecha, "%Y-%m-%d").date()
    except ValueError:
        return HTMLResponse("Fecha inválida.", status_code=400)
    if fecha_dt > date.today():
        return HTMLResponse("No puedes cargar una fecha futura.", status_code=400)

    # Ajustamos valores fuera de rango en vez de rechazar el envío: un typo
    # (ej. rpe=99) no debería tirarle un error al jugador, se corrige solo.
    entreno = 1 if entreno else 0
    rpe = clamp(rpe, 0, 10)
    minutos = clamp(minutos, 0, 600)
    fatiga = clamp(fatiga, 1, 5)
    sueno = clamp(sueno, 0, 24)
    rutina_ok = 1 if rutina_ok else 0

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
        return HTMLResponse("Sesión expirada. Vuelve a cargar la página e intentá de nuevo.", status_code=403)
    nombre = nombre.strip()
    email = email.strip().lower()
    if not nombre or "@" not in email:
        return RedirectResponse(
            "/registro?error=" + quote("Completa tu nombre y un email válido."), status_code=303
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
        return RedirectResponse("/login?error=" + quote("Sesión expirada, prueba de nuevo."), status_code=303)
    email = email.strip().lower()
    if login_bloqueado(request, email):
        return RedirectResponse(
            "/login?error=" + quote("Demasiados intentos fallidos. Espera unos minutos y prueba de nuevo."),
            status_code=303,
        )
    with conn() as c:
        j = c.execute("SELECT * FROM jugadores WHERE email=%s AND activo=1", (email,)).fetchone()
    if not j or not j["password_hash"] or not check_password(password, j["password_hash"]):
        registrar_intento_fallido(request, email)
        return RedirectResponse("/login?error=" + quote("Email o contraseña incorrectos."), status_code=303)
    limpiar_intentos(request, email)
    request.session["jugador_id"] = j["id"]
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ===========================================================================
#  RUTAS — CUENTA DEL ENTRENADOR (registro / login / logout)
# ===========================================================================
@app.get("/entrenador/registro", response_class=HTMLResponse)
def entrenador_registro_form(request: Request, error: str = ""):
    msg = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return HTMLResponse(
        PAGINA_ENTRENADOR_REGISTRO.replace("{{ERROR}}", msg).replace("{{CSRF}}", generar_csrf(request))
    )


@app.post("/entrenador/registro")
def entrenador_registro(
    request: Request,
    csrf_token: str = Form(...),
    pin: str = Form(...),
    nombre: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password2: str = Form(...),
):
    if not csrf_valido(request, csrf_token):
        return HTMLResponse("Sesión expirada. Vuelve a cargar la página e intentá de nuevo.", status_code=403)
    # El PIN prueba que quien se registra está autorizado por el club a ver
    # los datos de todo el plantel; se rate-limitea igual que un login.
    if login_bloqueado(request, "__entrenador_pin__"):
        return RedirectResponse(
            "/entrenador/registro?error="
            + quote("Demasiados intentos fallidos. Espera unos minutos y prueba de nuevo."),
            status_code=303,
        )
    if pin != PIN_ENTRENADOR:
        registrar_intento_fallido(request, "__entrenador_pin__")
        return RedirectResponse("/entrenador/registro?error=" + quote("PIN inválido."), status_code=303)
    nombre = nombre.strip()
    email = email.strip().lower()
    if not nombre or "@" not in email:
        return RedirectResponse(
            "/entrenador/registro?error=" + quote("Completa tu nombre y un email válido."), status_code=303
        )
    if len(password) < 6:
        return RedirectResponse(
            "/entrenador/registro?error=" + quote("La contraseña debe tener al menos 6 caracteres."),
            status_code=303,
        )
    if password != password2:
        return RedirectResponse(
            "/entrenador/registro?error=" + quote("Las contraseñas no coinciden."), status_code=303
        )
    try:
        with conn() as c:
            fila = c.execute(
                "INSERT INTO entrenadores (nombre, email, password_hash) VALUES (%s,%s,%s) RETURNING id",
                (nombre, email, hash_password(password)),
            ).fetchone()
    except psycopg.errors.UniqueViolation:
        return RedirectResponse(
            "/entrenador/registro?error=" + quote("Ya existe una cuenta con ese email."), status_code=303
        )
    limpiar_intentos(request, "__entrenador_pin__")
    request.session["entrenador_id"] = fila["id"]
    return RedirectResponse("/panel", status_code=303)


@app.get("/entrenador/login", response_class=HTMLResponse)
def entrenador_login_form(request: Request, error: str = ""):
    msg = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return HTMLResponse(
        PAGINA_ENTRENADOR_LOGIN.replace("{{ERROR}}", msg).replace("{{CSRF}}", generar_csrf(request))
    )


@app.post("/entrenador/login")
def entrenador_login(
    request: Request, csrf_token: str = Form(...), email: str = Form(...), password: str = Form(...)
):
    if not csrf_valido(request, csrf_token):
        return RedirectResponse(
            "/entrenador/login?error=" + quote("Sesión expirada, prueba de nuevo."), status_code=303
        )
    email = email.strip().lower()
    if login_bloqueado(request, email):
        return RedirectResponse(
            "/entrenador/login?error="
            + quote("Demasiados intentos fallidos. Espera unos minutos y prueba de nuevo."),
            status_code=303,
        )
    with conn() as c:
        e = c.execute("SELECT * FROM entrenadores WHERE email=%s", (email,)).fetchone()
    if not e or not check_password(password, e["password_hash"]):
        registrar_intento_fallido(request, email)
        return RedirectResponse(
            "/entrenador/login?error=" + quote("Email o contraseña incorrectos."), status_code=303
        )
    limpiar_intentos(request, email)
    request.session["entrenador_id"] = e["id"]
    return RedirectResponse("/panel", status_code=303)


@app.get("/entrenador/logout")
def entrenador_logout(request: Request):
    request.session.pop("entrenador_id", None)
    return RedirectResponse("/entrenador/login", status_code=303)


# ===========================================================================
#  RUTAS — ENTRENADOR / PANEL
# ===========================================================================
@app.get("/panel", response_class=HTMLResponse)
def panel(request: Request):
    if not entrenador_logueado(request):
        return RedirectResponse("/entrenador/login", status_code=303)
    return HTMLResponse(PAGINA_PANEL)


@app.get("/jugador/{jid}", response_class=HTMLResponse)
def ficha(jid: int, request: Request):
    if not entrenador_logueado(request):
        return RedirectResponse("/entrenador/login", status_code=303)
    return HTMLResponse(PAGINA_FICHA)


@app.get("/api/datos")
def api_datos(request: Request):
    if not entrenador_logueado(request):
        return JSONResponse({"error": "No autenticado"}, status_code=403)
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
def api_jugador(jid: int, request: Request):
    if not entrenador_logueado(request):
        return JSONResponse({"error": "No autenticado"}, status_code=403)
    d = datos_jugador(jid)
    if not d:
        return JSONResponse({"error": "No existe"}, status_code=404)
    return d


@app.get("/api/export.csv")
def export_csv(request: Request):
    if not entrenador_logueado(request):
        return JSONResponse({"error": "No autenticado"}, status_code=403)
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
        js = c.execute(
            "SELECT id, nombre, posicion, activo, email FROM jugadores ORDER BY nombre"
        ).fetchall()
    return {"jugadores": [dict(j) for j in js]}


@app.get("/admin/entrenadores", response_class=HTMLResponse)
def admin_entrenadores(pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return RedirectResponse("/admin", status_code=303)
    return PAGINA_ADMIN_ENTRENADORES


@app.get("/api/entrenadores")
def api_entrenadores(pin: str = ""):
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    with conn() as c:
        es = c.execute("SELECT id, nombre, email FROM entrenadores ORDER BY nombre").fetchall()
    return {"entrenadores": [dict(e) for e in es]}


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


@app.post("/admin/resetear_clave")
def admin_resetear_clave(pin: str = Form(...), jugador_id: int = Form(...)):
    """Genera una contraseña temporal nueva para un jugador que no puede
    entrar (no hay recuperación por email todavía). Se muestra una sola vez
    acá; el admin se la pasa al jugador por fuera de la app."""
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    clave_nueva = secrets.token_urlsafe(6)  # ej: "kQ3f8pXa", fácil de dictar/copiar
    with conn() as c:
        fila = c.execute(
            "UPDATE jugadores SET password_hash=%s WHERE id=%s RETURNING nombre",
            (hash_password(clave_nueva), jugador_id),
        ).fetchone()
    if not fila:
        return JSONResponse({"error": "No existe ese jugador"}, status_code=404)
    return {"ok": True, "nombre": fila["nombre"], "clave_nueva": clave_nueva}


@app.post("/admin/jugador/borrar")
def admin_jugador_borrar(pin: str = Form(...), jugador_id: int = Form(...)):
    """Borra un jugador y todo su historial (registros, rutina). Es
    irreversible: pensado para sacar cuentas de prueba o dadas de alta por
    error, no para bajas normales (para eso está 'Dar de baja', que no
    borra nada)."""
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    with conn() as c:
        j = c.execute("SELECT nombre FROM jugadores WHERE id=%s", (jugador_id,)).fetchone()
        if not j:
            return JSONResponse({"error": "No existe ese jugador"}, status_code=404)
        c.execute("DELETE FROM registros WHERE jugador_id=%s", (jugador_id,))
        c.execute("DELETE FROM sesiones WHERE jugador_id=%s", (jugador_id,))
        c.execute("DELETE FROM jugadores WHERE id=%s", (jugador_id,))
    return {"ok": True, "nombre": j["nombre"]}


@app.post("/admin/entrenador/borrar")
def admin_entrenador_borrar(pin: str = Form(...), email: str = Form(...)):
    """Borra una cuenta de entrenador (ej: una cuenta de prueba, o alguien que
    dejó el cuerpo técnico). No hay interfaz para esto todavía, se llama
    directo a la API con el PIN."""
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    with conn() as c:
        fila = c.execute(
            "DELETE FROM entrenadores WHERE email=%s RETURNING nombre", (email.strip().lower(),)
        ).fetchone()
    if not fila:
        return JSONResponse({"error": "No existe ese entrenador"}, status_code=404)
    return {"ok": True, "nombre": fila["nombre"]}


# ===========================================================================
#  RUTAS — RUTINA DE ENTRENAMIENTO (el entrenador la carga, el jugador la ve)
# ===========================================================================
@app.get("/entrenador/rutina/{jid}", response_class=HTMLResponse)
def rutina_editor(jid: int, request: Request):
    if not entrenador_logueado(request):
        return RedirectResponse("/entrenador/login", status_code=303)
    return HTMLResponse(
        PAGINA_RUTINA_EDITAR.replace("{{JID}}", str(jid)).replace("{{CSRF}}", generar_csrf(request))
    )


@app.get("/api/rutina/{jid}")
def api_rutina_obtener(jid: int, request: Request, fecha: str = ""):
    if not entrenador_logueado(request):
        return JSONResponse({"error": "No autenticado"}, status_code=403)
    with conn() as c:
        j = c.execute("SELECT nombre FROM jugadores WHERE id=%s", (jid,)).fetchone()
    if not j:
        return JSONResponse({"error": "No existe ese jugador"}, status_code=404)
    fecha = fecha or date.today().isoformat()
    sesion = obtener_sesion(jid, fecha) or {
        "fecha": fecha, "enfoque": "", "rpe_final": "", "objetivo": "",
        "objetivo_nota": "", "bloques": [],
    }
    sesion["jugador_nombre"] = j["nombre"]
    return sesion


@app.post("/api/rutina/{jid}")
async def api_rutina_guardar(jid: int, request: Request):
    if not entrenador_logueado(request):
        return JSONResponse({"error": "No autenticado"}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    if not csrf_valido(request, body.get("csrf_token", "")):
        return JSONResponse(
            {"error": "Sesión expirada. Recargá la página e intentá de nuevo."}, status_code=403
        )

    fecha = str(body.get("fecha", "")).strip()
    try:
        datetime.strptime(fecha, "%Y-%m-%d")
    except ValueError:
        return JSONResponse({"error": "Fecha inválida."}, status_code=400)

    enfoque = str(body.get("enfoque", "")).strip()
    rpe_final = str(body.get("rpe_final", "")).strip()
    objetivo = str(body.get("objetivo", "")).strip()
    objetivo_nota = str(body.get("objetivo_nota", "")).strip()

    bloques_in = body.get("bloques")
    if not isinstance(bloques_in, list):
        return JSONResponse({"error": "Formato inválido"}, status_code=400)

    bloques_limpios = []
    for b in bloques_in:
        if not isinstance(b, dict):
            return JSONResponse({"error": "Formato inválido"}, status_code=400)
        nombre = str(b.get("nombre", "")).strip()
        if not nombre:
            continue  # bloque sin nombre: se descarta en vez de rechazar todo el guardado
        try:
            minutos = int(b["minutos"]) if b.get("minutos") not in (None, "") else None
        except (TypeError, ValueError):
            minutos = None
        if minutos is not None:
            minutos = clamp(minutos, 0, 240)
        ejercicios_limpios = []
        for e in b.get("ejercicios") or []:
            if not isinstance(e, dict):
                continue
            actividad = str(e.get("actividad", "")).strip()
            if not actividad:
                continue  # ejercicio sin nombre: se descarta
            youtube_url = str(e.get("youtube_url", "")).strip()
            if not youtube_valida(youtube_url):
                return JSONResponse(
                    {"error": f'Link de YouTube inválido en "{actividad}". '
                              "Tiene que ser un link de youtube.com o youtu.be."},
                    status_code=400,
                )
            ejercicios_limpios.append({
                "actividad": actividad,
                "dosificacion": str(e.get("dosificacion", "")).strip(),
                "clave": str(e.get("clave", "")).strip(),
                "youtube_url": youtube_url,
            })
        bloques_limpios.append({"nombre": nombre, "minutos": minutos, "ejercicios": ejercicios_limpios})

    with conn() as c:
        j = c.execute("SELECT id FROM jugadores WHERE id=%s", (jid,)).fetchone()
        if not j:
            return JSONResponse({"error": "No existe ese jugador"}, status_code=404)
        fila_s = c.execute(
            """INSERT INTO sesiones (jugador_id, fecha, enfoque, rpe_final, objetivo, objetivo_nota, actualizado)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (jugador_id, fecha) DO UPDATE SET
                 enfoque=EXCLUDED.enfoque, rpe_final=EXCLUDED.rpe_final,
                 objetivo=EXCLUDED.objetivo, objetivo_nota=EXCLUDED.objetivo_nota,
                 actualizado=EXCLUDED.actualizado
               RETURNING id""",
            (jid, fecha, enfoque, rpe_final, objetivo, objetivo_nota,
             datetime.now().isoformat(timespec="seconds")),
        ).fetchone()
        sesion_id = fila_s["id"]
        c.execute("DELETE FROM bloques WHERE sesion_id=%s", (sesion_id,))
        for i, b in enumerate(bloques_limpios):
            fila_b = c.execute(
                "INSERT INTO bloques (sesion_id, orden, nombre, minutos) VALUES (%s,%s,%s,%s) RETURNING id",
                (sesion_id, i, b["nombre"], b["minutos"]),
            ).fetchone()
            for k, e in enumerate(b["ejercicios"]):
                c.execute(
                    """INSERT INTO ejercicios (bloque_id, orden, actividad, dosificacion, clave, youtube_url)
                       VALUES (%s,%s,%s,%s,%s,%s)""",
                    (fila_b["id"], k, e["actividad"], e["dosificacion"], e["clave"], e["youtube_url"]),
                )
    return {"ok": True}


@app.get("/mi-rutina", response_class=HTMLResponse)
def mi_rutina(request: Request, fecha: str = ""):
    j = jugador_logueado(request)
    if not j:
        return RedirectResponse("/login", status_code=303)
    try:
        fecha_dt = datetime.strptime(fecha, "%Y-%m-%d").date() if fecha else date.today()
    except ValueError:
        fecha_dt = date.today()
    sesion = obtener_sesion(j["id"], fecha_dt.isoformat())
    return HTMLResponse(_pagina_mi_rutina(j["nombre"], fecha_dt, sesion))


# ===========================================================================
#  ESTILO COMPARTIDO
# ===========================================================================
ESTILO = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@700;800;900&display=swap" rel="stylesheet">
<style>
  :root{
    --tinta:#10173f; --gris:#5b6577; --linea:#e4e7ee;
    --acento:#214EE0; --acento2:#1c3fc4; --ok:#1a7f5a; --rojo:#c0402a; --ambar:#c98a00;
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
  h1{font-family:"Bitter";font-weight:800;font-size:1.25rem;margin:0}
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
  .kpi .n{font-family:"Bitter";font-size:1.8rem;font-weight:800} .kpi .l{color:var(--gris);font-size:.8rem}
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
<title>Corey Strength · Mi día</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@500;600;700;800;900&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
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
  .escudo .mono{font-family:"Bitter";font-weight:800;font-size:24px;color:#fff}
  .wordmark{font-family:"Bitter";font-weight:800;font-size:21px;letter-spacing:.02em;line-height:1;white-space:nowrap}
  .wordmark small{display:block;font-weight:500;font-size:11px;letter-spacing:.18em;opacity:.7;margin-top:3px}
  .salir{margin-left:auto;color:#fff;opacity:.85;font-size:.78rem;font-weight:600;text-decoration:none;
    border:1px solid rgba(255,255,255,.4);border-radius:20px;padding:6px 12px;flex:none}
  .hero h1{font-family:"Bitter";font-weight:700;font-size:34px;line-height:1;margin:20px 0 4px}
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
  .titulo-sec{font-family:"Bitter";font-weight:700;font-size:1.05rem;margin:0 0 12px}
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
    font-family:"Bitter";font-weight:700;font-size:1.15rem;color:var(--negro);
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
    font-family:"Bitter";font-weight:700;font-size:1.1rem;cursor:pointer;
    transition:transform .08s, background .12s;box-shadow:0 6px 18px rgba(33,78,224,.35)}
  .guardar:hover{background:var(--azul-800)}
  .guardar:active{transform:scale(.99)}
  @media (prefers-reduced-motion: reduce){*{transition:none!important}}
</style></head>
<body><div class="app">
  <header class="hero">
    <div class="marca">
      <div class="escudo">
        <img src="/static/escudo.png" alt="Escudo Corey Strength" onerror="this.style.display='none';this.nextElementSibling.style.display='grid'">
        <span class="mono" style="display:none">C</span>
      </div>
      <div class="wordmark">COREY STRENGTH<small>RENDIMIENTO</small></div>
      <a href="/mi-rutina" class="salir">Mi rutina</a>
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
          <input type="number" id="minutos" name="minutos" min="0" max="600" value="0" inputmode="numeric">
        </div>
        <div class="campo" style="margin:0">
          <label for="sueno">Horas de sueño</label>
          <input type="number" id="sueno" name="sueno" step="0.5" min="0" max="24" value="8" inputmode="decimal">
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
<title>Corey Strength · Guardado</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@600;700;800;900&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0}
  body{font-family:"Inter",system-ui,sans-serif;background:#214EE0;color:#fff;
    min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;
    text-align:center;padding:40px;-webkit-font-smoothing:antialiased}
  .tic{width:80px;height:80px;border-radius:50%;background:#fff;color:#214EE0;font-size:42px;
    display:grid;place-items:center;margin-bottom:20px}
  h2{font-family:"Bitter";font-weight:800;font-size:2rem;margin-bottom:8px}
  .disp{font-family:"Bitter";font-weight:700;font-size:1.1rem;opacity:.95;margin-bottom:28px}
  a{background:#fff;color:#214EE0;text-decoration:none;padding:14px 28px;border-radius:12px;
    font-family:"Bitter";font-weight:700;font-size:1rem}
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
  h1{font-family:"Bitter";font-weight:800;font-size:1.6rem;margin:0 0 4px;color:#111318}
  p.sub{color:#6B7280;font-size:.9rem;margin:0 0 22px}
  label{display:block;font-weight:600;font-size:.88rem;margin:14px 0 6px;color:#111318}
  input{width:100%;padding:12px;border:1.5px solid #E6E8EE;border-radius:10px;font-size:1rem;font-family:inherit}
  input:focus{outline:none;border-color:#214EE0;box-shadow:0 0 0 4px #EDF1FE}
  .par{display:flex;gap:10px}.par>div{flex:1}
  button{width:100%;padding:14px;border:0;border-radius:12px;background:#214EE0;color:#fff;
    font-family:"Bitter";font-weight:700;font-size:1.02rem;margin-top:20px;cursor:pointer}
  .error{background:#fde8e2;color:#c0402a;padding:10px 12px;border-radius:10px;font-size:.85rem;margin:0 0 8px}
  .alt{text-align:center;margin-top:18px;font-size:.88rem;color:#6B7280}
  .alt a{color:#214EE0;font-weight:600;text-decoration:none}
</style>"""

# Variante de _ESTILO_CUENTA para las pantallas de jugador. Login y registro
# son su propia pantalla (fondo oscuro + marca chica + tarjeta), separada de
# la bienvenida (que tiene la imagen grande + los botones). El entrenador
# sigue con _ESTILO_CUENTA (fondo azul liso).
_ESTILO_CUENTA_JUGADOR = """
<style>
  *{box-sizing:border-box}
  body{margin:0;font-family:"Inter",system-ui,sans-serif;
    background:radial-gradient(ellipse at 50% 0%, #2c3a86 0%, #10173f 45%, #05081f 100%);
    min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;
    padding:24px;-webkit-font-smoothing:antialiased}
  .volver{align-self:flex-start;color:#aab4e8;text-decoration:none;font-size:.85rem;
    font-weight:600;margin:0 0 18px 4px}
  .marca{font-family:"Bitter";font-weight:800;font-size:1.35rem;letter-spacing:.03em;color:#fff;
    text-align:center;margin:0 0 22px}
  .marca small{display:block;font-weight:600;font-size:.68rem;letter-spacing:.2em;color:#9aa6e8;
    text-transform:uppercase;margin-top:5px}
  .card{background:#fff;border-radius:20px;padding:32px 26px;max-width:380px;width:100%;
    box-shadow:0 20px 50px rgba(5,8,31,.5)}
  h1{font-family:"Bitter";font-weight:800;font-size:1.6rem;margin:0 0 4px;color:#111318}
  p.sub{color:#6B7280;font-size:.9rem;margin:0 0 22px}
  label{display:block;font-weight:600;font-size:.88rem;margin:14px 0 6px;color:#111318}
  input{width:100%;padding:12px;border:1.5px solid #E6E8EE;border-radius:10px;font-size:1rem;font-family:inherit}
  input:focus{outline:none;border-color:#214EE0;box-shadow:0 0 0 4px #EDF1FE}
  .par{display:flex;gap:10px}.par>div{flex:1}
  button{width:100%;padding:14px;border:0;border-radius:12px;background:#214EE0;color:#fff;
    font-family:"Bitter";font-weight:700;font-size:1.02rem;margin-top:20px;cursor:pointer}
  .error{background:#fde8e2;color:#c0402a;padding:10px 12px;border-radius:10px;font-size:.85rem;margin:0 0 8px}
  .alt{text-align:center;margin-top:18px;font-size:.88rem;color:#6B7280}
  .alt a{color:#214EE0;font-weight:600;text-decoration:none}
</style>"""

_HEAD_FUENTES = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bitter:wght@700;800;900&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">"""

_ICONO_LAPIZ = ('<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" '
                'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                '<path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>')
_ICONO_PERSONA = ('<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" '
                   'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                   '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/></svg>')


def _boton_cuenta(href, icono, texto, activo):
    """Botón Regístrate/Inicia sesión. Si `activo` (ya estás en esa página),
    se dibuja como bloque sin link en vez de <a>, para no auto-navegar."""
    tag = "div" if activo else "a"
    href_attr = "" if activo else f' href="{href}"'
    clase = "btn activo" if activo else "btn"
    return (
        f'<{tag} class="{clase}"{href_attr}>'
        f'<span class="icono">{icono}</span><span class="txt">{texto}</span>'
        f"</{tag}>"
    )


def bloque_hero(activo=None):
    """Bloque compartido: imagen de marca completa + botones + redes.
    `activo` es None (bienvenida), "login" o "registro" (esa página)."""
    return f"""
  <div class="hero">
    <img src="/static/fondo-riocorey.png" alt="Corey Strength — Live the game.">
  </div>
  <div class="botones">
    {_boton_cuenta("/registro", _ICONO_LAPIZ, "Regístrate", activo == "registro")}
    {_boton_cuenta("/login", _ICONO_PERSONA, "Inicia sesión", activo == "login")}
  </div>
  <div class="redes">
    <a href="https://www.instagram.com/corey__hoops/" target="_blank" rel="noopener noreferrer" aria-label="Instagram"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="5"/><circle cx="12" cy="12" r="4"/><circle cx="17.5" cy="6.5" r="1" fill="currentColor" stroke="none"/></svg></a>
    <a href="https://riocoreybasquet.wixsite.com/coreyhoops" target="_blank" rel="noopener noreferrer" aria-label="Sitio web"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 4 6.1 4 9s-1.5 6.3-4 9c-2.5-2.7-4-6.1-4-9s1.5-6.3 4-9Z"/></svg></a>
    <a href="https://www.youtube.com/@riocorey" target="_blank" rel="noopener noreferrer" aria-label="YouTube"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="5" width="20" height="14" rx="4"/><path d="M10 9l6 3-6 3V9Z" fill="currentColor" stroke="none"/></svg></a>
  </div>"""


PAGINA_LOGIN = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey Strength · Ingresar</title>{_HEAD_FUENTES}{_ESTILO_CUENTA_JUGADOR}</head>
<body>
  <a href="/" class="volver">‹ Volver</a>
  <div class="marca">COREY STRENGTH</div>
  <div class="card">
    <h1>Bienvenido de vuelta</h1>
    <p class="sub">Ingresa para cargar tu día</p>
    {{{{ERROR}}}}
    <form method="post" action="/login">
      <input type="hidden" name="csrf_token" value="{{{{CSRF}}}}">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" required autofocus>
      <label for="password">Contraseña</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Ingresar</button>
    </form>
    <p class="alt">¿No tienes cuenta? <a href="/registro">Regístrate</a></p>
  </div>
</body></html>"""

PAGINA_REGISTRO = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey Strength · Crear cuenta</title>{_HEAD_FUENTES}{_ESTILO_CUENTA_JUGADOR}</head>
<body>
  <a href="/" class="volver">‹ Volver</a>
  <div class="marca">COREY STRENGTH</div>
  <div class="card">
    <h1>Crea tu cuenta</h1>
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
    <p class="alt">¿Ya tienes cuenta? <a href="/login">Ingresa</a></p>
  </div>
</body></html>"""

PAGINA_BIENVENIDA = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey Strength</title>{_HEAD_FUENTES}
<style>
  *{{box-sizing:border-box}}
  html,body{{margin:0}}
  body{{font-family:"Inter",system-ui,sans-serif;color:#fff;-webkit-font-smoothing:antialiased;
    background:#05081f;min-height:100vh;display:flex;flex-direction:column;align-items:center;
    text-align:center;overflow-x:hidden}}
  .hero{{width:100%;max-width:460px;position:relative}}
  .hero img{{width:100%;display:block}}
  .botones{{position:relative;z-index:2;width:100%;max-width:380px;margin:-16% auto 0;
    padding:0 28px;display:flex;flex-direction:column;gap:14px}}
  .btn{{display:flex;align-items:center;width:100%;padding:15px 22px;border-radius:999px;
    background:linear-gradient(135deg,#4266e0,#1c3fc4);color:#fff;text-decoration:none;
    font-family:"Bitter";font-weight:700;font-size:1.05rem;box-shadow:0 10px 24px rgba(28,63,196,.45);
    border:1px solid rgba(255,255,255,.15)}}
  .btn .icono{{width:32px;height:32px;border-radius:50%;background:rgba(255,255,255,.18);
    display:grid;place-items:center;flex:none}}
  .btn span.txt{{flex:1;text-align:center;margin-right:32px}}
  .redes{{position:relative;z-index:2;display:flex;gap:16px;margin:22px 0 32px}}
  .redes a{{color:#aab4e8;display:grid;place-items:center;width:36px;height:36px;
    border-radius:50%;border:1px solid rgba(170,180,232,.35)}}
</style></head>
<body>
  {bloque_hero()}
</body></html>"""

PAGINA_PIN = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{ESTILO}</head>
<body><div class="wrap"><header class="top"><div class="bola">🔒</div>
<div><h1>Administración</h1><p class="sub">Ingresa el PIN</p></div></header>
<div class="card"><form action="/admin" method="get">
<label>PIN</label><input type="password" name="pin" required autofocus>
<button class="enviar" type="submit">Entrar</button></form></div></div></body></html>"""

PAGINA_ENTRENADOR_LOGIN = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey Strength · Cuerpo técnico</title>{_HEAD_FUENTES}{_ESTILO_CUENTA}</head>
<body>
  <div class="card">
    <h1>Panel del cuerpo técnico</h1>
    <p class="sub">Ingresa con tu cuenta</p>
    {{{{ERROR}}}}
    <form method="post" action="/entrenador/login">
      <input type="hidden" name="csrf_token" value="{{{{CSRF}}}}">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" required autofocus>
      <label for="password">Contraseña</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Ingresar</button>
    </form>
    <p class="alt">¿No tienes cuenta? <a href="/entrenador/registro">Regístrate con el PIN del club</a></p>
  </div>
</body></html>"""

PAGINA_ENTRENADOR_REGISTRO = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Corey Strength · Cuerpo técnico</title>{_HEAD_FUENTES}{_ESTILO_CUENTA}</head>
<body>
  <div class="card">
    <h1>Crear cuenta de entrenador</h1>
    <p class="sub">Necesitas el PIN del club para registrarte</p>
    {{{{ERROR}}}}
    <form method="post" action="/entrenador/registro">
      <input type="hidden" name="csrf_token" value="{{{{CSRF}}}}">
      <label for="pin">PIN del club</label>
      <input type="password" id="pin" name="pin" required autofocus>
      <label for="nombre">Nombre y apellido</label>
      <input type="text" id="nombre" name="nombre" required>
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
    <p class="alt">¿Ya tienes cuenta? <a href="/entrenador/login">Ingresa</a></p>
  </div>
</body></html>"""

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
document.getElementById('nav').innerHTML =
  `<a href="/admin">⚙️ Gestionar jugadores</a>
   <a href="/api/export.csv">⬇️ Exportar CSV</a>
   <a href="/entrenador/logout">Salir</a>`;

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

fetch('/api/datos').then(r=>{{
  if(r.status===403){{ location.href='/entrenador/login'; throw new Error('no autenticado'); }}
  return r.json();
}}).then(d=>{{
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
      <td><a href="/jugador/${{j.id}}">Ver ficha →</a></td>`;
    tb.appendChild(tr);
  }});
  document.getElementById('alertas').innerHTML = alertasHTML;
  document.getElementById('kpis').innerHTML=`
    <div class="kpi"><div class="n">${{js.length}}</div><div class="l">Jugadores</div></div>
    <div class="kpi"><div class="n">${{cargaHoy}}</div><div class="l">Carga total hoy</div></div>
    <div class="kpi"><div class="n">${{enRiesgo}}</div><div class="l">ACWR en riesgo</div></div>
    <div class="kpi"><div class="n">${{dispBaja}}</div><div class="l">Disponibilidad baja</div></div>`;
}}).catch(()=>{{document.body.innerHTML='<div class="wrap"><p>Error: no se pudo cargar el panel.</p></div>'}});
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
const jid = location.pathname.split('/').pop();
document.getElementById('nav').innerHTML = `<a href="/panel">← Volver al panel</a><a href="/entrenador/rutina/${{jid}}">Editar rutina →</a>`;

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

fetch('/api/jugador/'+jid).then(r=>{{
  if(r.status===403){{ location.href='/entrenador/login'; throw new Error('no autenticado'); }}
  return r.json();
}}).then(d=>{{
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
  dibujar('c_carga', ult.map(x=>({{y:x.carga}})), '#214EE0', {{tipo:'barra'}});
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
}}).catch(()=>{{document.body.innerHTML='<div class="wrap"><p>Error: jugador inexistente.</p></div>'}});
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
<thead><tr><th>Nombre</th><th>Posición</th><th>Estado</th><th></th><th></th><th></th></tr></thead>
<tbody></tbody></table></div>
</div>
<script>
const pin = new URLSearchParams(location.search).get('pin');
const P = encodeURIComponent(pin);
document.getElementById('nav').innerHTML =
  '<a href="/panel">← Volver al panel</a><a href="/admin/entrenadores?pin='+P+'">Gestionar entrenadores →</a>';

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
      const nombreEsc = j.nombre.replace(/'/g, "\\\\'");
      const btnClave = j.email
        ? '<button class="btn" onclick="resetearClave('+j.id+',\\''+nombreEsc+'\\')">Resetear clave</button>'
        : '<span class="sub">sin cuenta</span>';
      const btnBorrar = '<button class="btn" style="color:var(--rojo);border-color:var(--rojo)" '+
        'onclick="borrar('+j.id+',\\''+nombreEsc+'\\')">Borrar</button>';
      tr.innerHTML='<td><b>'+j.nombre+'</b></td><td>'+(j.posicion||'—')+'</td><td>'+estado+'</td><td>'+btn+'</td><td>'+btnClave+'</td><td>'+btnBorrar+'</td>';
      tb.appendChild(tr);
    }});
  }});
}}
function estado(id,activo){{
  const fd=new FormData(); fd.append('pin',pin); fd.append('jugador_id',id); fd.append('activo',activo);
  fetch('/admin/estado',{{method:'POST',body:fd}}).then(()=>cargar());
}}
function borrar(id,nombre){{
  if(!confirm('¿BORRAR a '+nombre+' para siempre? Se pierde todo su historial de cargas y su rutina, '+
    'no se puede deshacer.\\n\\nSi solo querés que no pueda ingresar, usá "Dar de baja" en cambio.')) return;
  const fd=new FormData(); fd.append('pin',pin); fd.append('jugador_id',id);
  fetch('/admin/jugador/borrar',{{method:'POST',body:fd}}).then(r=>r.json()).then(res=>{{
    if(res.error){{ alert('Error: '+res.error); return; }}
    cargar();
  }});
}}
function resetearClave(id,nombre){{
  if(!confirm('¿Resetear la clave de '+nombre+'? La contraseña anterior deja de funcionar.')) return;
  const fd=new FormData(); fd.append('pin',pin); fd.append('jugador_id',id);
  fetch('/admin/resetear_clave',{{method:'POST',body:fd}}).then(r=>r.json()).then(res=>{{
    if(res.error){{ alert('Error: '+res.error); return; }}
    alert('Nueva clave de '+res.nombre+':\\n\\n'+res.clave_nueva+'\\n\\nPasásela ahora, no queda guardada en ningún lado.');
  }});
}}
document.getElementById('btnAdd').onclick=function(){{
  const nombre=document.getElementById('nombre').value;
  const posicion=document.getElementById('posicion').value;
  const msg=document.getElementById('msg');
  if(!nombre.trim()){{ msg.textContent='Ingresa un nombre.'; return; }}
  const fd=new FormData(); fd.append('pin',pin); fd.append('nombre',nombre); fd.append('posicion',posicion);
  fetch('/admin/agregar',{{method:'POST',body:fd}}).then(r=>r.json()).then(res=>{{
    if(res.error){{ msg.textContent=res.error; return; }}
    document.getElementById('nombre').value=''; document.getElementById('posicion').value='';
    msg.textContent='Agregado ✔'; cargar();
  }});
}};
cargar();
</script></body></html>"""

PAGINA_ADMIN_ENTRENADORES = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gestionar entrenadores</title>{ESTILO}</head>
<body><div class="wrap">
<div class="nav" id="nav"></div>
<header class="top"><div class="bola">🧑‍🏫</div>
<div><h1>Gestionar entrenadores</h1><p class="sub">Cuerpo técnico con acceso al panel</p></div></header>
<div class="tabla-wrap"><table id="tabla">
<thead><tr><th>Nombre</th><th>Email</th><th></th></tr></thead>
<tbody></tbody></table></div>
</div>
<script>
const pin = new URLSearchParams(location.search).get('pin');
const P = encodeURIComponent(pin);
document.getElementById('nav').innerHTML =
  '<a href="/panel">← Volver al panel</a><a href="/admin?pin='+P+'">Gestionar jugadores →</a>';

function cargar(){{
  fetch('/api/entrenadores?pin='+P).then(r=>r.json()).then(d=>{{
    const tb=document.querySelector('#tabla tbody'); tb.innerHTML='';
    const lista = d.entrenadores||[];
    if(!lista.length){{
      tb.innerHTML='<tr><td colspan="3" class="sub">Todavía no hay entrenadores registrados.</td></tr>';
      return;
    }}
    lista.forEach(e=>{{
      const tr=document.createElement('tr');
      const nombreEsc = e.nombre.replace(/'/g, "\\\\'");
      const emailEsc = e.email.replace(/'/g, "\\\\'");
      tr.innerHTML='<td><b>'+e.nombre+'</b></td><td>'+e.email+'</td>'+
        '<td><button class="btn" onclick="borrar(\\''+emailEsc+'\\',\\''+nombreEsc+'\\')">Borrar</button></td>';
      tb.appendChild(tr);
    }});
  }});
}}
function borrar(email,nombre){{
  if(!confirm('¿Borrar la cuenta de '+nombre+'? No va a poder entrar más al panel.')) return;
  const fd=new FormData(); fd.append('pin',pin); fd.append('email',email);
  fetch('/admin/entrenador/borrar',{{method:'POST',body:fd}}).then(r=>r.json()).then(res=>{{
    if(res.error){{ alert('Error: '+res.error); return; }}
    cargar();
  }});
}}
cargar();
</script></body></html>"""

# ===========================================================================
#  RUTINA DE ENTRENAMIENTO — páginas
# ===========================================================================
PAGINA_RUTINA_EDITAR = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rutina — Jugador</title>""" + ESTILO + """
<style>
  .bloque-card{background:#fff;border:1px solid var(--linea);border-radius:14px;
    padding:16px;margin-bottom:14px}
  .bloque-head{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
  .bloque-head input[type="text"]{flex:1;min-width:160px}
  .bloque-head input[type="number"]{width:90px}
  .fila-ejercicio{display:grid;grid-template-columns:1.3fr 1fr 1fr 1.3fr auto;
    gap:8px;margin-bottom:8px;align-items:center}
  .fila-ejercicio input{padding:9px 10px;border:1px solid var(--linea);border-radius:8px;
    font-size:.88rem;font-family:inherit;width:100%}
  .fila-cabecera{display:grid;grid-template-columns:1.3fr 1fr 1fr 1.3fr auto;
    gap:8px;font-size:.72rem;text-transform:uppercase;letter-spacing:.03em;
    color:var(--gris);margin-bottom:6px}
  .quitar{background:none;border:0;color:var(--rojo);cursor:pointer;font-size:1.1rem;
    padding:4px 8px}
  .agregar-ejercicio{background:none;border:1px dashed var(--linea);border-radius:8px;
    color:var(--acento2);font-weight:600;padding:8px 12px;cursor:pointer;font-size:.85rem;
    margin-top:4px}
  .quitar-bloque{background:none;border:0;color:var(--rojo);cursor:pointer;
    font-weight:600;font-size:.85rem;flex:none}
  .agregar-bloque{width:100%;padding:14px;border:2px dashed var(--linea);border-radius:14px;
    background:none;color:var(--gris);font-weight:700;cursor:pointer;margin-bottom:16px}
  .barra-guardar{position:sticky;bottom:0;background:#fff;padding:14px 0;
    border-top:1px solid var(--linea);margin-top:8px}
  .msg-ok{background:#e2f4ec;color:var(--ok);padding:10px 12px;border-radius:10px;
    font-size:.86rem;margin-bottom:10px}
  .sesion-form{background:#fff;border:1px solid var(--linea);border-radius:14px;
    padding:16px;margin-bottom:16px}
  .sesion-form label{display:block;font-weight:600;font-size:.82rem;margin:0 0 6px}
  .sesion-form input{width:100%;padding:10px 12px;border:1px solid var(--linea);
    border-radius:8px;font-size:.9rem;font-family:inherit;margin-bottom:12px}
  .sesion-form input:disabled{background:#f6f7fb;color:var(--gris)}
  .fila-campos{display:flex;gap:12px}
  .fila-campos>div{flex:1}
  @media (max-width:640px){
    .fila-ejercicio,.fila-cabecera{grid-template-columns:1fr;gap:4px}
    .fila-cabecera{display:none}
    .fila-campos{flex-direction:column;gap:0}
  }
</style></head>
<body><div class="wrap wide">
<div class="nav"><a href="/jugador/{{JID}}">← Volver a la ficha</a></div>
<header class="top"><div class="bola">🏋️</div>
<div><h1 id="nombre">Rutina</h1><p class="sub">Elegí el día y cargá la sesión de ese día</p></div></header>
<div class="sesion-form">
  <label for="fecha">Fecha de la sesión</label>
  <input type="date" id="fecha">
  <div class="fila-campos">
    <div><label for="enfoque">Enfoque de la sesión</label>
      <input type="text" id="enfoque" placeholder="Ej: Potencia · fuerza · acondicionamiento"></div>
  </div>
  <div class="fila-campos">
    <div><label for="rpeFinal">RPE final</label>
      <input type="text" id="rpeFinal" placeholder="Ej: 7-8/10"></div>
    <div><label for="duracionTotal">Duración total</label>
      <input type="text" id="duracionTotal" disabled></div>
  </div>
  <div class="fila-campos">
    <div><label for="objetivo">Objetivo</label>
      <input type="text" id="objetivo" placeholder="Ej: Estímulo fuerte de cuerpo completo"></div>
    <div><label for="objetivoNota">Nota del objetivo</label>
      <input type="text" id="objetivoNota" placeholder="Ej: Sin llegar al fallo"></div>
  </div>
</div>
<div id="mensaje"></div>
<div id="bloques"></div>
<button type="button" class="agregar-bloque" id="agregarBloque">+ Agregar bloque</button>
<div class="barra-guardar">
  <button class="btn btn-p" id="guardar" style="width:100%;padding:14px;font-size:1rem">Guardar rutina</button>
</div>
</div>
<script>
const jid = "{{JID}}";
const CSRF = "{{CSRF}}";
let rutina = {bloques: []};
let sesionActual = {enfoque:'', rpe_final:'', objetivo:'', objetivo_nota:''};

function esc(s){
  return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/"/g,'&quot;')
    .replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function hoyISO(){
  const d = new Date();
  return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
}

function actualizarDuracion(){
  const total = rutina.bloques.reduce((s,b)=> s+(b.minutos||0), 0);
  document.getElementById('duracionTotal').value = total+' min';
}

function render(){
  actualizarDuracion();
  const cont = document.getElementById('bloques');
  if(!rutina.bloques.length){
    cont.innerHTML = '<p class="sub">Todavía no hay bloques. Agregá el primero.</p>';
    return;
  }
  cont.innerHTML = rutina.bloques.map((b, bi) => `
    <div class="bloque-card">
      <div class="bloque-head">
        <input type="text" placeholder="Nombre del bloque (ej: Calentamiento)"
          value="${esc(b.nombre)}" data-b="${bi}" class="in-bloque-nombre">
        <input type="number" placeholder="Min." min="0" max="240"
          value="${b.minutos==null?'':b.minutos}" data-b="${bi}" class="in-bloque-min">
        <button type="button" class="quitar-bloque" data-b="${bi}">✕ Quitar bloque</button>
      </div>
      <div class="fila-cabecera">
        <div>Actividad</div><div>Dosificación</div><div>Clave</div><div>Link de YouTube</div><div></div>
      </div>
      ${b.ejercicios.map((e, ei) => `
        <div class="fila-ejercicio">
          <input type="text" placeholder="Actividad" value="${esc(e.actividad)}"
            data-b="${bi}" data-e="${ei}" class="in-actividad">
          <input type="text" placeholder="Ej: 3 × 10" value="${esc(e.dosificacion)}"
            data-b="${bi}" data-e="${ei}" class="in-dosificacion">
          <input type="text" placeholder="Clave técnica" value="${esc(e.clave)}"
            data-b="${bi}" data-e="${ei}" class="in-clave">
          <input type="url" placeholder="https://youtube.com/..." value="${esc(e.youtube_url)}"
            data-b="${bi}" data-e="${ei}" class="in-youtube">
          <button type="button" class="quitar" data-b="${bi}" data-e="${ei}" title="Quitar ejercicio">✕</button>
        </div>`).join('')}
      <button type="button" class="agregar-ejercicio" data-b="${bi}">+ Agregar ejercicio</button>
    </div>`).join('');
}

document.getElementById('bloques').addEventListener('input', e => {
  const t = e.target, bi = t.dataset.b, ei = t.dataset.e;
  if(bi===undefined) return;
  const b = rutina.bloques[bi];
  if(!b) return;
  if(t.classList.contains('in-bloque-nombre')) b.nombre = t.value;
  else if(t.classList.contains('in-bloque-min')){
    b.minutos = t.value===''?null:parseInt(t.value,10);
    actualizarDuracion();
  }
  else if(ei!==undefined && b.ejercicios[ei]){
    const ej = b.ejercicios[ei];
    if(t.classList.contains('in-actividad')) ej.actividad = t.value;
    else if(t.classList.contains('in-dosificacion')) ej.dosificacion = t.value;
    else if(t.classList.contains('in-clave')) ej.clave = t.value;
    else if(t.classList.contains('in-youtube')) ej.youtube_url = t.value;
  }
});

document.getElementById('bloques').addEventListener('click', e => {
  const t = e.target;
  if(t.classList.contains('quitar-bloque')){
    rutina.bloques.splice(parseInt(t.dataset.b,10), 1);
    render();
  } else if(t.classList.contains('agregar-ejercicio')){
    rutina.bloques[parseInt(t.dataset.b,10)].ejercicios.push(
      {actividad:'', dosificacion:'', clave:'', youtube_url:''});
    render();
  } else if(t.classList.contains('quitar')){
    rutina.bloques[parseInt(t.dataset.b,10)].ejercicios.splice(parseInt(t.dataset.e,10), 1);
    render();
  }
});

document.getElementById('agregarBloque').onclick = () => {
  rutina.bloques.push({nombre:'', minutos:null, ejercicios:[]});
  render();
};

document.getElementById('fecha').value = hoyISO();
document.getElementById('fecha').onchange = cargar;
document.getElementById('enfoque').oninput = e => sesionActual.enfoque = e.target.value;
document.getElementById('rpeFinal').oninput = e => sesionActual.rpe_final = e.target.value;
document.getElementById('objetivo').oninput = e => sesionActual.objetivo = e.target.value;
document.getElementById('objetivoNota').oninput = e => sesionActual.objetivo_nota = e.target.value;

document.getElementById('guardar').onclick = () => {
  const msg = document.getElementById('mensaje');
  msg.innerHTML = '';
  fetch('/api/rutina/'+jid, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      csrf_token: CSRF,
      fecha: document.getElementById('fecha').value,
      enfoque: sesionActual.enfoque, rpe_final: sesionActual.rpe_final,
      objetivo: sesionActual.objetivo, objetivo_nota: sesionActual.objetivo_nota,
      bloques: rutina.bloques,
    }),
  }).then(r => r.json()).then(d => {
    if(d.error){
      msg.innerHTML = '<div class="alerta">'+esc(d.error)+'</div>';
    } else {
      msg.innerHTML = '<div class="msg-ok">Sesión guardada ✅</div>';
      cargar();
    }
  }).catch(() => { msg.innerHTML = '<div class="alerta">No se pudo guardar. Probá de nuevo.</div>'; });
};

function cargar(){
  const fecha = document.getElementById('fecha').value;
  fetch('/api/rutina/'+jid+'?fecha='+fecha).then(r => {
    if(r.status===403){ location.href='/entrenador/login'; throw new Error('no autenticado'); }
    return r.json();
  }).then(d => {
    if(d.error){
      document.body.innerHTML = '<div class="wrap"><p>Error: '+esc(d.error)+'</p></div>';
      return;
    }
    document.getElementById('nombre').textContent = 'Rutina de ' + d.jugador_nombre;
    sesionActual = {
      enfoque: d.enfoque||'', rpe_final: d.rpe_final||'',
      objetivo: d.objetivo||'', objetivo_nota: d.objetivo_nota||'',
    };
    document.getElementById('enfoque').value = sesionActual.enfoque;
    document.getElementById('rpeFinal').value = sesionActual.rpe_final;
    document.getElementById('objetivo').value = sesionActual.objetivo;
    document.getElementById('objetivoNota').value = sesionActual.objetivo_nota;
    rutina = {bloques: (d.bloques||[]).map(b => ({
      nombre: b.nombre, minutos: b.minutos,
      ejercicios: (b.ejercicios||[]).map(e => ({
        actividad: e.actividad, dosificacion: e.dosificacion,
        clave: e.clave, youtube_url: e.youtube_url,
      })),
    }))};
    render();
  });
}
cargar();
</script>
</body></html>"""

PAGINA_MI_RUTINA_BASE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mi rutina</title>""" + ESTILO + """
<style>
  body{background:#f6f7fb}
  .bloque{background:#fff;border:1px solid var(--linea);border-radius:14px;
    overflow:hidden;margin-bottom:16px}
  .bloque-head{background:var(--tinta);color:#fff;padding:12px 16px;
    display:flex;justify-content:space-between;align-items:center;font-weight:700}
  .bloque-head .min{font-weight:600;font-size:.85rem;opacity:.85}
  .ver-tecnica{color:var(--acento2);font-weight:700;text-decoration:none;font-size:.85rem;
    white-space:nowrap}
  .sesion-nav{display:flex;justify-content:space-between;align-items:center;
    margin-bottom:14px;font-size:.85rem}
  .sesion-nav a{color:var(--acento2);font-weight:600;text-decoration:none}
  .sesion-nav span{color:var(--gris);font-weight:600;text-transform:capitalize}
  .sesion-titulo{background:#dbe7fb;color:var(--tinta);text-align:center;
    font-family:"Bitter";font-weight:800;padding:14px;border-radius:14px 14px 0 0;
    letter-spacing:.02em}
  .sesion-enfoque{background:var(--tinta);color:#c3d0f7;text-align:center;
    padding:10px;font-size:.85rem;font-weight:600}
  .sesion-info{background:#fff;border:1px solid var(--linea);border-top:0;
    border-radius:0 0 14px 14px;margin-bottom:16px;overflow:hidden}
  .fila-info{display:flex;border-bottom:1px solid var(--linea)}
  .fila-info:last-child{border-bottom:0}
  .fila-info>div{padding:10px 14px;font-weight:600;font-size:.88rem;flex:1}
  .etiqueta{display:block;font-size:.68rem;text-transform:uppercase;
    letter-spacing:.05em;color:var(--gris);font-weight:700;margin-bottom:2px}
  .nota-verde{background:#e2f4ec;color:var(--ok);display:flex;align-items:center;
    justify-content:center;padding:10px 14px;font-weight:700;font-size:.85rem;
    text-align:center;flex:0 0 200px}
  @media (max-width:600px){
    .fila-info{flex-direction:column}
    .nota-verde{flex:none}
  }
</style></head>
<body><div class="wrap wide">
<div class="nav"><a href="/">← Volver a mi día</a></div>
<header class="top"><div class="bola">🏋️</div>
<div><h1>Mi rutina</h1><p class="sub">{{NOMBRE}}</p></div></header>
{{CONTENIDO}}
</div></body></html>"""


_DIAS_ES = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
_MESES_ES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
             "septiembre", "octubre", "noviembre", "diciembre"]


def _fecha_larga_es(d) -> str:
    """'sábado 05 de septiembre', sin depender del locale del servidor
    (Render no tiene configurado es_AR, así que strftime da nombres en inglés)."""
    return f"{_DIAS_ES[d.weekday()]} {d.day:02d} de {_MESES_ES[d.month - 1]}"


def _pagina_mi_rutina(nombre_jugador, fecha_dt, sesion):
    fecha_ant = (fecha_dt - timedelta(days=1)).isoformat()
    fecha_sig = (fecha_dt + timedelta(days=1)).isoformat()
    fecha_larga = _fecha_larga_es(fecha_dt)
    nav = (
        '<div class="sesion-nav">'
        f'<a href="/mi-rutina?fecha={fecha_ant}">‹ Día anterior</a>'
        f'<span>{html.escape(fecha_larga)}</span>'
        f'<a href="/mi-rutina?fecha={fecha_sig}">Día siguiente ›</a>'
        "</div>"
    )

    if not sesion or not sesion["bloques"]:
        contenido = nav + '<p class="sub">Todavía no tenés una sesión cargada para este día. Consultá con tu entrenador.</p>'
        return PAGINA_MI_RUTINA_BASE.replace("{{NOMBRE}}", html.escape(nombre_jugador)).replace(
            "{{CONTENIDO}}", contenido
        )

    duracion_total = sum((b["minutos"] or 0) for b in sesion["bloques"])
    primer_nombre = nombre_jugador.split(" ")[0].upper()
    titulo = f'SESIÓN {fecha_dt.strftime("%d-%m")} — {html.escape(primer_nombre)}'
    cabecera = f'<div class="sesion-titulo">{titulo}</div>'
    if sesion["enfoque"]:
        cabecera += f'<div class="sesion-enfoque">{html.escape(sesion["enfoque"])}</div>'

    fila1 = (
        f'<div><span class="etiqueta">Deportista</span>{html.escape(nombre_jugador)}</div>'
        f'<div><span class="etiqueta">Duración</span>{duracion_total} min</div>'
    )
    if sesion["rpe_final"]:
        fila1 += f'<div class="nota-verde">RPE final: {html.escape(sesion["rpe_final"])}</div>'
    info = f'<div class="fila-info">{fila1}</div>'
    if sesion["objetivo"]:
        fila2 = f'<div><span class="etiqueta">Objetivo</span>{html.escape(sesion["objetivo"])}</div>'
        if sesion["objetivo_nota"]:
            fila2 += f'<div class="nota-verde">{html.escape(sesion["objetivo_nota"])}</div>'
        info += f'<div class="fila-info">{fila2}</div>'
    cabecera += f'<div class="sesion-info">{info}</div>'

    partes = []
    for b in sesion["bloques"]:
        filas = []
        for e in b["ejercicios"]:
            if e["youtube_url"]:
                link = (
                    f'<a href="{html.escape(e["youtube_url"])}" target="_blank" '
                    f'rel="noopener noreferrer" class="ver-tecnica">▶ Ver técnica</a>'
                )
            else:
                link = "—"
            filas.append(
                "<tr><td>" + html.escape(e["actividad"]) + "</td>"
                "<td>" + html.escape(e["dosificacion"] or "—") + "</td>"
                "<td>" + html.escape(e["clave"] or "—") + "</td>"
                "<td>" + link + "</td></tr>"
            )
        minutos = f'{b["minutos"]} min' if b["minutos"] else ""
        partes.append(
            '<div class="bloque"><div class="bloque-head"><span>'
            + html.escape(b["nombre"]) + '</span><span class="min">' + minutos + "</span></div>"
            '<div class="tabla-wrap" style="border:0;border-radius:0"><table>'
            "<thead><tr><th>Actividad</th><th>Dosificación</th><th>Clave</th><th>Técnica</th></tr></thead>"
            "<tbody>" + "".join(filas) + "</tbody></table></div></div>"
        )

    contenido = nav + cabecera + "".join(partes)
    return PAGINA_MI_RUTINA_BASE.replace("{{NOMBRE}}", html.escape(nombre_jugador)).replace(
        "{{CONTENIDO}}", contenido
    )