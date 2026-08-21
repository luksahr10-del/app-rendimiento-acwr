"""
App de monitoreo de rendimiento físico — Club de básquet semipro (v2).

Corré con:  uvicorn main:app --reload --host 0.0.0.0 --port 8000
- Jugador:    http://<tu-ip>:8000/
- Entrenador: http://<tu-ip>:8000/panel     (PIN por defecto: 1234)
- Admin:      http://<tu-ip>:8000/admin      (mismo PIN)

Novedades v2:
  * Alta/baja de jugadores desde la web (sin tocar la base a mano).
  * Ficha individual con gráficos de tendencia (carga, fatiga, sueño).
  * ACWR (ratio carga aguda/crónica): estima riesgo de lesión.
  * Índice de disponibilidad (readiness) 0-100 por sueño/fatiga/molestias.
  * Alertas automáticas (fatiga sostenida, ACWR en zona de riesgo).
  * Un registro por jugador por día (si repite, se actualiza).
  * Exportar todo a CSV.
"""

import csv
import io
import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

DB = Path(__file__).parent / "datos.db"
PIN_ENTRENADOR = "1234"  # cambialo por uno propio

app = FastAPI(title="Monitoreo Rendimiento")


# ===========================================================================
#  BASE DE DATOS
# ===========================================================================
def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS jugadores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT UNIQUE NOT NULL,
                posicion TEXT DEFAULT '',
                activo INTEGER NOT NULL DEFAULT 1
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS registros (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                jugador_id INTEGER NOT NULL,
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
                UNIQUE (jugador_id, fecha),
                FOREIGN KEY (jugador_id) REFERENCES jugadores (id)
            )
        """)
        n = c.execute("SELECT COUNT(*) FROM jugadores").fetchone()[0]
        if n == 0:
            ejemplos = [("Juan Pérez", "Base"), ("Marcos Díaz", "Alero"),
                        ("Lucas Romero", "Pívot")]
            c.executemany("INSERT INTO jugadores (nombre, posicion) VALUES (?,?)", ejemplos)


init_db()


# ===========================================================================
#  MÉTRICAS (ciencias del deporte)
# ===========================================================================
def carga(rpe, minutos):
    """Carga de la sesión = RPE x minutos (session-RPE, estándar del rubro)."""
    return (rpe or 0) * (minutos or 0)


def readiness(sueno, fatiga, molestias):
    """Índice de disponibilidad 0-100: mezcla sueño, fatiga y molestias.
    Simple y transparente a propósito, para que puedas ajustarlo."""
    s = min((sueno or 0) / 8.0, 1.0)              # 8h = puntaje pleno
    f = (5 - (fatiga or 3)) / 4.0                  # fatiga 1(fresco)->5(agotado)
    m = 0.5 if (molestias or "").strip() else 1.0  # hay molestia = penaliza
    return round(100 * (0.4 * s + 0.4 * f + 0.2 * m))


def acwr_de(cargas_por_fecha, hasta):
    """ACWR = carga aguda (prom. diario últimos 7 días) / crónica (últimos 28).
    Zona ideal 0.8-1.3; > 1.5 = riesgo de lesión elevado.
    `cargas_por_fecha`: dict {fecha_iso: carga_total_del_dia}."""
    def prom(dias):
        ini = hasta - timedelta(days=dias - 1)
        total = sum(v for f, v in cargas_por_fecha.items()
                    if ini.isoformat() <= f <= hasta.isoformat())
        return total / dias
    aguda = prom(7)
    cronica = prom(28)
    if cronica == 0:
        return None
    return round(aguda / cronica, 2)


def datos_jugador(jid):
    """Junta registros + métricas derivadas de un jugador."""
    with conn() as c:
        j = c.execute("SELECT * FROM jugadores WHERE id=?", (jid,)).fetchone()
        if not j:
            return None
        regs = c.execute(
            "SELECT * FROM registros WHERE jugador_id=? ORDER BY fecha", (jid,)
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

    # Alertas
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
@app.get("/", response_class=HTMLResponse)
def formulario():
    with conn() as c:
        jugadores = c.execute(
            "SELECT id, nombre FROM jugadores WHERE activo=1 ORDER BY nombre"
        ).fetchall()
    opciones = "".join(f'<option value="{j["id"]}">{j["nombre"]}</option>' for j in jugadores)
    return PAGINA_JUGADOR.replace("{{OPCIONES}}", opciones).replace("{{HOY}}", date.today().isoformat())


@app.post("/registrar")
def registrar(
    jugador_id: int = Form(...),
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
    with conn() as c:
        # Upsert: un registro por jugador por día
        c.execute(
            """INSERT INTO registros
               (jugador_id, fecha, entreno, rpe, minutos, fatiga, sueno, comida,
                rutina_ok, molestias, creado)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(jugador_id, fecha) DO UPDATE SET
                 entreno=excluded.entreno, rpe=excluded.rpe, minutos=excluded.minutos,
                 fatiga=excluded.fatiga, sueno=excluded.sueno, comida=excluded.comida,
                 rutina_ok=excluded.rutina_ok, molestias=excluded.molestias,
                 creado=excluded.creado""",
            (jugador_id, fecha, entreno, rpe, minutos, fatiga, sueno, comida,
             rutina_ok, molestias, datetime.now().isoformat(timespec="seconds")),
        )
    r = readiness(sueno, fatiga, molestias)
    return HTMLResponse(PAGINA_OK.replace("{{READY}}", str(r)))


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
            c.execute("INSERT INTO jugadores (nombre, posicion) VALUES (?,?)",
                      (nombre, posicion.strip()))
    except sqlite3.IntegrityError:
        return JSONResponse({"error": "Ya existe un jugador con ese nombre"}, status_code=400)
    return {"ok": True}


@app.post("/admin/estado")
def admin_estado(pin: str = Form(...), jugador_id: int = Form(...), activo: int = Form(...)):
    if pin != PIN_ENTRENADOR:
        return JSONResponse({"error": "PIN inválido"}, status_code=403)
    with conn() as c:
        c.execute("UPDATE jugadores SET activo=? WHERE id=?", (activo, jugador_id))
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
PAGINA_JUGADOR = f"""<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mi día — Rendimiento</title>{ESTILO}</head><body><div class="wrap">
<header class="top"><div class="bola">🏀</div>
<div><h1>Mi día</h1><p class="sub">Cargá tus datos en 1 minuto</p></div></header>
<form action="/registrar" method="post">
<div class="card">
  <label>Jugador</label>
  <select name="jugador_id" required>{{{{OPCIONES}}}}</select>
  <label>Fecha</label>
  <input type="date" name="fecha" value="{{{{HOY}}}}" required>
  <label>¿Entrenaste hoy?</label>
  <div class="seg">
    <input type="radio" name="entreno" id="e1" value="1" checked><label for="e1">Sí</label>
    <input type="radio" name="entreno" id="e0" value="0"><label for="e0">No</label>
  </div>
</div>
<div class="card">
  <label>Intensidad del entrenamiento (RPE)</label>
  <div class="seg">
    {"".join(f'<input type="radio" name="rpe" id="r{i}" value="{i}"><label for="r{i}">{i}</label>' for i in range(1,11))}
  </div>
  <p class="ayuda">1 = muy suave · 10 = máximo esfuerzo</p>
  <div class="fila">
    <div><label>Minutos</label><input type="number" name="minutos" min="0" value="0"></div>
    <div><label>Horas de sueño</label><input type="number" name="sueno" step="0.5" min="0" value="8"></div>
  </div>
  <label>Nivel de cansancio</label>
  <div class="seg">
    {"".join(f'<input type="radio" name="fatiga" id="f{i}" value="{i}"{" checked" if i==3 else ""}><label for="f{i}">{i}</label>' for i in range(1,6))}
  </div>
  <p class="ayuda">1 = fresco · 5 = agotado</p>
</div>
<div class="card">
  <label>¿Completaste tu rutina asignada?</label>
  <div class="seg">
    <input type="radio" name="rutina_ok" id="ro1" value="1" checked><label for="ro1">Sí</label>
    <input type="radio" name="rutina_ok" id="ro0" value="0"><label for="ro0">No</label>
  </div>
  <label>¿Qué comiste hoy?</label>
  <textarea name="comida" placeholder="Desayuno, almuerzo, cena, snacks..."></textarea>
  <label>Molestias o dolores (opcional)</label>
  <textarea name="molestias" placeholder="Ej: molestia en rodilla derecha"></textarea>
</div>
<button class="enviar" type="submit">Enviar registro</button>
</form></div></body></html>"""

PAGINA_OK = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{ESTILO}</head>
<body><div class="wrap"><div class="exito">
<div class="big">✅</div><h1>¡Registrado!</h1>
<p class="sub">Tu disponibilidad de hoy: <b>{{{{READY}}}}/100</b></p>
<p style="margin-top:30px"><a href="/">← Cargar otro</a></p>
</div></div></body></html>"""

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

// Mini-gráfico en SVG, sin librerías externas
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