"""Tests de integración: levantan la app real (FastAPI TestClient) contra un
Postgres descartable (ver tests/conftest.py) y prueban los controles de
seguridad que más nos importan: CSRF, rate limiting, y que las rutas
protegidas por sesión (jugador/entrenador) o PIN (admin) rechacen a quien
no corresponde. No corren contra la base de producción (Supabase).
"""
import re

import pytest
from fastapi.testclient import TestClient

import main as app_module

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]*)"')


def csrf_de(html: str) -> str:
    m = CSRF_RE.search(html)
    assert m, "no se encontró csrf_token en la página"
    return m.group(1)


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    """Los contadores de intentos fallidos son diccionarios a nivel módulo:
    sin este reset, los tests se contaminarían entre sí."""
    app_module._intentos_por_ip.clear()
    app_module._intentos_por_email.clear()
    yield


@pytest.fixture
def client():
    return TestClient(app_module.app)


def registrar_jugador(client, nombre, email, password="secreto123"):
    r = client.get("/registro")
    token = csrf_de(r.text)
    return client.post(
        "/registro",
        data={
            "csrf_token": token,
            "nombre": nombre,
            "posicion": "",
            "email": email,
            "password": password,
            "password2": password,
        },
        follow_redirects=False,
    )


def registrar_entrenador(client, nombre, email, password="secreto123", pin="999999"):
    r = client.get("/entrenador/registro")
    token = csrf_de(r.text)
    return client.post(
        "/entrenador/registro",
        data={
            "csrf_token": token,
            "pin": pin,
            "nombre": nombre,
            "email": email,
            "password": password,
            "password2": password,
        },
        follow_redirects=False,
    )


def test_bienvenida_sin_sesion_muestra_botones(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Regístrate" in r.text
    assert "Inicia sesión" in r.text


def test_head_en_raiz_no_rompe(client):
    r = client.request("HEAD", "/")
    assert r.status_code == 200


def test_registro_y_login_de_jugador(client):
    r = registrar_jugador(client, "Integracion Uno", "integracion1@example.com")
    assert r.status_code == 303
    assert r.headers["location"] == "/"

    # el registro ya deja logueado
    r = client.get("/")
    assert "Hola, Integracion Uno" in r.text


def test_registro_rechaza_csrf_invalido(client):
    r = client.post(
        "/registro",
        data={
            "csrf_token": "un-token-inventado",
            "nombre": "Nadie",
            "posicion": "",
            "email": "nadie@example.com",
            "password": "secreto123",
            "password2": "secreto123",
        },
    )
    assert r.status_code == 403


def test_registro_rechaza_email_duplicado(client):
    registrar_jugador(client, "Dup Uno", "duplicado@example.com")
    # un cliente nuevo, sin la sesión del anterior
    otro = TestClient(app_module.app)
    r = otro.get("/registro")
    token = csrf_de(r.text)
    r = otro.post(
        "/registro",
        data={
            "csrf_token": token,
            "nombre": "Dup Dos",
            "posicion": "",
            "email": "duplicado@example.com",
            "password": "secreto123",
            "password2": "secreto123",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "error=" in r.headers["location"]


def test_login_con_clave_incorrecta_falla(client):
    registrar_jugador(client, "Login Test", "logintest@example.com")
    fresco = TestClient(app_module.app)
    r = fresco.get("/login")
    token = csrf_de(r.text)
    r = fresco.post(
        "/login",
        data={"csrf_token": token, "email": "logintest@example.com", "password": "mala"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "incorrectos" in r.headers["location"]


def test_login_bloquea_tras_repetidos_intentos_fallidos(client):
    registrar_jugador(client, "Rate Limit", "ratelimit@example.com")
    fresco = TestClient(app_module.app)
    r = fresco.get("/login")
    token = csrf_de(r.text)

    for _ in range(5):
        r = fresco.post(
            "/login",
            data={"csrf_token": token, "email": "ratelimit@example.com", "password": "mala"},
            follow_redirects=False,
        )
        assert r.status_code == 303

    # el 6to intento, aunque la clave sea la correcta, debe quedar bloqueado
    r = fresco.post(
        "/login",
        data={"csrf_token": token, "email": "ratelimit@example.com", "password": "secreto123"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "Demasiados" in r.headers["location"]


def test_registrar_requiere_sesion(client):
    r = client.post("/registrar", data={
        "csrf_token": "x", "fecha": "2020-01-01", "entreno": 1,
    }, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_registrar_rechaza_fecha_futura(client):
    registrar_jugador(client, "Fecha Futura", "fechafutura@example.com")
    r = client.get("/")
    token = csrf_de(r.text)
    r = client.post(
        "/registrar",
        data={
            "csrf_token": token, "fecha": "2099-01-01", "entreno": 1, "rpe": 5,
            "minutos": 60, "fatiga": 3, "sueno": 8, "comida": "", "rutina_ok": 1, "molestias": "",
        },
    )
    assert r.status_code == 400


def test_registrar_clampea_valores_fuera_de_rango(client):
    registrar_jugador(client, "Clamp Test", "clamptest@example.com")
    r = client.get("/")
    token = csrf_de(r.text)
    resp = client.post(
        "/registrar",
        data={
            "csrf_token": token, "fecha": "2026-01-01", "entreno": 1, "rpe": 999,
            "minutos": 99999, "fatiga": 0, "sueno": 500, "comida": "", "rutina_ok": 1, "molestias": "",
        },
    )
    assert resp.status_code == 200

    with app_module.conn() as c:
        fila = c.execute(
            "SELECT rpe, minutos, fatiga, sueno FROM registros r "
            "JOIN jugadores j ON j.id = r.jugador_id WHERE j.email = %s",
            ("clamptest@example.com",),
        ).fetchone()
    assert fila["rpe"] == 10
    assert fila["minutos"] == 600
    assert fila["fatiga"] == 1
    assert fila["sueno"] == 24


def test_panel_sin_sesion_redirige_a_login_entrenador(client):
    r = client.get("/panel", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/entrenador/login"


def test_api_datos_sin_sesion_devuelve_403(client):
    r = client.get("/api/datos")
    assert r.status_code == 403


def test_entrenador_registro_rechaza_pin_invalido(client):
    r = registrar_entrenador(client, "Coach Malo", "coachmalo@example.com", pin="000000")
    assert r.status_code == 303
    assert "PIN" in r.headers["location"]


def test_entrenador_registro_y_panel(client):
    r = registrar_entrenador(client, "Coach Bueno", "coachbueno@example.com")
    assert r.status_code == 303
    assert r.headers["location"] == "/panel"

    r = client.get("/panel")
    assert r.status_code == 200

    r = client.get("/api/datos")
    assert r.status_code == 200
    assert isinstance(r.json().get("jugadores"), list)


def test_admin_sin_pin_no_muestra_el_panel(client):
    r = client.get("/admin")
    assert r.status_code == 200
    assert "Gestionar jugadores" not in r.text


def test_admin_con_pin_correcto_muestra_el_panel(client):
    r = client.get("/admin", params={"pin": "999999"})
    assert r.status_code == 200
    assert "Gestionar jugadores" in r.text
