"""Config compartida de pytest.

Fija las variables de entorno ANTES de que cualquier test importe
main.py (que las lee al cargar el módulo). Así los tests de
integración corren contra un Postgres descartable (el que levanta el
workflow de CI como servicio), nunca contra la base real de Supabase.

Para correr los tests de integración en tu máquina hace falta un
Postgres local escuchando en localhost:5432 con esas credenciales;
si no lo tenés, alcanza con correr solo tests/test_metrics.py.
"""
import os

os.environ.setdefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-prod")
os.environ.setdefault("PIN_ENTRENADOR", "999999")
os.environ.setdefault("SECURE_COOKIES", "false")
