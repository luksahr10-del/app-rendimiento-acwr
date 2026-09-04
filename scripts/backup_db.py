"""Backup diario de la base a un JSON en backups/. Standalone: no importa
main.py (evita levantar el pool/servidor solo para hacer un dump).

Corre desde el workflow .github/workflows/backup.yml, que necesita
DATABASE_URL como secret del repo (Settings > Secrets and variables >
Actions). El repo tiene que ser privado: estos backups incluyen datos
de salud de los jugadores (sueño, fatiga, molestias).
"""
import json
import os
from datetime import date

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ["DATABASE_URL"]


def dump():
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as c:
        with c.cursor() as cur:
            cur.execute("SELECT * FROM jugadores ORDER BY id")
            jugadores = cur.fetchall()
            cur.execute("SELECT * FROM registros ORDER BY id")
            registros = cur.fetchall()
            cur.execute("SELECT id, nombre, email FROM entrenadores ORDER BY id")
            entrenadores = cur.fetchall()

    # Nunca guardamos el hash de la contraseña en el backup, no hace falta.
    for j in jugadores:
        j.pop("password_hash", None)

    datos = {
        "generado": date.today().isoformat(),
        "jugadores": jugadores,
        "registros": registros,
        "entrenadores": entrenadores,
    }

    os.makedirs("backups", exist_ok=True)
    archivo = f"backups/backup_{date.today().isoformat()}.json"
    with open(archivo, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2, default=str)
    print(f"Backup guardado en {archivo} "
          f"({len(jugadores)} jugadores, {len(registros)} registros, {len(entrenadores)} entrenadores)")


if __name__ == "__main__":
    dump()
