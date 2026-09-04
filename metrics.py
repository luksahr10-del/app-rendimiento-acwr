"""Métricas de ciencias del deporte: carga, disponibilidad (readiness) y ACWR.

Separado de main.py a propósito: son funciones puras (sin DB, sin FastAPI),
así se pueden testear directo sin necesitar un Postgres corriendo.
"""
from datetime import timedelta


def carga(rpe, minutos):
    """Carga de la sesión = RPE x minutos (session-RPE, estándar del rubro)."""
    return (rpe or 0) * (minutos or 0)


def readiness(sueno, fatiga, molestias):
    """Índice de disponibilidad 0-100: mezcla sueño, fatiga y molestias."""
    s = min((sueno or 0) / 8.0, 1.0)
    f = (5 - (fatiga or 3)) / 4.0
    m = 0.5 if (molestias or "").strip() else 1.0
    return round(100 * (0.4 * s + 0.4 * f + 0.2 * m))


def acwr_de(cargas_por_fecha, hasta):
    """ACWR = carga aguda (prom. 7 días) / crónica (prom. 28 días).
    Zona ideal 0.8-1.3; > 1.5 = riesgo de lesión elevado."""
    def prom(dias):
        ini = hasta - timedelta(days=dias - 1)
        total = sum(v for f, v in cargas_por_fecha.items()
                    if ini.isoformat() <= f <= hasta.isoformat())
        return total / dias
    cronica = prom(28)
    if cronica == 0:
        return None
    return round(prom(7) / cronica, 2)
