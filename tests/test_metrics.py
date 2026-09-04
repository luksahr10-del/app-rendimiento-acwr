from datetime import date, timedelta

from metrics import acwr_de, carga, readiness


def test_carga_basica():
    assert carga(7, 60) == 420


def test_carga_valores_none():
    assert carga(None, 60) == 0
    assert carga(7, None) == 0
    assert carga(None, None) == 0


def test_readiness_maxima():
    assert readiness(8, 1, "") == 100


def test_readiness_minima():
    assert readiness(0, 5, "duele la rodilla") == 10


def test_readiness_con_molestias_penaliza():
    assert readiness(8, 3, "molestia leve") < readiness(8, 3, "")


def test_readiness_siempre_en_rango():
    for sueno in (0, 4, 8, 12):
        for fatiga in (1, 2, 3, 4, 5):
            assert 0 <= readiness(sueno, fatiga, "") <= 100


def test_acwr_sin_historial():
    assert acwr_de({}, date(2026, 1, 28)) is None


def test_acwr_carga_estable_da_uno():
    hasta = date(2026, 1, 28)
    cargas = {
        (date(2026, 1, 1) + timedelta(days=i)).isoformat(): 300
        for i in range(28)
    }
    assert acwr_de(cargas, hasta) == 1.0


def test_acwr_pico_reciente_da_riesgo():
    hasta = date(2026, 1, 28)
    cargas = {
        (date(2026, 1, 1) + timedelta(days=i)).isoformat(): 200
        for i in range(21)
    }
    for i in range(21, 28):
        cargas[(date(2026, 1, 1) + timedelta(days=i)).isoformat()] = 600
    assert acwr_de(cargas, hasta) > 1.5
