# Puster 3.5 - Security Operations Dashboard

Dashboard de monitoreo de seguridad que escanea conexiones de red activas, clasifica riesgos y genera reportes PDF/CSV.

## Arquitectura

- **puster.c** -- Escanea conexiones TCP/UDP con `ss`, clasifica riesgos (LOW/MEDIUM/HIGH) y genera JSON
- **app.py** -- Servidor Flask que ejecuta el binario y sirve el dashboard web
- **HTML/JS/CSS** -- Dashboard con Chart.js, filtros, tabla interactiva y auto-refresh

## Requisitos

- Python 3.10+
- GCC
- `ss` (iproute2, incluido en Linux)

## Instalacion

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
gcc -O2 -o puster puster.c
```

## Uso

```bash
.venv/bin/python app.py
```

Abrir http://127.0.0.1:5000

### Variables de entorno

| Variable | Default | Descripcion |
|---|---|---|
| `PUSTER_PORT` | 5000 | Puerto del servidor |
| `PUSTER_HOST` | 127.0.0.1 | Host donde escucha |
| `PUSTER_DEBUG` | false | Modo debug de Flask |

## Endpoints

| Ruta | Descripcion |
|---|---|
| `GET /` | Dashboard web |
| `GET /scan` | Ejecuta escaneo de red |
| `GET /data` | Datos completos en JSON |
| `GET /api/alerts?risk=HIGH&process=firefox` | Alertas filtradas |
| `GET /export/csv` | Descargar CSV |
| `GET /export/pdf` | Descargar PDF |

## Clasificacion de riesgo

- **LOW** -- Proceso en whitelist (firefox, spotify, chrome, etc.)
- **MEDIUM** -- Conexion externa a puerto comun (443, 80, 53, 22)
- **HIGH** -- Puerto peligroso (4444, 1337, 31337), proceso sospechoso (nc, python, nmap) o IP externa en puerto alto
