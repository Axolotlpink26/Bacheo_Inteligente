"""
Interfaz web - Bacheo Inteligente y Priorización Urbana (Alcaldía Gustavo A. Madero, CDMX)
Encargado: Daniel Santana Carbajal

Servidor Flask. Todo el HTML y el CSS se generan desde métodos de este archivo
(css_global, html_pagina_mapa, html_pagina_reporte, html_pagina_admin, ...) y los datos
vienen de `bacheo_inteligente.py` (modelo de prioridad) y de MySQL (`base_de_datos.sql`).

Páginas:
  /mapa       Mapa público con baches activos y filtros (riesgo, cercanía, tamaño, ...)
  /reportar   Formulario de reporte (requiere cuenta)
  /admin      Base de datos completa, costos y eliminación (sólo administradores)

Ejecutar:  python interfaz_web.py   ->  http://127.0.0.1:5000
"""
import csv
import functools
import hmac
import io
import os
import secrets
import time
from html import escape

from flask import (Flask, Response, abort, flash, g, get_flashed_messages, jsonify,
                   redirect, request, session, url_for)
from mysql.connector import Error

from bacheo_inteligente import (
    FRECUENCIAS_TRANSITO, PRECIO_M2_POR_PROFUNDIDAD, PROFUNDIDADES, RADIO_DUPLICADO_METROS,
    SI_NO, TAMANOS, UMBRAL_SEMAFORO_AMARILLO, UMBRAL_SEMAFORO_ROJO,
    BaseDatos, ReporteBache, autenticar_usuario, coordenadas_validas, distancia_en_km,
    elegir_opcion, formato_dinero, ranking_por_prioridad, registrar_usuario,
)

app = Flask(__name__)
# Si no defines SECRET_KEY en .env, se genera una al arrancar (las sesiones se cierran al reiniciar).
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

CAMPOS_REPORTE = ("calle", "colonia", "alcaldia", "latitud", "longitud", "tamano", "profundidad",
                  "transporte_publico", "frecuencia_transito", "accidentes", "zona_sensible",
                  "comentario")
ALCALDIA_POR_DEFECTO = "Gustavo A. Madero"
MESES_POR_DEFECTO = 6.0

# Límite sencillo contra adivinar contraseñas: 8 fallos cada 10 minutos por correo + IP
MAXIMO_INTENTOS_FALLIDOS = 8
VENTANA_INTENTOS_SEGUNDOS = 600
INTENTOS_FALLIDOS = {}

LEAFLET_CSS = ('<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" '
               'integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin="">')
LEAFLET_JS = ('<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" '
              'integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>')


# ===========================================================================
#  BASE DE DATOS, SESIÓN Y SEGURIDAD
# ===========================================================================
def obtener_bd() -> BaseDatos:
    """Una conexión MySQL por petición (se cierra sola al terminar)."""
    if "bd" not in g:
        bd = BaseDatos()
        bd.conectar()
        g.bd = bd
    return g.bd


@app.teardown_appcontext
def cerrar_bd(_error):
    bd = g.pop("bd", None)
    if bd is not None:
        bd.cerrar()


def usuario_actual():
    """Usuario con sesión iniciada (o None). Consulta la BD una sola vez por petición."""
    if "usuario_cache" in g:
        return g.usuario_cache
    usuario = None
    id_usuario = session.get("id_usuario")
    if id_usuario:
        usuario = obtener_bd().buscar_usuario_por_id(id_usuario)
        if usuario is None or not usuario.activo:
            session.pop("id_usuario", None)
            usuario = None
    g.usuario_cache = usuario
    return usuario


def usuario_seguro():
    """Como usuario_actual(), pero sin fallar si MySQL no responde (para páginas de error)."""
    try:
        return usuario_actual()
    except Error:
        return None


def destino_seguro(destino, defecto):
    """Evita redirecciones a otros sitios: sólo rutas internas."""
    if destino and destino.startswith("/") and not destino.startswith("//") and "\\" not in destino:
        return destino
    return defecto


def requiere_login(vista):
    @functools.wraps(vista)
    def envoltura(*args, **kwargs):
        if usuario_actual() is None:
            flash("Inicia sesión para continuar.", "aviso")
            destino = request.full_path if request.query_string else request.path
            return redirect(url_for("login", siguiente=destino))
        return vista(*args, **kwargs)
    return envoltura


def requiere_admin(vista):
    @functools.wraps(vista)
    def envoltura(*args, **kwargs):
        usuario = usuario_actual()
        if usuario is None:
            flash("Inicia sesión como administrador para entrar al panel.", "aviso")
            destino = request.full_path if request.query_string else request.path
            return redirect(url_for("login", siguiente=destino))
        if not usuario.es_administrador:
            abort(403)
        return vista(*args, **kwargs)
    return envoltura


def token_csrf() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def campo_csrf() -> str:
    return f'<input type="hidden" name="csrf" value="{token_csrf()}">'


@app.before_request
def verificar_csrf():
    if request.method == "POST":
        enviado = request.form.get("csrf", "").encode()
        esperado = session.get("csrf", "").encode()
        if not esperado or not hmac.compare_digest(enviado, esperado):
            abort(400)


@app.after_request
def cabeceras_de_seguridad(respuesta):
    respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
    respuesta.headers.setdefault("X-Frame-Options", "DENY")
    respuesta.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return respuesta


def demasiados_intentos(clave: str) -> bool:
    ahora = time.time()
    recientes = [t for t in INTENTOS_FALLIDOS.get(clave, []) if ahora - t < VENTANA_INTENTOS_SEGUNDOS]
    INTENTOS_FALLIDOS[clave] = recientes
    return len(recientes) >= MAXIMO_INTENTOS_FALLIDOS


def registrar_intento_fallido(clave: str):
    INTENTOS_FALLIDOS.setdefault(clave, []).append(time.time())


# ===========================================================================
#  CSS
# ===========================================================================
def css_global() -> str:
    """Estilo 'señalética vial': asfalto oscuro, línea amarilla discontinua, naranja de cono."""
    return """
:root{
  color-scheme: dark;
  --a900:#0f1114; --a800:#15181c; --a700:#1c2026; --a600:#252a32; --a500:#323843;
  --borde:#383e4a; --texto:#eef1f6; --suave:#a5adbb; --tenue:#6f7889;
  --cono:#ff7a1a; --cono-h:#ff9440; --via:#ffd23f;
  --rojo:#ef4444; --amarillo:#fbbf24; --verde:#22c55e; --azul:#3b82f6;
  --radio:14px; --alto-barra:68px;
  --fuente-titulos:"Barlow Condensed","Arial Narrow",Impact,sans-serif;
  --fuente:"Barlow",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none !important}
html{scroll-behavior:smooth}
body{
  margin:0;min-height:100vh;display:flex;flex-direction:column;
  font-family:var(--fuente);font-size:16px;line-height:1.5;color:var(--texto);
  background:
    radial-gradient(900px 480px at 85% -8%,rgba(255,122,26,.10),transparent 60%),
    radial-gradient(700px 420px at -5% 105%,rgba(255,210,63,.05),transparent 60%),
    var(--a800);
}
a{color:var(--cono-h)}
h1,h2,h3{font-family:var(--fuente-titulos);text-transform:uppercase;letter-spacing:.03em;line-height:1.1;margin:0 0 .5em}
h1{font-size:clamp(2rem,4vw,2.8rem)} h2{font-size:1.55rem} h3{font-size:1.15rem}
p{margin:0 0 .8em}
small,.suave{color:var(--suave)}

/* ---------- Barra superior ---------- */
.barra{
  display:flex;align-items:center;gap:1.25rem;min-height:var(--alto-barra);padding:.6rem 1.25rem;
  background:var(--a900);border-bottom:1px solid var(--borde);position:sticky;top:0;z-index:1200;
}
.marca{display:flex;align-items:center;gap:.7rem;text-decoration:none;color:var(--texto)}
.marca svg{width:42px;height:42px;flex:none}
.marca-texto{display:flex;flex-direction:column;line-height:1}
.marca-texto b{font-family:var(--fuente-titulos);font-size:1.5rem;letter-spacing:.07em;color:var(--cono);text-transform:uppercase}
.marca-texto span{font-family:var(--fuente-titulos);font-size:.95rem;letter-spacing:.18em;text-transform:uppercase}
.marca-texto small{font-size:.7rem;color:var(--suave);margin-top:.2rem}
.apartados{display:flex;gap:.3rem;margin-left:1rem;flex:1}
.apartados a{
  padding:.5rem 1rem;border-radius:10px;text-decoration:none;color:var(--suave);
  font-family:var(--fuente-titulos);font-size:1.12rem;letter-spacing:.06em;text-transform:uppercase;
  transition:background .15s,color .15s;
}
.apartados a:hover{color:var(--texto);background:var(--a600)}
.apartados a.activo{background:var(--via);color:#14110a}
.cuenta{margin-left:auto;display:flex;align-items:center;gap:.6rem}
.cuenta-info{display:flex;align-items:center;gap:.55rem}
.avatar{width:36px;height:36px;border-radius:50%;background:var(--cono);color:#1a0d02;display:grid;place-items:center;font:700 1.1rem var(--fuente-titulos)}
.cuenta-texto{display:flex;flex-direction:column;line-height:1.15;font-size:.92rem}
.rol{font-size:.7rem;letter-spacing:.08em;text-transform:uppercase;color:var(--suave)}
.rol-admin{color:var(--via)}
.linea-calle{
  height:6px;flex:none;opacity:.92;
  background:repeating-linear-gradient(90deg,var(--via) 0 30px,transparent 30px 58px);
  animation:avanza 14s linear infinite;
}
@keyframes avanza{to{background-position:58px 0}}

/* ---------- Botones y formularios ---------- */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:.4rem;
  border:2px solid var(--cono);background:var(--cono);color:#1a0d02;
  font:600 1rem var(--fuente);padding:.6rem 1.1rem;border-radius:10px;cursor:pointer;
  text-decoration:none;transition:background .15s,border-color .15s,transform .05s;
}
.btn:hover{background:var(--cono-h);border-color:var(--cono-h)}
.btn:active{transform:translateY(1px)}
.btn:focus-visible,a:focus-visible,button:focus-visible{outline:3px solid var(--via);outline-offset:2px}
.btn-secundario{background:transparent;color:var(--cono-h)}
.btn-secundario:hover{background:rgba(255,122,26,.14);color:var(--cono-h)}
.btn-fantasma{background:transparent;border-color:var(--borde);color:var(--texto)}
.btn-fantasma:hover{background:var(--a600);border-color:var(--tenue)}
.btn-peligro{background:transparent;border-color:var(--rojo);color:#ff9a9a}
.btn-peligro:hover{background:rgba(239,68,68,.16);border-color:var(--rojo)}
.btn-chico{padding:.35rem .75rem;font-size:.9rem;border-radius:8px}
.btn-grande{padding:.8rem 1.6rem;font-size:1.1rem}
.btn-bloque{width:100%}

label.etiqueta{display:block;font-weight:600;margin:0 0 .3rem}
input[type=text],input[type=email],input[type=password],input[type=search],input[type=number],select,textarea{
  width:100%;background:var(--a900);color:var(--texto);border:1.5px solid var(--borde);
  border-radius:10px;padding:.6rem .75rem;font:inherit;
}
textarea{resize:vertical;min-height:90px}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--via);box-shadow:0 0 0 3px rgba(255,210,63,.2)}
::placeholder{color:var(--tenue)}
fieldset{border:0;margin:0;padding:0;min-width:0}
legend{padding:0;font-weight:600;margin-bottom:.4rem}
.campo{margin-bottom:1.1rem}
.ayuda{font-size:.85rem;color:var(--suave);margin:.3rem 0 0}
.error-campo{color:#ff8a8a;font-size:.88rem;margin:.3rem 0 0}
.fila-2{display:grid;grid-template-columns:1fr 1fr;gap:.9rem}

.opciones{display:flex;flex-wrap:wrap;gap:.5rem}
.opciones label{position:relative}
.opciones input{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer;margin:0}
.opciones span{
  display:block;padding:.5rem .95rem;border:1.5px solid var(--borde);border-radius:12px;
  background:var(--a900);transition:background .12s,border-color .12s;
}
.opciones small{display:block;font-size:.76rem;color:var(--tenue);line-height:1.25}
.opciones input:hover + span{border-color:var(--tenue)}
.opciones input:checked + span{background:var(--via);border-color:var(--via);color:#14110a;font-weight:600}
.opciones input:checked + span small{color:#4a3d0c}
.opciones input:focus-visible + span{outline:3px solid var(--cono);outline-offset:2px}

/* ---------- Tarjetas y avisos ---------- */
.tarjeta{background:var(--a700);border:1px solid var(--borde);border-radius:var(--radio);padding:1.25rem}
.avisos{width:100%;max-width:1100px;margin:.8rem auto 0;padding:0 1rem}
.aviso{padding:.7rem 1rem;border-radius:10px;border-left:6px solid var(--azul);background:var(--a600);margin-bottom:.5rem}
.aviso-ok{border-color:var(--verde)} .aviso-error{border-color:var(--rojo)} .aviso-aviso{border-color:var(--amarillo)}
.punto{display:inline-block;width:.8em;height:.8em;border-radius:50%;background:var(--c,var(--suave));margin-right:.35em}

/* ---------- Mapa ---------- */
.mapa-layout{flex:1;display:grid;grid-template-columns:minmax(310px,390px) 1fr;height:calc(100vh - var(--alto-barra) - 6px);min-height:520px}
.panel-filtros{padding:1.1rem 1.1rem 2rem;overflow-y:auto;background:var(--a700);border-right:1px solid var(--borde)}
.panel-filtros h2{margin-bottom:.2rem}
.contador{margin:0 0 .9rem;color:var(--suave);font-size:.92rem}
.resumen-semaforo{display:grid;grid-template-columns:repeat(3,1fr);gap:.5rem;margin-bottom:1rem}
.mini{background:var(--a600);border:1px solid var(--borde);border-radius:12px;padding:.5rem .6rem;text-align:center;border-bottom:4px solid var(--c)}
.mini b{display:block;font:700 1.6rem var(--fuente-titulos);line-height:1.1}
.mini span{font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;color:var(--suave)}
.grupo{margin-bottom:1.1rem}
.chips{display:flex;flex-wrap:wrap;gap:.4rem}
.chip{position:relative}
.chip input{position:absolute;inset:0;width:100%;height:100%;opacity:0;margin:0;cursor:pointer}
.chip span{display:inline-flex;align-items:center;padding:.38rem .8rem;border-radius:999px;border:1.5px solid var(--borde);background:var(--a900);color:var(--suave);font-size:.92rem}
.chip input:checked + span{border-color:var(--c);color:var(--texto);background:color-mix(in srgb,var(--c) 18%,var(--a900))}
.chip input:focus-visible + span{outline:3px solid var(--via);outline-offset:2px}
.segmentos{display:grid;grid-template-columns:repeat(3,1fr);border:1.5px solid var(--borde);border-radius:12px;overflow:hidden;background:var(--a900)}
.segmentos label{position:relative}
.segmentos input{position:absolute;inset:0;width:100%;height:100%;opacity:0;margin:0;cursor:pointer}
.segmentos span{display:block;text-align:center;padding:.5rem .2rem;font-size:.88rem;line-height:1.2;color:var(--suave)}
.segmentos input:checked + span{background:var(--via);color:#14110a;font-weight:600}
.segmentos input:focus-visible + span{outline:3px solid var(--cono);outline-offset:-3px}
.sub{margin-top:.7rem;padding:.7rem;border-radius:10px;background:var(--a600);display:flex;flex-direction:column;gap:.5rem}
.sub label{font-size:.9rem}
.sub input[type=number]{width:5rem;display:inline-block;padding:.3rem .5rem}
.sub input[type=range]{width:100%;accent-color:var(--cono)}
.casilla{display:flex;align-items:center;gap:.55rem;margin:.35rem 0;cursor:pointer}
.casilla input{width:1.1rem;height:1.1rem;accent-color:var(--cono)}
.lista-baches{list-style:none;margin:1rem 0 0;padding:0;display:flex;flex-direction:column;gap:.5rem}
.item-bache{
  display:grid;grid-template-columns:auto 1fr;gap:.7rem;align-items:center;width:100%;padding:.55rem .7rem;
  background:var(--a600);border:1px solid var(--borde);border-radius:12px;color:inherit;font:inherit;text-align:left;cursor:pointer;
}
.item-bache:hover{border-color:var(--cono)}
.item-texto{display:flex;flex-direction:column;min-width:0}
.item-texto b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.item-texto small{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ipu-insignia{width:46px;height:46px;border-radius:50%;display:grid;place-items:center;font:700 1.15rem var(--fuente-titulos);color:#111;background:var(--c);border:3px solid rgba(0,0,0,.3)}
.mapa-contenedor{position:relative;min-height:420px}
#mapa,#mapa-reporte{width:100%;height:100%;background:#cfd5dd}
.leaflet-container{font-family:var(--fuente)}
.leyenda{
  position:absolute;left:12px;bottom:26px;z-index:500;padding:.6rem .8rem;border-radius:12px;font-size:.8rem;
  background:rgba(15,17,20,.92);border:1px solid var(--borde);color:var(--texto);line-height:1.6;
}
.leyenda b{display:block;font-family:var(--fuente-titulos);letter-spacing:.08em;text-transform:uppercase;font-size:.95rem}
.marcador{background:none;border:0}
.pin{
  position:relative;display:grid;place-items:center;width:34px;height:34px;border-radius:50%;
  background:var(--c);border:3px solid #fff;box-shadow:0 2px 8px rgba(0,0,0,.5);
  font:700 .88rem var(--fuente-titulos);color:#111;
}
.pin-rojo::after{content:"";position:absolute;inset:-5px;border-radius:50%;border:2px solid var(--rojo);animation:latido 1.9s ease-out infinite}
@keyframes latido{0%{transform:scale(.8);opacity:.9}100%{transform:scale(1.7);opacity:0}}
.pin-nuevo{--c:var(--cono);font-size:1.1rem;width:40px;height:40px}
.pop{min-width:210px;color:#14161a}
.pop strong{font-size:1.02rem}
.pop-sub{color:#555d6b;font-size:.85rem;margin-bottom:.5rem}
.pop-ipu{display:flex;align-items:center;gap:.6rem;margin:.4rem 0;padding:.35rem .5rem;border-radius:10px;border-left:8px solid var(--c);background:#f1f3f6}
.pop-ipu b{font:700 1.7rem var(--fuente-titulos);line-height:1}
.pop-ipu span{font-size:.78rem;letter-spacing:.06em;text-transform:uppercase;color:#444}
.pop-fila{display:flex;justify-content:space-between;gap:.8rem;font-size:.85rem;padding:.12rem 0}
.pop-fila span{color:#555d6b}
.pop-just{font-size:.8rem;color:#444;margin:.5rem 0 .3rem}
.pop small{color:#7a8290}

/* ---------- Reporte ---------- */
.reporte-layout{width:100%;max-width:1250px;margin:0 auto;padding:1.5rem 1rem 3rem;display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,.9fr);gap:1.5rem}
.paso-cab{display:flex;align-items:center;gap:1rem;margin:1.6rem 0 .8rem}
.paso-cab:first-of-type{margin-top:.4rem}
.paso-num{width:34px;height:34px;flex:none;background:var(--via);color:#14110a;transform:rotate(45deg);border-radius:6px;display:grid;place-items:center}
.paso-num span{transform:rotate(-45deg);font:700 1.15rem var(--fuente-titulos)}
.paso-cab h3{margin:0}
.mapa-reporte-caja{position:sticky;top:calc(var(--alto-barra) + 20px);align-self:start}
.mapa-reporte-caja #mapa-reporte{height:min(66vh,560px);border-radius:12px}
.barra-busqueda{display:flex;gap:.5rem;margin-bottom:.7rem;flex-wrap:wrap}
.barra-busqueda input{flex:1;min-width:180px}
.estado-ubicacion{margin:.6rem 0 0;font-size:.9rem;color:var(--suave)}
.estado-ubicacion.ok{color:var(--verde)} .estado-ubicacion.error{color:#ff8a8a}
.resumen-errores{border-left:6px solid var(--rojo);background:rgba(239,68,68,.1);padding:.7rem 1rem;border-radius:10px;margin-bottom:1rem}
.resumen-errores ul{margin:.3rem 0 0;padding-left:1.2rem}
.nota-privacidad{font-size:.85rem;color:var(--suave);border-top:1px dashed var(--borde);padding-top:.8rem;margin-top:1.2rem}

/* ---------- Resultado de un reporte ---------- */
.centrado{width:100%;max-width:760px;margin:2rem auto 3rem;padding:0 1rem}
.resultado{display:grid;grid-template-columns:auto 1fr;gap:1.5rem;align-items:center}
.senal-ipu{--c:var(--verde);width:152px;height:152px;border-radius:50%;background:#fff;border:15px solid var(--c);display:grid;place-items:center;align-content:center;color:#111;box-shadow:0 8px 28px rgba(0,0,0,.45)}
.senal-ipu b{display:block;font:700 3.2rem var(--fuente-titulos);line-height:1;text-align:center}
.senal-ipu small{display:block;text-align:center;font-size:.68rem;letter-spacing:.12em;text-transform:uppercase;color:#555}
.datos{display:grid;grid-template-columns:1fr 1fr;gap:.4rem 1.2rem;margin:1rem 0}
.datos div{display:flex;flex-direction:column}
.datos span{font-size:.78rem;letter-spacing:.06em;text-transform:uppercase;color:var(--suave)}
.acciones-fila{display:flex;gap:.6rem;flex-wrap:wrap;margin-top:1rem}
.lista-duplicados{display:flex;flex-direction:column;gap:.7rem;margin:1rem 0}
.duplicado{display:grid;grid-template-columns:auto 1fr auto;gap:.8rem;align-items:center}

/* ---------- Acceso ---------- */
.auth-caja{width:100%;max-width:440px;margin:2.5rem auto 3rem;padding:0 1rem}
.auth-caja .tarjeta{border-top:6px solid var(--via)}
.auth-pie{margin-top:1rem;font-size:.92rem;color:var(--suave);text-align:center}

/* ---------- Panel de administrador ---------- */
.admin-contenedor{width:100%;max-width:1560px;margin:0 auto;padding:1.5rem 1rem 3rem}
.estadisticas{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:.7rem;margin:1rem 0 1.4rem}
.estadistica{background:var(--a700);border:1px solid var(--borde);border-radius:12px;padding:.75rem .9rem;border-top:4px solid var(--c,var(--borde))}
.estadistica span{display:block;font-size:.72rem;letter-spacing:.07em;text-transform:uppercase;color:var(--suave)}
.estadistica b{display:block;font:700 1.75rem var(--fuente-titulos);line-height:1.2}
.herramientas{display:flex;flex-wrap:wrap;gap:.7rem;align-items:end;margin-bottom:.9rem}
.herramientas .campo{margin:0;min-width:150px}
.herramientas .campo.ancho{flex:1;min-width:220px}
.tabla-caja{overflow:auto;max-height:68vh;border:1px solid var(--borde);border-radius:12px;background:var(--a700)}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:.9rem}
th{position:sticky;top:0;z-index:2;background:var(--a600);text-align:left;padding:.65rem .7rem;font-size:.74rem;letter-spacing:.07em;text-transform:uppercase;color:var(--suave);white-space:nowrap;border-bottom:1px solid var(--borde)}
td{padding:.6rem .7rem;border-top:1px solid var(--borde);vertical-align:top}
tbody tr:first-child td{border-top:0}
tbody tr:hover td{background:rgba(255,255,255,.03)}
tr.atendido td{opacity:.55}
td.num,th.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.ubicacion b{display:block}
.ubicacion small{display:block;color:var(--suave)}
.etiquetas span{display:inline-block;font-size:.72rem;padding:.08rem .45rem;border-radius:6px;background:var(--a600);border:1px solid var(--borde);margin:0 .2rem .2rem 0;white-space:nowrap}
.semaforo-celda{display:flex;align-items:center;gap:.5rem;white-space:nowrap}
.semaforo-celda .ipu-insignia{width:38px;height:38px;font-size:1rem}
.estado-pendiente{color:var(--via)} .estado-atendido{color:var(--verde)}
.acciones-celda{display:flex;flex-direction:column;gap:.35rem;min-width:132px}
.acciones-celda form{margin:0}
.acciones-celda .btn{width:100%}
.pie-tabla{font-size:.85rem;color:var(--suave);margin-top:.8rem}

@media (max-width:980px){
  .barra{flex-wrap:wrap;gap:.6rem 1rem}
  .apartados{order:3;flex:1 0 100%;margin:0;overflow-x:auto}
  .mapa-layout{grid-template-columns:1fr;height:auto}
  .mapa-contenedor{order:-1;height:62vh}
  .panel-filtros{border-right:0;border-top:1px solid var(--borde);overflow:visible}
  .reporte-layout{grid-template-columns:1fr}
  .mapa-reporte-caja{position:static;order:-1}
  .marca-texto small{display:none}
}
@media (max-width:560px){
  .fila-2,.datos{grid-template-columns:1fr}
  .resultado{grid-template-columns:1fr;justify-items:center;text-align:center}
  .cuenta-texto{display:none}
  .duplicado{grid-template-columns:1fr}
}
@media (prefers-reduced-motion:reduce){
  .linea-calle,.pin-rojo::after{animation:none}
  html{scroll-behavior:auto}
}
"""


# ===========================================================================
#  JAVASCRIPT (se inserta dentro de cada página)
# ===========================================================================
def js_mapa() -> str:
    """Mapa público: carga /api/baches, dibuja pines y aplica filtros (riesgo, cercanía, ...)."""
    return r"""
(function () {
  'use strict';
  const COLOR = {Rojo: '#ef4444', Amarillo: '#fbbf24', Verde: '#22c55e'};
  const CENTRO = [19.4900, -99.1100];
  const $ = (id) => document.getElementById(id);
  const esc = (valor) => String(valor).replace(/[&<>"']/g, (c) =>
    ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

  function distanciaKm(lat1, lng1, lat2, lng2) {
    const rad = Math.PI / 180;
    const a = Math.sin((lat2 - lat1) * rad / 2) ** 2 +
      Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin((lng2 - lng1) * rad / 2) ** 2;
    return 2 * 6371.0088 * Math.asin(Math.sqrt(a));
  }

  const mapa = L.map('mapa').setView(CENTRO, 12);
  const capaCalles = L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
  }).addTo(mapa);
  const capaOscura = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    maxZoom: 20, subdomains: 'abcd', attribution: '&copy; OpenStreetMap &copy; CARTO'
  });
  L.control.layers({'Calles': capaCalles, 'Oscuro': capaOscura}, null, {position: 'topright'}).addTo(mapa);
  const capaBaches = L.layerGroup().addTo(mapa);
  const capaUsuario = L.layerGroup().addTo(mapa);

  let baches = [];
  let ubicacion = null;
  let primeraCarga = true;
  const marcadores = new Map();

  function leerFiltros() {
    return {
      semaforos: [...document.querySelectorAll('input[name=semaforo]:checked')].map((i) => i.value),
      enfoque: document.querySelector('input[name=enfoque]:checked').value,
      topN: Math.max(1, parseInt($('topN').value, 10) || 10),
      radio: parseFloat($('radio').value) || 3,
      tamano: $('f-tamano').value,
      profundidad: $('f-profundidad').value,
      transporte: $('f-transporte').checked,
      accidentes: $('f-accidentes').checked,
      sensible: $('f-sensible').checked,
      texto: $('f-texto').value.trim().toLowerCase()
    };
  }

  function filtrar(f) {
    let lista = baches.filter((b) => f.semaforos.includes(b.semaforo));
    if (f.tamano) lista = lista.filter((b) => b.tamano === f.tamano);
    if (f.profundidad) lista = lista.filter((b) => b.profundidad === f.profundidad);
    if (f.transporte) lista = lista.filter((b) => b.transporte_publico === 'Si');
    if (f.accidentes) lista = lista.filter((b) => b.accidentes === 'Si');
    if (f.sensible) lista = lista.filter((b) => b.zona_sensible === 'Si');
    if (f.texto) lista = lista.filter((b) => (b.calle + ' ' + b.colonia + ' ' + b.alcaldia).toLowerCase().includes(f.texto));
    baches.forEach((b) => { b.distancia = ubicacion ? distanciaKm(ubicacion.lat, ubicacion.lng, b.latitud, b.longitud) : null; });

    if (f.enfoque === 'cercanos' && ubicacion) {
      lista = lista.filter((b) => b.distancia <= f.radio).sort((a, b) => a.distancia - b.distancia);
    } else {
      lista.sort((a, b) => b.ipu - a.ipu || a.id_bache - b.id_bache);
      if (f.enfoque === 'riesgosos') lista = lista.slice(0, f.topN);
    }
    return lista;
  }

  function popupHtml(b) {
    const distancia = b.distancia != null
      ? `<div class="pop-fila"><span>Distancia</span><b>${b.distancia.toFixed(2)} km</b></div>` : '';
    return `<div class="pop">
      <strong>${esc(b.calle)}</strong>
      <div class="pop-sub">${esc(b.colonia)} · ${esc(b.alcaldia)}</div>
      <div class="pop-ipu" style="--c:${COLOR[b.semaforo]}"><b>${b.ipu}</b><span>IPU · ${esc(b.semaforo)}</span></div>
      <div class="pop-fila"><span>Prob. de siniestro (72 h)</span><b>${b.prob_siniestro_72h}%</b></div>
      <div class="pop-fila"><span>Tamaño / daño</span><b>${esc(b.tamano)} · ${esc(b.profundidad)}</b></div>
      <div class="pop-fila"><span>Reportes ciudadanos</span><b>${b.num_reportes}</b></div>
      ${distancia}
      <p class="pop-just">${esc(b.justificacion)}</p>
      <small>Bache #${b.id_bache} · ${esc(b.fecha_registro)}</small>
    </div>`;
  }

  function dibujar(lista) {
    capaBaches.clearLayers();
    marcadores.clear();
    const ul = $('lista');
    ul.innerHTML = '';
    lista.forEach((b) => {
      const color = COLOR[b.semaforo];
      const icono = L.divIcon({
        className: 'marcador', iconSize: [34, 34], iconAnchor: [17, 17], popupAnchor: [0, -18],
        html: `<span class="pin pin-${b.semaforo.toLowerCase()}" style="--c:${color}">${Math.round(b.ipu)}</span>`
      });
      const marcador = L.marker([b.latitud, b.longitud], {icon: icono, title: `${b.calle} - IPU ${b.ipu}`})
        .bindPopup(popupHtml(b)).addTo(capaBaches);
      marcadores.set(b.id_bache, marcador);

      const li = document.createElement('li');
      const boton = document.createElement('button');
      boton.type = 'button';
      boton.className = 'item-bache';
      const distancia = b.distancia != null ? ` · ${b.distancia.toFixed(1)} km` : '';
      boton.innerHTML = `<span class="ipu-insignia" style="--c:${color}">${Math.round(b.ipu)}</span>
        <span class="item-texto"><b>${esc(b.calle)}</b><small>${esc(b.colonia)}${distancia}</small></span>`;
      boton.addEventListener('click', () => enfocar(b.id_bache));
      li.appendChild(boton);
      ul.appendChild(li);
    });
    if (!lista.length) {
      ul.innerHTML = '<li class="ayuda">No hay baches con estos filtros.</li>';
    }
  }

  function dibujarUsuario(f) {
    capaUsuario.clearLayers();
    if (!ubicacion) return;
    L.circleMarker([ubicacion.lat, ubicacion.lng], {radius: 8, color: '#fff', weight: 3, fillColor: '#3b82f6', fillOpacity: 1})
      .bindTooltip('Tu punto de referencia').addTo(capaUsuario);
    if (f.enfoque === 'cercanos') {
      L.circle([ubicacion.lat, ubicacion.lng], {radius: f.radio * 1000, color: '#3b82f6', weight: 1.5, fillOpacity: 0.07, interactive: false})
        .addTo(capaUsuario);
    }
  }

  function aplicar() {
    const f = leerFiltros();
    $('sub-riesgosos').hidden = f.enfoque !== 'riesgosos';
    $('sub-cercanos').hidden = f.enfoque !== 'cercanos';
    $('radio-valor').textContent = f.radio.toLocaleString('es-MX') + ' km';
    const lista = filtrar(f);
    dibujar(lista);
    dibujarUsuario(f);
    $('contador').textContent = `Mostrando ${lista.length} de ${baches.length} baches activos`;
    if (f.enfoque === 'cercanos' && !ubicacion) {
      $('ayuda-ubicacion').textContent = 'Aún no tenemos tu punto: usa el botón o haz clic en el mapa.';
    }
  }

  function enfocar(id) {
    const marcador = marcadores.get(id);
    if (!marcador) return;
    mapa.flyTo(marcador.getLatLng(), Math.max(mapa.getZoom(), 16), {duration: 0.8});
    marcador.openPopup();
    if (window.matchMedia('(max-width: 980px)').matches) {
      $('mapa').scrollIntoView({behavior: 'smooth', block: 'center'});
    }
  }

  function fijarUbicacion(lat, lng, centrar) {
    ubicacion = {lat: lat, lng: lng};
    $('ayuda-ubicacion').textContent = 'Punto fijado. Puedes moverlo haciendo clic en otro lugar del mapa.';
    if (centrar) mapa.setView([lat, lng], 14);
    aplicar();
  }

  function usarMiUbicacion() {
    if (!navigator.geolocation) {
      $('ayuda-ubicacion').textContent = 'Tu navegador no permite geolocalización. Haz clic en el mapa para fijar tu punto.';
      return;
    }
    $('ayuda-ubicacion').textContent = 'Buscando tu ubicación…';
    navigator.geolocation.getCurrentPosition(
      (pos) => fijarUbicacion(pos.coords.latitude, pos.coords.longitude, true),
      () => { $('ayuda-ubicacion').textContent = 'No pudimos obtener tu ubicación. Haz clic en el mapa para fijar un punto.'; },
      {enableHighAccuracy: true, timeout: 10000}
    );
  }

  async function cargar() {
    try {
      const respuesta = await fetch('/api/baches', {cache: 'no-store'});
      if (!respuesta.ok) throw new Error('HTTP ' + respuesta.status);
      baches = (await respuesta.json()).baches;
    } catch (error) {
      $('contador').textContent = 'No se pudieron cargar los baches. Recarga la página.';
      return;
    }
    const conteo = {Rojo: 0, Amarillo: 0, Verde: 0};
    baches.forEach((b) => { conteo[b.semaforo] += 1; });
    $('n-rojo').textContent = conteo.Rojo;
    $('n-amarillo').textContent = conteo.Amarillo;
    $('n-verde').textContent = conteo.Verde;
    aplicar();

    if (primeraCarga && baches.length) {
      primeraCarga = false;
      mapa.fitBounds(L.latLngBounds(baches.map((b) => [b.latitud, b.longitud])), {padding: [40, 40], maxZoom: 15});
    }
    const pedido = parseInt(new URLSearchParams(location.search).get('bache'), 10);
    if (pedido) setTimeout(() => enfocar(pedido), 400);
  }

  const formulario = $('form-filtros');
  formulario.addEventListener('input', aplicar);
  formulario.addEventListener('reset', () => setTimeout(aplicar, 0));
  formulario.addEventListener('submit', (e) => e.preventDefault());
  document.querySelectorAll('input[name=enfoque]').forEach((radio) => radio.addEventListener('change', () => {
    if (radio.checked && radio.value === 'cercanos' && !ubicacion) usarMiUbicacion();
  }));
  $('btn-ubicacion').addEventListener('click', usarMiUbicacion);
  mapa.on('click', (e) => {
    if (leerFiltros().enfoque === 'cercanos') fijarUbicacion(e.latlng.lat, e.latlng.lng, false);
  });
  cargar();
})();
"""


def js_reporte() -> str:
    """Formulario de reporte: mapa para marcar el bache, búsqueda de dirección y autocompletado."""
    return r"""
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const CENTRO = [19.4900, -99.1100];
  const inputLat = $('latitud');
  const inputLng = $('longitud');
  const estado = $('estado-ubicacion');

  const mapa = L.map('mapa-reporte').setView(CENTRO, 13);
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
  }).addTo(mapa);
  const icono = L.divIcon({
    className: 'marcador', iconSize: [40, 40], iconAnchor: [20, 20],
    html: '<span class="pin pin-nuevo">🚧</span>'
  });
  let pin = null;

  function mostrarEstado(texto, clase) {
    estado.textContent = texto;
    estado.className = 'estado-ubicacion' + (clase ? ' ' + clase : '');
  }

  function rellenar(id, valor) {
    const campo = $(id);
    if (!valor) return;
    if (!campo.value.trim() || campo.dataset.auto === '1') {
      campo.value = valor;
      campo.dataset.auto = '1';
    }
  }

  async function completarDireccion(lat, lng) {
    try {
      const r = await fetch('https://nominatim.openstreetmap.org/reverse?format=jsonv2&zoom=18&addressdetails=1&accept-language=es'
        + '&lat=' + lat + '&lon=' + lng);
      if (!r.ok) return;
      const a = (await r.json()).address || {};
      rellenar('calle', a.road || a.pedestrian || a.residential);
      rellenar('colonia', a.suburb || a.neighbourhood || a.quarter || a.village);
      rellenar('alcaldia', a.city_district || a.borough || a.county);
    } catch (error) { /* si falla, la persona escribe la dirección a mano */ }
  }

  function fijar(lat, lng, autocompletar) {
    inputLat.value = lat.toFixed(6);
    inputLng.value = lng.toFixed(6);
    mostrarEstado(`Ubicación marcada: ${lat.toFixed(5)}, ${lng.toFixed(5)}. Arrastra el pin para ajustarla.`, 'ok');
    if (autocompletar) completarDireccion(lat, lng);
  }

  function colocar(lat, lng, autocompletar) {
    if (!pin) {
      pin = L.marker([lat, lng], {draggable: true, icon: icono}).addTo(mapa);
      pin.on('dragend', () => { const p = pin.getLatLng(); fijar(p.lat, p.lng, true); });
    } else {
      pin.setLatLng([lat, lng]);
    }
    fijar(lat, lng, autocompletar);
  }

  ['calle', 'colonia', 'alcaldia'].forEach((id) =>
    $(id).addEventListener('input', () => { $(id).dataset.auto = '0'; }));

  mapa.on('click', (e) => colocar(e.latlng.lat, e.latlng.lng, true));

  $('btn-mi-ubicacion').addEventListener('click', () => {
    if (!navigator.geolocation) { mostrarEstado('Tu navegador no permite geolocalización. Haz clic en el mapa.', 'error'); return; }
    mostrarEstado('Buscando tu ubicación…');
    navigator.geolocation.getCurrentPosition((pos) => {
      mapa.setView([pos.coords.latitude, pos.coords.longitude], 18);
      colocar(pos.coords.latitude, pos.coords.longitude, true);
    }, () => mostrarEstado('No pudimos obtener tu ubicación. Haz clic en el mapa.', 'error'),
    {enableHighAccuracy: true, timeout: 10000});
  });

  async function buscar() {
    const consulta = $('buscar-direccion').value.trim();
    if (!consulta) return;
    mostrarEstado('Buscando dirección…');
    try {
      const r = await fetch('https://nominatim.openstreetmap.org/search?format=jsonv2&limit=1&countrycodes=mx&accept-language=es'
        + '&viewbox=-99.4,19.8,-98.9,19.0&bounded=1&q=' + encodeURIComponent(consulta));
      const datos = await r.json();
      if (!datos.length) { mostrarEstado('No encontramos esa dirección. Haz clic en el mapa para marcarla.', 'error'); return; }
      const lat = parseFloat(datos[0].lat), lng = parseFloat(datos[0].lon);
      mapa.setView([lat, lng], 17);
      colocar(lat, lng, true);
    } catch (error) {
      mostrarEstado('No se pudo buscar ahora. Haz clic en el mapa para marcar el bache.', 'error');
    }
  }
  $('btn-buscar').addEventListener('click', buscar);
  $('buscar-direccion').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); buscar(); } });

  $('form-reporte').addEventListener('submit', (e) => {
    if (!inputLat.value || !inputLng.value) {
      e.preventDefault();
      mostrarEstado('Falta marcar el bache en el mapa (haz clic donde está).', 'error');
      $('mapa-reporte').scrollIntoView({behavior: 'smooth', block: 'center'});
    }
  });

  if (inputLat.value && inputLng.value) {
    const lat = parseFloat(inputLat.value), lng = parseFloat(inputLng.value);
    if (isFinite(lat) && isFinite(lng)) { mapa.setView([lat, lng], 17); colocar(lat, lng, false); }
  }
})();
"""


def js_admin() -> str:
    """Panel admin: filtro instantáneo de la tabla y envío automático de los selectores."""
    return r"""
(function () {
  'use strict';
  const filas = [...document.querySelectorAll('#tabla-baches tbody tr')];
  const buscador = document.getElementById('buscar-tabla');
  const semaforo = document.getElementById('filtro-semaforo');
  const conteo = document.getElementById('conteo-filas');

  function aplicar() {
    const texto = buscador.value.trim().toLowerCase();
    const color = semaforo.value;
    let visibles = 0;
    filas.forEach((fila) => {
      const coincide = (!color || fila.dataset.semaforo === color) &&
        (!texto || fila.textContent.toLowerCase().includes(texto));
      fila.hidden = !coincide;
      if (coincide) visibles += 1;
    });
    conteo.textContent = visibles + ' de ' + filas.length + ' filas';
  }
  buscador.addEventListener('input', aplicar);
  semaforo.addEventListener('change', aplicar);
  document.querySelectorAll('[data-autoenvio]').forEach((el) =>
    el.addEventListener('change', () => el.form.submit()));
  aplicar();
})();
"""


# ===========================================================================
#  HTML: piezas reutilizables
# ===========================================================================
def html_logo() -> str:
    """Logotipo: un bache (óvalo oscuro con grietas) sobre una señal amarilla en rombo."""
    return """<svg viewBox="0 0 48 48" aria-hidden="true">
  <rect x="7" y="7" width="34" height="34" rx="5" transform="rotate(45 24 24)" fill="#ffd23f"/>
  <ellipse cx="24" cy="26" rx="11" ry="6.5" fill="#15181c"/>
  <path d="M24 19.5 21 14M27 20.5 31 16M14 27l-4 1.5M34 27l4 1.5" stroke="#15181c" stroke-width="2" stroke-linecap="round" fill="none"/>
  <ellipse cx="24" cy="24.8" rx="7" ry="3.2" fill="#ff7a1a"/>
</svg>"""


def html_avisos() -> str:
    piezas = [f'<div class="aviso aviso-{escape(categoria)}" role="status">{escape(mensaje)}</div>'
              for categoria, mensaje in get_flashed_messages(with_categories=True)]
    return f'<div class="avisos">{"".join(piezas)}</div>' if piezas else ""


def html_barra_superior(seccion: str, usuario) -> str:
    """Apartados a la izquierda y acceso a la cuenta (usuario o administrador) a la derecha."""
    def enlace(clave, texto, endpoint):
        activo = ' class="activo" aria-current="page"' if seccion == clave else ""
        return f'<a href="{url_for(endpoint)}"{activo}>{texto}</a>'

    apartados = enlace("mapa", "Mapa", "pagina_mapa") + enlace("reportar", "Reportar bache", "pagina_reportar")
    if usuario is not None and usuario.es_administrador:
        apartados += enlace("admin", "Panel administrador", "pagina_admin")

    if usuario is not None:
        rol_texto = "Administrador" if usuario.es_administrador else "Usuario"
        rol_clase = "rol rol-admin" if usuario.es_administrador else "rol"
        cuenta = f"""<div class="cuenta">
  <div class="cuenta-info">
    <span class="avatar" aria-hidden="true">{escape(usuario.nombre[:1].upper())}</span>
    <span class="cuenta-texto"><b>{escape(usuario.nombre)}</b><span class="{rol_clase}">{rol_texto}</span></span>
  </div>
  <form method="post" action="{url_for('salir')}">{campo_csrf()}<button class="btn btn-fantasma btn-chico" type="submit">Salir</button></form>
</div>"""
    else:
        cuenta = f"""<div class="cuenta">
  <a class="btn btn-secundario btn-chico" href="{url_for('login')}">Iniciar sesión</a>
  <a class="btn btn-chico" href="{url_for('registro')}">Crear cuenta</a>
</div>"""

    return f"""<header class="barra">
  <a class="marca" href="{url_for('pagina_mapa')}" aria-label="Bacheo Inteligente, inicio">
    {html_logo()}
    <span class="marca-texto"><b>Bacheo</b><span>Inteligente</span><small>Gustavo A. Madero · CDMX</small></span>
  </a>
  <nav class="apartados" aria-label="Apartados">{apartados}</nav>
  {cuenta}
</header>
<div class="linea-calle" aria-hidden="true"></div>"""


def pagina_base(titulo: str, cuerpo: str, seccion: str = "", usuario=None,
                extra_head: str = "", extra_scripts: str = "") -> str:
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(titulo)} · Bacheo Inteligente GAM</title>
<meta name="description" content="Bacheo inteligente y priorización urbana en la Alcaldía Gustavo A. Madero, CDMX: mapa de baches, reportes ciudadanos y panel de costos.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E🚧%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@600;700&family=Barlow:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="{url_for('estilos')}">
{extra_head}
</head>
<body>
{html_barra_superior(seccion, usuario)}
{html_avisos()}
{cuerpo}
{extra_scripts}
</body>
</html>"""


def html_pagina_mensaje(titulo: str, mensaje: str, usuario=None) -> str:
    cuerpo = f"""<main class="centrado"><div class="tarjeta">
  <h1>{escape(titulo)}</h1><p>{escape(mensaje)}</p>
  <div class="acciones-fila"><a class="btn" href="{url_for('pagina_mapa')}">Ir al mapa</a></div>
</div></main>"""
    return pagina_base(titulo, cuerpo, usuario=usuario)


def etiqueta_si_no(valor: str) -> str:
    return "Sí" if valor == "Si" else "No"


# ===========================================================================
#  HTML: MAPA (apartado 1)
# ===========================================================================
def html_pagina_mapa(usuario) -> str:
    opciones_tamano = "".join(f'<option value="{t}">{t}</option>' for t in TAMANOS)
    opciones_profundidad = "".join(f'<option value="{p}">{p}</option>' for p in PROFUNDIDADES)
    cuerpo = f"""<main class="mapa-layout">
  <aside class="panel-filtros" aria-label="Filtros del mapa">
    <h2>Baches activos</h2>
    <p class="contador" id="contador" aria-live="polite">Cargando baches…</p>
    <div class="resumen-semaforo">
      <div class="mini" style="--c:var(--rojo)"><b id="n-rojo">–</b><span>Rojo</span></div>
      <div class="mini" style="--c:var(--amarillo)"><b id="n-amarillo">–</b><span>Amarillo</span></div>
      <div class="mini" style="--c:var(--verde)"><b id="n-verde">–</b><span>Verde</span></div>
    </div>

    <form id="form-filtros" autocomplete="off">
      <fieldset class="grupo">
        <legend>Nivel de prioridad</legend>
        <div class="chips">
          <label class="chip" style="--c:var(--rojo)"><input type="checkbox" name="semaforo" value="Rojo" checked><span><i class="punto"></i>Rojo</span></label>
          <label class="chip" style="--c:var(--amarillo)"><input type="checkbox" name="semaforo" value="Amarillo" checked><span><i class="punto"></i>Amarillo</span></label>
          <label class="chip" style="--c:var(--verde)"><input type="checkbox" name="semaforo" value="Verde" checked><span><i class="punto"></i>Verde</span></label>
        </div>
      </fieldset>

      <fieldset class="grupo">
        <legend>¿Qué quieres ver?</legend>
        <div class="segmentos">
          <label><input type="radio" name="enfoque" value="todos" checked><span>Todos</span></label>
          <label><input type="radio" name="enfoque" value="riesgosos"><span>Más riesgosos</span></label>
          <label><input type="radio" name="enfoque" value="cercanos"><span>Más cercanos</span></label>
        </div>
        <div class="sub" id="sub-riesgosos" hidden>
          <label for="topN">Mostrar los <input type="number" id="topN" min="1" max="100" value="10"> baches con mayor IPU</label>
        </div>
        <div class="sub" id="sub-cercanos" hidden>
          <button type="button" class="btn btn-secundario btn-chico" id="btn-ubicacion">Usar mi ubicación</button>
          <label for="radio">Radio: <b id="radio-valor">3 km</b></label>
          <input type="range" id="radio" min="0.5" max="15" step="0.5" value="3">
          <p class="ayuda" id="ayuda-ubicacion">…o haz clic en el mapa para fijar un punto.</p>
        </div>
      </fieldset>

      <fieldset class="grupo">
        <legend>Características</legend>
        <div class="fila-2">
          <div><label class="etiqueta" for="f-tamano">Tamaño</label><select id="f-tamano"><option value="">Todos</option>{opciones_tamano}</select></div>
          <div><label class="etiqueta" for="f-profundidad">Daño</label><select id="f-profundidad"><option value="">Todos</option>{opciones_profundidad}</select></div>
        </div>
        <label class="casilla"><input type="checkbox" id="f-transporte"> En ruta de transporte público</label>
        <label class="casilla"><input type="checkbox" id="f-accidentes"> Con accidentes previos</label>
        <label class="casilla"><input type="checkbox" id="f-sensible"> Cerca de hospital, escuela o zona concurrida</label>
      </fieldset>

      <div class="grupo">
        <label class="etiqueta" for="f-texto">Buscar calle o colonia</label>
        <input type="search" id="f-texto" placeholder="Ej. Montevideo, Lindavista">
      </div>
      <button type="reset" class="btn btn-fantasma btn-chico">Restablecer filtros</button>
    </form>

    <ol class="lista-baches" id="lista" aria-label="Baches que coinciden con los filtros"></ol>
    <p class="ayuda">IPU = Índice de Prioridad Urbana (0-100). El sistema sugiere; la decisión final es de la autoridad.</p>
  </aside>

  <section class="mapa-contenedor" aria-label="Mapa de baches">
    <div id="mapa" role="application" aria-label="Mapa interactivo de baches"></div>
    <div class="leyenda">
      <b>Prioridad (IPU)</b>
      <div><i class="punto" style="--c:var(--rojo)"></i>Rojo: {UMBRAL_SEMAFORO_ROJO} o más</div>
      <div><i class="punto" style="--c:var(--amarillo)"></i>Amarillo: {UMBRAL_SEMAFORO_AMARILLO} a {UMBRAL_SEMAFORO_ROJO - 0.1:g}</div>
      <div><i class="punto" style="--c:var(--verde)"></i>Verde: menos de {UMBRAL_SEMAFORO_AMARILLO}</div>
    </div>
  </section>
</main>"""
    return pagina_base("Mapa de baches", cuerpo, "mapa", usuario, extra_head=LEAFLET_CSS,
                       extra_scripts=LEAFLET_JS + f"<script>{js_mapa()}</script>")


# ===========================================================================
#  HTML: REPORTE (apartado 2)
# ===========================================================================
ETIQUETAS_TAMANO = {
    "Pequeño": ("Pequeño", "≈ 0.25 m², como una llanta"),
    "Mediano": ("Mediano", "≈ 1 m²"),
    "Grande": ("Grande", "≈ 3 m² o más"),
}
ETIQUETAS_PROFUNDIDAD = {
    "Superficial": ("Superficial", "≈ 5 cm"),
    "Profundo": ("Profundo", "≈ 10 cm o más"),
}
ETIQUETAS_FRECUENCIA = {
    "Diario": ("Diario", "avenida con mucho tránsito"),
    "Semanal": ("Semanal", "calle secundaria"),
    "Ocasional": ("Ocasional", "poco transitada"),
}
ETIQUETAS_SI_NO = {"Si": ("Sí", ""), "No": ("No", "")}


def html_opciones(nombre: str, opciones, seleccionada, etiquetas: dict) -> str:
    """Grupo de botones tipo 'pastilla' (radio) para elegir una opción."""
    piezas = []
    for indice, opcion in enumerate(opciones):
        titulo, detalle = etiquetas.get(opcion, (opcion, ""))
        marcado = " checked" if opcion == seleccionada else ""
        requerido = " required" if indice == 0 else ""
        sub = f"<small>{escape(detalle)}</small>" if detalle else ""
        piezas.append(f'<label><input type="radio" name="{nombre}" value="{escape(opcion)}"{marcado}{requerido}>'
                      f'<span>{escape(titulo)}{sub}</span></label>')
    return f'<div class="opciones" role="radiogroup">{"".join(piezas)}</div>'


def html_error_campo(errores: dict, campo: str) -> str:
    return f'<p class="error-campo">{escape(errores[campo])}</p>' if campo in errores else ""


def html_pagina_reporte(usuario, valores: dict, errores: dict) -> str:
    def valor(campo, defecto=""):
        return escape(str(valores.get(campo, defecto) or ""))

    alcaldia_auto = ' data-auto="1"' if "alcaldia" not in valores else ""
    resumen_errores = ""
    if errores:
        items = "".join(f"<li>{escape(mensaje)}</li>" for mensaje in errores.values())
        resumen_errores = (f'<div class="resumen-errores" role="alert"><b>Revisa estos puntos:</b><ul>{items}</ul></div>')

    cuerpo = f"""<main class="reporte-layout">
  <section>
    <h1>Reportar un bache</h1>
    <p class="suave">Entre más completos sean los datos, mejor se calcula la prioridad de atención.
       Todo es opcional excepto lo marcado; si ya hay un reporte cercano te avisamos.</p>
    {resumen_errores}
    <form method="post" action="{url_for('pagina_reportar')}" id="form-reporte" novalidate>
      {campo_csrf()}
      <input type="hidden" name="latitud" id="latitud" value="{valor('latitud')}">
      <input type="hidden" name="longitud" id="longitud" value="{valor('longitud')}">

      <div class="paso-cab"><div class="paso-num"><span>1</span></div><h3>¿Dónde está?</h3></div>
      <div class="campo"><label class="etiqueta" for="calle">Calle o avenida</label>
        <input type="text" id="calle" name="calle" maxlength="120" value="{valor('calle')}" placeholder="Ej. Av. Montevideo" required>
        {html_error_campo(errores, 'calle')}</div>
      <div class="fila-2">
        <div class="campo"><label class="etiqueta" for="colonia">Colonia</label>
          <input type="text" id="colonia" name="colonia" maxlength="120" value="{valor('colonia')}" placeholder="Ej. Lindavista" required>
          {html_error_campo(errores, 'colonia')}</div>
        <div class="campo"><label class="etiqueta" for="alcaldia">Alcaldía</label>
          <input type="text" id="alcaldia" name="alcaldia" maxlength="80" value="{valor('alcaldia', ALCALDIA_POR_DEFECTO)}"{alcaldia_auto} required>
          {html_error_campo(errores, 'alcaldia')}</div>
      </div>
      <p class="ayuda">Marca el punto exacto en el mapa: la calle y la colonia se llenan solas (puedes corregirlas).</p>
      {html_error_campo(errores, 'ubicacion')}

      <div class="paso-cab"><div class="paso-num"><span>2</span></div><h3>El bache</h3></div>
      <fieldset class="campo"><legend>Tamaño</legend>
        {html_opciones('tamano', TAMANOS, valores.get('tamano'), ETIQUETAS_TAMANO)}{html_error_campo(errores, 'tamano')}</fieldset>
      <fieldset class="campo"><legend>Tipo de daño</legend>
        {html_opciones('profundidad', PROFUNDIDADES, valores.get('profundidad'), ETIQUETAS_PROFUNDIDAD)}{html_error_campo(errores, 'profundidad')}</fieldset>

      <div class="paso-cab"><div class="paso-num"><span>3</span></div><h3>Su entorno</h3></div>
      <fieldset class="campo"><legend>¿Circula transporte público por ahí?</legend>
        {html_opciones('transporte_publico', SI_NO, valores.get('transporte_publico'), ETIQUETAS_SI_NO)}{html_error_campo(errores, 'transporte_publico')}</fieldset>
      <fieldset class="campo"><legend>Frecuencia de tránsito</legend>
        {html_opciones('frecuencia_transito', FRECUENCIAS_TRANSITO, valores.get('frecuencia_transito'), ETIQUETAS_FRECUENCIA)}{html_error_campo(errores, 'frecuencia_transito')}</fieldset>
      <fieldset class="campo"><legend>¿Ha causado algún accidente?</legend>
        {html_opciones('accidentes', SI_NO, valores.get('accidentes'), ETIQUETAS_SI_NO)}{html_error_campo(errores, 'accidentes')}</fieldset>
      <fieldset class="campo"><legend>¿Está cerca de un hospital, escuela o zona de mucha afluencia?</legend>
        {html_opciones('zona_sensible', SI_NO, valores.get('zona_sensible'), ETIQUETAS_SI_NO)}{html_error_campo(errores, 'zona_sensible')}</fieldset>

      <div class="paso-cab"><div class="paso-num"><span>4</span></div><h3>Algo más (opcional)</h3></div>
      <div class="campo"><label class="etiqueta" for="comentario">Comentario</label>
        <textarea id="comentario" name="comentario" maxlength="500" placeholder="Ej. Está junto a la parada, se llena de agua cuando llueve.">{valor('comentario')}</textarea>
        <p class="ayuda">Máximo 500 caracteres. No escribas datos personales (teléfono, nombres).</p>
        {html_error_campo(errores, 'comentario')}</div>

      <button class="btn btn-grande" type="submit">Enviar reporte</button>
      <p class="nota-privacidad">Privacidad: el reporte del bache no guarda tu nombre ni tu correo; sólo se enlaza tu cuenta
        para evitar que el mismo bache cuente dos veces por la misma persona.</p>
    </form>
  </section>

  <aside class="mapa-reporte-caja">
    <div class="tarjeta">
      <div class="barra-busqueda">
        <input type="search" id="buscar-direccion" placeholder="Buscar dirección (ej. Av. Montevideo 100)" aria-label="Buscar dirección">
        <button type="button" class="btn btn-secundario btn-chico" id="btn-buscar">Buscar</button>
        <button type="button" class="btn btn-fantasma btn-chico" id="btn-mi-ubicacion">Usar mi ubicación</button>
      </div>
      <div id="mapa-reporte" role="application" aria-label="Mapa para marcar la ubicación del bache"></div>
      <p class="estado-ubicacion" id="estado-ubicacion" aria-live="polite">Haz clic en el mapa donde está el bache.</p>
    </div>
  </aside>
</main>"""
    return pagina_base("Reportar bache", cuerpo, "reportar", usuario, extra_head=LEAFLET_CSS,
                       extra_scripts=LEAFLET_JS + f"<script>{js_reporte()}</script>")


def campos_ocultos(valores: dict) -> str:
    return "".join(f'<input type="hidden" name="{campo}" value="{escape(str(valores.get(campo, "")))}">'
                   for campo in CAMPOS_REPORTE)


def html_pagina_duplicados(usuario, valores: dict, duplicados: list, latitud: float, longitud: float) -> str:
    """Pregunta si el bache ya estaba reportado (desduplicación)."""
    tarjetas = []
    for bache in duplicados:
        metros = distancia_en_km(latitud, longitud, bache.latitud, bache.longitud) * 1000
        semaforo = bache.color_semaforo()
        color = {"Rojo": "var(--rojo)", "Amarillo": "var(--amarillo)", "Verde": "var(--verde)"}[semaforo]
        tarjetas.append(f"""<div class="tarjeta duplicado">
  <span class="ipu-insignia" style="--c:{color}">{round(bache.calcular_ipu())}</span>
  <div><b>#{bache.id_bache} · {escape(bache.calle)}</b><br>
    <small>{escape(bache.colonia)} · a {metros:.0f} m de tu punto · {escape(bache.tamano.lower())}, {escape(bache.profundidad.lower())} ·
    {bache.num_reportes} reporte(s)</small></div>
  <form method="post" action="{url_for('pagina_reportar')}">
    {campo_csrf()}{campos_ocultos(valores)}
    <input type="hidden" name="decision" value="sumar"><input type="hidden" name="id_destino" value="{bache.id_bache}">
    <button class="btn btn-chico" type="submit">Es el mismo bache</button>
  </form>
</div>""")

    cuerpo = f"""<main class="centrado">
  <h1>Ya hay un reporte cerca</h1>
  <p class="suave">Encontramos {len(duplicados)} bache(s) pendiente(s) a menos de {RADIO_DUPLICADO_METROS} m del punto que marcaste.
     Si es el mismo, suma tu reporte: más reportes ayudan a confirmar el problema sin duplicar trabajo.</p>
  <div class="lista-duplicados">{"".join(tarjetas)}</div>
  <form method="post" action="{url_for('pagina_reportar')}">
    {campo_csrf()}{campos_ocultos(valores)}
    <input type="hidden" name="decision" value="nuevo">
    <div class="acciones-fila">
      <button class="btn btn-secundario" type="submit">No, es otro bache: crear reporte nuevo</button>
      <a class="btn btn-fantasma" href="{url_for('pagina_reportar')}">Cancelar</a>
    </div>
  </form>
</main>"""
    return pagina_base("Posible duplicado", cuerpo, "reportar", usuario)


def html_pagina_detalle_reporte(usuario, bache: ReporteBache) -> str:
    semaforo = bache.color_semaforo()
    color = {"Rojo": "var(--rojo)", "Amarillo": "var(--amarillo)", "Verde": "var(--verde)"}[semaforo]
    cuerpo = f"""<main class="centrado"><div class="tarjeta">
  <h1>Bache #{bache.id_bache}</h1>
  <div class="resultado">
    <div class="senal-ipu" style="--c:{color}" role="img" aria-label="IPU {bache.calcular_ipu()} de 100, prioridad {semaforo}">
      <div><b>{bache.calcular_ipu():g}</b><small>IPU · {semaforo}</small></div>
    </div>
    <div>
      <p><b>{escape(bache.calle)}</b><br><span class="suave">{escape(bache.colonia)} · {escape(bache.alcaldia)}</span></p>
      <p class="suave">{escape(bache.explicar_prioridad().capitalize())}.</p>
    </div>
  </div>
  <div class="datos">
    <div><span>Prob. de siniestro en 72 h</span><b>{bache.probabilidad_siniestro_72h()}%</b></div>
    <div><span>Reportes ciudadanos</span><b>{bache.num_reportes}</b></div>
    <div><span>Tamaño / daño</span><b>{escape(bache.tamano)} · {escape(bache.profundidad)}</b></div>
    <div><span>Estado</span><b>{escape(bache.estado)}</b></div>
  </div>
  <p class="ayuda">El sistema sugiere la prioridad con criterios verificables; la decisión final de atención es de la autoridad.</p>
  <div class="acciones-fila">
    <a class="btn" href="{url_for('pagina_mapa', bache=bache.id_bache)}">Ver en el mapa</a>
    <a class="btn btn-fantasma" href="{url_for('pagina_reportar')}">Hacer otro reporte</a>
  </div>
</div></main>"""
    return pagina_base(f"Bache #{bache.id_bache}", cuerpo, "reportar", usuario)


# ===========================================================================
#  HTML: ADMINISTRACIÓN (apartado 3)
# ===========================================================================
def html_fila_admin(bache: ReporteBache, meses: float, volver: str) -> str:
    estimacion = bache.comparar_preventivo_vs_correctivo(meses)
    semaforo = bache.color_semaforo()
    color = {"Rojo": "var(--rojo)", "Amarillo": "var(--amarillo)", "Verde": "var(--verde)"}[semaforo]
    pendiente = bache.estado == "Pendiente"

    etiquetas = "".join(f"<span>{escape(texto)}</span>" for texto in (
        f"{bache.tamano} · {bache.profundidad}",
        f"Tránsito {bache.frecuencia_transito.lower()}",
        "Transporte público" if bache.transporte_publico == "Si" else "Sin transporte público",
        "Con accidentes" if bache.accidentes == "Si" else "Sin accidentes",
        "Zona sensible" if bache.zona_sensible == "Si" else "Sin zona sensible",
    ))
    comentario = f'<small title="{escape(bache.comentario)}">💬 {escape(bache.comentario[:70])}{"…" if len(bache.comentario) > 70 else ""}</small>' if bache.comentario else ""

    if pendiente:
        costo_hoy = formato_dinero(estimacion["costo_preventivo"])
        costo_espera = formato_dinero(estimacion["costo_correctivo"])
        ahorro = formato_dinero(estimacion["ahorro"])
    else:
        costo_hoy = costo_espera = ahorro = "—"

    boton_atender = ""
    if pendiente:
        boton_atender = f"""<form method="post" action="{url_for('admin_atender', id_bache=bache.id_bache)}">
  {campo_csrf()}<input type="hidden" name="volver" value="{escape(volver)}">
  <button class="btn btn-secundario btn-chico" type="submit">Marcar atendido</button></form>"""
    boton_eliminar = f"""<form method="post" action="{url_for('admin_eliminar', id_bache=bache.id_bache)}"
  onsubmit="return confirm('¿Eliminar el bache #{bache.id_bache} definitivamente? Se borrarán también sus reportes y no se puede deshacer.');">
  {campo_csrf()}<input type="hidden" name="volver" value="{escape(volver)}">
  <button class="btn btn-peligro btn-chico" type="submit">Eliminar (ya tapado)</button></form>"""

    fecha_atencion = (f"<br><small>Atendido: {bache.fecha_atencion:%Y-%m-%d}</small>"
                      if bache.fecha_atencion else "")
    clase_fila = "" if pendiente else ' class="atendido"'
    clase_estado = "estado-pendiente" if pendiente else "estado-atendido"

    return f"""<tr{clase_fila} data-semaforo="{semaforo}" data-estado="{escape(bache.estado)}">
  <td class="num">#{bache.id_bache}</td>
  <td class="ubicacion"><b>{escape(bache.calle)}</b><small>{escape(bache.colonia)} · {escape(bache.alcaldia)}</small>
    <small>{bache.latitud:.5f}, {bache.longitud:.5f}</small>{comentario}</td>
  <td class="etiquetas">{etiquetas}</td>
  <td class="num">{bache.num_reportes}</td>
  <td><div class="semaforo-celda"><span class="ipu-insignia" style="--c:{color}">{round(bache.calcular_ipu())}</span>{semaforo}</div></td>
  <td class="num">{bache.probabilidad_siniestro_72h()}%</td>
  <td class="num"><b>{costo_hoy}</b><br><small>{estimacion['area_preventivo']:.2f} m²</small></td>
  <td class="num">{costo_espera}<br><small>ahorro: {ahorro}</small></td>
  <td class="{clase_estado}">{escape(bache.estado)}<br><small>{bache.fecha_registro:%Y-%m-%d %H:%M}</small>{fecha_atencion}</td>
  <td><div class="acciones-celda">{boton_atender}{boton_eliminar}</div></td>
</tr>"""


def html_pagina_admin(usuario, baches: list, meses: float, filtro_estado: str, volver: str) -> str:
    ordenados = ranking_por_prioridad(baches)  # mayor IPU primero (cola de prioridad)
    pendientes = [b for b in baches if b.estado == "Pendiente"]
    conteo = {"Rojo": 0, "Amarillo": 0, "Verde": 0}
    costo_hoy = costo_espera = 0.0
    for bache in pendientes:
        conteo[bache.color_semaforo()] += 1
        estimacion = bache.comparar_preventivo_vs_correctivo(meses)
        costo_hoy += estimacion["costo_preventivo"]
        costo_espera += estimacion["costo_correctivo"]

    filas = "".join(html_fila_admin(bache, meses, volver) for bache in ordenados)
    if not filas:
        filas = '<tr><td colspan="10" class="suave">No hay baches registrados con este filtro.</td></tr>'

    def opcion_estado(valor, texto):
        marcada = " selected" if filtro_estado == valor else ""
        return f'<option value="{valor}"{marcada}>{texto}</option>'

    cuerpo = f"""<main class="admin-contenedor">
  <h1>Panel administrador</h1>
  <p class="suave">Base de datos completa de baches, costo estimado de reparación y limpieza de los que ya se taparon.
     Ordenados por prioridad (IPU de mayor a menor).</p>

  <div class="estadisticas">
    <div class="estadistica"><span>Baches registrados</span><b>{len(baches)}</b></div>
    <div class="estadistica" style="--c:var(--via)"><span>Pendientes</span><b>{len(pendientes)}</b></div>
    <div class="estadistica" style="--c:var(--rojo)"><span>Prioridad roja</span><b>{conteo['Rojo']}</b></div>
    <div class="estadistica" style="--c:var(--amarillo)"><span>Prioridad amarilla</span><b>{conteo['Amarillo']}</b></div>
    <div class="estadistica" style="--c:var(--verde)"><span>Prioridad verde</span><b>{conteo['Verde']}</b></div>
    <div class="estadistica" style="--c:var(--cono)"><span>Costo de repararlos hoy</span><b>{formato_dinero(costo_hoy)}</b></div>
    <div class="estadistica" style="--c:var(--rojo)"><span>Costo si se espera {meses:g} meses</span><b>{formato_dinero(costo_espera)}</b></div>
    <div class="estadistica" style="--c:var(--verde)"><span>Ahorro de actuar a tiempo</span><b>{formato_dinero(costo_espera - costo_hoy)}</b></div>
  </div>

  <form class="herramientas" method="get" action="{url_for('pagina_admin')}">
    <div class="campo"><label class="etiqueta" for="estado">Estado</label>
      <select id="estado" name="estado" data-autoenvio>
        {opcion_estado('todos', 'Todos')}{opcion_estado('Pendiente', 'Pendientes')}{opcion_estado('Atendido', 'Atendidos')}
      </select></div>
    <div class="campo"><label class="etiqueta" for="meses">Meses de espera (costo correctivo)</label>
      <input type="number" id="meses" name="meses" min="1" max="60" step="1" value="{meses:g}" data-autoenvio></div>
    <div class="campo"><label class="etiqueta" for="filtro-semaforo">Semáforo</label>
      <select id="filtro-semaforo"><option value="">Todos</option><option>Rojo</option><option>Amarillo</option><option>Verde</option></select></div>
    <div class="campo ancho"><label class="etiqueta" for="buscar-tabla">Buscar en la tabla</label>
      <input type="search" id="buscar-tabla" placeholder="Calle, colonia, ID…"></div>
    <a class="btn btn-secundario" href="{url_for('admin_exportar', meses=f'{meses:g}')}">Descargar CSV</a>
  </form>
  <p class="suave" id="conteo-filas" aria-live="polite"></p>

  <div class="tabla-caja">
    <table id="tabla-baches">
      <thead><tr>
        <th class="num">ID</th><th>Ubicación</th><th>Características</th><th class="num">Reportes</th>
        <th>Prioridad</th><th class="num">Siniestro 72 h</th>
        <th class="num">Costo hoy (preventivo)</th><th class="num">Costo en {meses:g} m (correctivo)</th>
        <th>Estado</th><th>Acciones</th>
      </tr></thead>
      <tbody>{filas}</tbody>
    </table>
  </div>
  <p class="pie-tabla">Costos con el Tabulador General CDMX (julio 2026): {formato_dinero(PRECIO_M2_POR_PROFUNDIDAD['Superficial'])}/m² (5 cm)
    y {formato_dinero(PRECIO_M2_POR_PROFUNDIDAD['Profundo'])}/m² (10 cm). La columna "correctivo" estima el volumen de asfalto perdido con la
    integral definida del modelo de degradación y repara con bacheo profundo. Son estimaciones para apoyar la decisión.
    "Marcar atendido" conserva el historial; "Eliminar" borra el bache de la base de datos.</p>
</main>"""
    return pagina_base("Panel administrador", cuerpo, "admin", usuario,
                       extra_scripts=f"<script>{js_admin()}</script>")


# ===========================================================================
#  HTML: ACCESO (iniciar sesión y crear cuenta)
# ===========================================================================
def html_pagina_login(usuario, correo: str = "", error: str = "", siguiente: str = "") -> str:
    aviso = f'<div class="resumen-errores" role="alert">{escape(error)}</div>' if error else ""
    cuerpo = f"""<main class="auth-caja"><div class="tarjeta">
  <h1>Iniciar sesión</h1>
  <p class="suave">Entra como usuario para reportar baches, o como administrador para abrir el panel.</p>
  {aviso}
  <form method="post" action="{url_for('login')}">
    {campo_csrf()}<input type="hidden" name="siguiente" value="{escape(siguiente)}">
    <div class="campo"><label class="etiqueta" for="correo">Correo</label>
      <input type="email" id="correo" name="correo" value="{escape(correo)}" autocomplete="email" required autofocus></div>
    <div class="campo"><label class="etiqueta" for="contrasena">Contraseña</label>
      <input type="password" id="contrasena" name="contrasena" autocomplete="current-password" required></div>
    <button class="btn btn-bloque" type="submit">Entrar</button>
  </form>
  <p class="auth-pie">¿No tienes cuenta? <a href="{url_for('registro')}">Crear cuenta</a></p>
</div></main>"""
    return pagina_base("Iniciar sesión", cuerpo, usuario=usuario)


def html_pagina_registro(usuario, nombre: str = "", correo: str = "", error: str = "") -> str:
    aviso = f'<div class="resumen-errores" role="alert">{escape(error)}</div>' if error else ""
    cuerpo = f"""<main class="auth-caja"><div class="tarjeta">
  <h1>Crear cuenta</h1>
  <p class="suave">Con una cuenta puedes reportar baches. Sólo pedimos lo necesario: nombre, correo y contraseña.</p>
  {aviso}
  <form method="post" action="{url_for('registro')}">
    {campo_csrf()}
    <div class="campo"><label class="etiqueta" for="nombre">Nombre</label>
      <input type="text" id="nombre" name="nombre" value="{escape(nombre)}" maxlength="80" autocomplete="name" required autofocus></div>
    <div class="campo"><label class="etiqueta" for="correo">Correo</label>
      <input type="email" id="correo" name="correo" value="{escape(correo)}" maxlength="120" autocomplete="email" required></div>
    <div class="campo"><label class="etiqueta" for="contrasena">Contraseña</label>
      <input type="password" id="contrasena" name="contrasena" minlength="8" maxlength="128" autocomplete="new-password" required>
      <p class="ayuda">Mínimo 8 caracteres. Se guarda cifrada (hash), nunca en texto plano.</p></div>
    <button class="btn btn-bloque" type="submit">Crear cuenta</button>
  </form>
  <p class="auth-pie">¿Ya tienes cuenta? <a href="{url_for('login')}">Iniciar sesión</a></p>
</div></main>"""
    return pagina_base("Crear cuenta", cuerpo, usuario=usuario)


# ===========================================================================
#  VALIDACIÓN DEL FORMULARIO DE REPORTE
# ===========================================================================
def validar_formulario_reporte(formulario) -> tuple:
    """Devuelve (datos limpios, errores por campo)."""
    datos, errores = {}, {}

    for campo, maximo, nombre in (("calle", 120, "la calle"), ("colonia", 120, "la colonia"),
                                  ("alcaldia", 80, "la alcaldía")):
        texto = formulario.get(campo, "").strip()
        if not texto:
            errores[campo] = f"Escribe {nombre}."
        elif len(texto) > maximo:
            errores[campo] = f"{nombre.capitalize()} admite máximo {maximo} caracteres."
        datos[campo] = texto

    try:
        latitud = float(formulario.get("latitud", "").replace(",", "."))
        longitud = float(formulario.get("longitud", "").replace(",", "."))
    except ValueError:
        errores["ubicacion"] = "Marca el bache en el mapa."
    else:
        if coordenadas_validas(latitud, longitud):
            datos["latitud"], datos["longitud"] = latitud, longitud
        else:
            errores["ubicacion"] = "La ubicación debe estar dentro de la Ciudad de México."

    for campo, opciones, nombre in (
            ("tamano", TAMANOS, "el tamaño"), ("profundidad", PROFUNDIDADES, "el tipo de daño"),
            ("transporte_publico", SI_NO, "si circula transporte público"),
            ("frecuencia_transito", FRECUENCIAS_TRANSITO, "la frecuencia de tránsito"),
            ("accidentes", SI_NO, "si ha causado accidentes"),
            ("zona_sensible", SI_NO, "si está cerca de una zona sensible")):
        elegida = elegir_opcion(formulario.get(campo, ""), opciones)
        if elegida is None:
            errores[campo] = f"Elige {nombre}."
        datos[campo] = elegida

    comentario = formulario.get("comentario", "").strip()
    if len(comentario) > 500:
        errores["comentario"] = "El comentario admite máximo 500 caracteres."
    datos["comentario"] = comentario
    return datos, errores


def leer_meses(texto) -> float:
    try:
        meses = float(texto)
    except (TypeError, ValueError):
        return MESES_POR_DEFECTO
    if meses != meses or meses < 1:  # NaN o menor a 1
        return MESES_POR_DEFECTO
    return min(meses, 60.0)


def celda_csv_segura(valor):
    """Evita 'inyección de fórmulas' al abrir el CSV en Excel."""
    if isinstance(valor, str) and valor[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + valor
    return valor


# ===========================================================================
#  RUTAS
# ===========================================================================
@app.route("/")
def inicio():
    return redirect(url_for("pagina_mapa"))


@app.route("/estilos.css")
def estilos():
    respuesta = Response(css_global(), mimetype="text/css")
    respuesta.headers["Cache-Control"] = "public, max-age=300"
    return respuesta


@app.route("/favicon.ico")
def favicon():
    return Response(status=204)


@app.route("/mapa")
def pagina_mapa():
    return html_pagina_mapa(usuario_actual())


@app.route("/api/baches")
def api_baches():
    """Baches pendientes en JSON (sin comentarios, para no exponer datos personales)."""
    baches = obtener_bd().listar_pendientes()
    respuesta = jsonify({"total": len(baches), "baches": [b.a_diccionario() for b in baches]})
    respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


@app.route("/reportar", methods=["GET", "POST"])
@requiere_login
def pagina_reportar():
    usuario = usuario_actual()
    if request.method == "GET":
        return html_pagina_reporte(usuario, {}, {})

    datos, errores = validar_formulario_reporte(request.form)
    if errores:
        return html_pagina_reporte(usuario, request.form.to_dict(), errores)

    bd = obtener_bd()
    decision = request.form.get("decision", "")

    if decision == "sumar":
        destino = request.form.get("id_destino", "")
        bache = bd.buscar_por_id(int(destino)) if destino.isdigit() else None
        if bache is None or bache.estado != "Pendiente":
            flash("Ese bache ya no está pendiente. Puedes registrarlo como nuevo.", "aviso")
            return html_pagina_reporte(usuario, request.form.to_dict(), {})
        if bd.sumar_reporte(bache.id_bache, usuario.id_usuario):
            flash("¡Listo! Sumamos tu reporte al bache que ya estaba registrado.", "ok")
        else:
            flash("Tu cuenta ya había reportado este bache; no se cuenta dos veces.", "aviso")
        return redirect(url_for("pagina_detalle_reporte", id_bache=bache.id_bache))

    if decision != "nuevo":
        duplicados = bd.buscar_duplicados_cercanos(datos["latitud"], datos["longitud"])
        if duplicados:
            return html_pagina_duplicados(usuario, request.form.to_dict(), duplicados,
                                          datos["latitud"], datos["longitud"])

    reporte = ReporteBache(
        datos["calle"], datos["colonia"], datos["alcaldia"], datos["latitud"], datos["longitud"],
        datos["tamano"], datos["profundidad"], datos["transporte_publico"],
        datos["frecuencia_transito"], datos["accidentes"], datos["zona_sensible"], datos["comentario"])
    bd.guardar_bache(reporte, usuario.id_usuario)
    flash("¡Reporte registrado! Gracias por ayudar a priorizar el bacheo.", "ok")
    return redirect(url_for("pagina_detalle_reporte", id_bache=reporte.id_bache))


@app.route("/reporte/<int:id_bache>")
def pagina_detalle_reporte(id_bache):
    bache = obtener_bd().buscar_por_id(id_bache)
    if bache is None:
        abort(404)
    return html_pagina_detalle_reporte(usuario_actual(), bache)


@app.route("/login", methods=["GET", "POST"])
def login():
    usuario = usuario_actual()
    siguiente = destino_seguro(request.values.get("siguiente"), url_for("pagina_mapa"))
    if request.method == "GET":
        if usuario is not None:
            return redirect(siguiente)
        return html_pagina_login(usuario, siguiente=siguiente)

    correo = request.form.get("correo", "").strip().lower()
    clave = f"{request.remote_addr}|{correo}"
    if demasiados_intentos(clave):
        return html_pagina_login(usuario, correo, "Demasiados intentos fallidos. Espera unos minutos e inténtalo de nuevo.", siguiente)

    autenticado = autenticar_usuario(obtener_bd(), correo, request.form.get("contrasena", ""))
    if autenticado is None:
        registrar_intento_fallido(clave)
        return html_pagina_login(usuario, correo, "Correo o contraseña incorrectos.", siguiente)

    INTENTOS_FALLIDOS.pop(clave, None)
    session.clear()
    session["id_usuario"] = autenticado.id_usuario
    flash(f"Bienvenido, {autenticado.nombre}.", "ok")
    return redirect(siguiente)


@app.route("/registro", methods=["GET", "POST"])
def registro():
    usuario = usuario_actual()
    if request.method == "GET":
        if usuario is not None:
            return redirect(url_for("pagina_mapa"))
        return html_pagina_registro(usuario)

    nombre = request.form.get("nombre", "")
    correo = request.form.get("correo", "")
    try:
        nuevo = registrar_usuario(obtener_bd(), nombre, correo, request.form.get("contrasena", ""))
    except ValueError as error:
        return html_pagina_registro(usuario, nombre, correo, str(error))

    session.clear()
    session["id_usuario"] = nuevo.id_usuario
    flash("Cuenta creada. ¡Ya puedes reportar baches!", "ok")
    return redirect(url_for("pagina_reportar"))


@app.route("/salir", methods=["POST"])
def salir():
    session.clear()
    flash("Sesión cerrada.", "ok")
    return redirect(url_for("pagina_mapa"))


@app.route("/admin")
@requiere_admin
def pagina_admin():
    meses = leer_meses(request.args.get("meses"))
    filtro_estado = request.args.get("estado", "todos")
    if filtro_estado not in ("Pendiente", "Atendido"):
        filtro_estado = "todos"
    baches = obtener_bd().listar_baches(None if filtro_estado == "todos" else filtro_estado)
    volver = url_for("pagina_admin", estado=filtro_estado, meses=f"{meses:g}")
    return html_pagina_admin(usuario_actual(), baches, meses, filtro_estado, volver)


@app.route("/admin/atender/<int:id_bache>", methods=["POST"])
@requiere_admin
def admin_atender(id_bache):
    if obtener_bd().marcar_atendido(id_bache):
        flash(f"Bache #{id_bache} marcado como atendido.", "ok")
    else:
        flash(f"El bache #{id_bache} no existe o ya estaba atendido.", "aviso")
    return redirect(destino_seguro(request.form.get("volver"), url_for("pagina_admin")))


@app.route("/admin/eliminar/<int:id_bache>", methods=["POST"])
@requiere_admin
def admin_eliminar(id_bache):
    if obtener_bd().eliminar_bache(id_bache):
        flash(f"Bache #{id_bache} eliminado de la base de datos.", "ok")
    else:
        flash(f"El bache #{id_bache} ya no existe.", "aviso")
    return redirect(destino_seguro(request.form.get("volver"), url_for("pagina_admin")))


@app.route("/admin/exportar.csv")
@requiere_admin
def admin_exportar():
    """CSV con toda la base (útil para Power BI / Excel)."""
    meses = leer_meses(request.args.get("meses"))
    salida = io.StringIO()
    escritor = csv.writer(salida)
    escritor.writerow(["id_bache", "calle", "colonia", "alcaldia", "latitud", "longitud", "fecha_registro",
                       "tamano", "profundidad", "transporte_publico", "frecuencia_transito", "accidentes",
                       "zona_sensible", "num_reportes", "estado", "fecha_atencion", "ipu", "semaforo",
                       "prob_siniestro_72h_pct", "costo_reparar_hoy_mxn", f"costo_reparar_en_{meses:g}_meses_mxn",
                       "comentario"])
    for bache in ranking_por_prioridad(obtener_bd().listar_baches()):
        estimacion = bache.comparar_preventivo_vs_correctivo(meses)
        fila = [bache.id_bache, bache.calle, bache.colonia, bache.alcaldia, bache.latitud, bache.longitud,
                bache.fecha_registro.strftime("%Y-%m-%d %H:%M"), bache.tamano, bache.profundidad,
                bache.transporte_publico, bache.frecuencia_transito, bache.accidentes, bache.zona_sensible,
                bache.num_reportes, bache.estado,
                bache.fecha_atencion.strftime("%Y-%m-%d %H:%M") if bache.fecha_atencion else "",
                bache.calcular_ipu(), bache.color_semaforo(), bache.probabilidad_siniestro_72h(),
                round(estimacion["costo_preventivo"], 2), round(estimacion["costo_correctivo"], 2),
                bache.comentario]
        escritor.writerow([celda_csv_segura(celda) for celda in fila])
    respuesta = Response("﻿" + salida.getvalue(), mimetype="text/csv; charset=utf-8")
    respuesta.headers["Content-Disposition"] = "attachment; filename=baches.csv"
    return respuesta


# ---------- Páginas de error ----------
@app.errorhandler(Error)
def error_de_base_de_datos(error):
    app.logger.error("Error de MySQL: %s", error)
    return html_pagina_mensaje(
        "No hay conexión con la base de datos",
        "Revisa que MySQL esté encendido, que hayas ejecutado base_de_datos.sql y que los datos del archivo .env sean correctos.",
    ), 503


@app.errorhandler(400)
def error_400(_error):
    return html_pagina_mensaje("Solicitud no válida",
                               "La sesión del formulario venció. Recarga la página e inténtalo de nuevo.",
                               usuario_seguro()), 400


@app.errorhandler(403)
def error_403(_error):
    return html_pagina_mensaje("Acceso restringido",
                               "Esta sección es sólo para cuentas de administrador.", usuario_seguro()), 403


@app.errorhandler(404)
def error_404(_error):
    return html_pagina_mensaje("No encontramos esa página",
                               "Puede que el bache ya se haya eliminado o que la dirección esté mal escrita.",
                               usuario_seguro()), 404


if __name__ == "__main__":
    # Con debug=True se expone el depurador de Werkzeug: NO lo actives si compartes un link público.
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")),
            debug=os.getenv("FLASK_DEBUG") == "1")
