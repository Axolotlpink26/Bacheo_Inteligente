"""
Sistema de Bacheo Inteligente y Priorización Urbana - CDMX (Alcaldía Gustavo A. Madero)
Encargados: Equipo 2 del la clase 301
La estructura de la base de datos se encuentra en el archivo `base_de_datos.sql`.
La interfaz web (`interfaz_web.py`) reutiliza todo lo que está aquí.
"""

import getpass
import heapq
import math
import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

try:  # python-dotenv es opcional: si existe, lee las variables del archivo .env
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import mysql.connector
from mysql.connector import Error, IntegrityError, errorcode
from werkzeug.security import check_password_hash, generate_password_hash

# CONFIGURACIÓN

CONFIG_CONEXION = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
}
NOMBRE_BASE_DE_DATOS = os.getenv("DB_NAME", "bacheo_inteligente")
ZONA_HORARIA = ZoneInfo("America/Mexico_City")

TAMANOS = ("Pequeño", "Mediano", "Grande")
PROFUNDIDADES = ("Superficial", "Profundo")
FRECUENCIAS_TRANSITO = ("Diario", "Semanal", "Ocasional")
SI_NO = ("Si", "No")
ROLES = ("usuario", "administrador")

# Areá Geográfica del proyecto
LATITUD_MINIMA, LATITUD_MAXIMA = 19.0, 19.8
LONGITUD_MINIMA, LONGITUD_MAXIMA = -99.4, -98.9
CENTRO_ALCALDIA_GAM = (19.4900, -99.1100)

# Dos reportes a menos de esta distancia se consideran posibles duplicados
RADIO_DUPLICADO_METROS = 20

# --- Índice de Prioridad Urbana (IPU): modelo multicriterio (pesos suman 1.0) ---
# (Por modificar)
PESOS_IPU = {
    "tamano": 0.25,
    "profundidad": 0.10,
    "transporte_publico": 0.20,
    "frecuencia_transito": 0.15,
    "accidentes": 0.15,
    "zona_sensible": 0.10,
    "reportes_ciudadanos": 0.05,  # peso bajo a propósito: evita favorecer zonas con más participación digital
}
assert math.isclose(sum(PESOS_IPU.values()), 1.0), "Los pesos del IPU deben sumar 1.0"

SEVERIDAD_POR_TAMANO = {"Pequeño": 1 / 3, "Mediano": 2 / 3, "Grande": 1.0}
VALOR_POR_PROFUNDIDAD = {"Superficial": 0.4, "Profundo": 1.0}
VALOR_POR_FRECUENCIA = {"Ocasional": 1 / 3, "Semanal": 2 / 3, "Diario": 1.0}
MAXIMO_REPORTES_CONSIDERADOS = 10

# Umbrales del semáforo de prioridad
UMBRAL_SEMAFORO_ROJO = 70
UMBRAL_SEMAFORO_AMARILLO = 40

# --- Modelo de probabilidad de siniestro a 72 horas (parámetros ilustrativos) ---
PROBABILIDAD_DIARIA_BASE = {"Ocasional": 0.005, "Semanal": 0.015, "Diario": 0.04}

# --- Modelo de degradación (Cálculo Integral): r(t) = A * f_carga * (1 + B*t)  [m³/mes] ---
TASA_DEGRADACION_BASE_M3_MES = 0.01     # A: m³/mes con carga normal
ACELERACION_DEGRADACION_POR_MES = 0.15  # B: la degradación se acelera con el tiempo (1/mes)
FACTOR_CARGA_POR_FRECUENCIA = {"Ocasional": 0.6, "Semanal": 1.0, "Diario": 1.5}
FACTOR_CARGA_TRANSPORTE_PUBLICO = 1.3   # multiplicador por el peso del transporte público

AREA_M2_POR_TAMANO = {"Pequeño": 0.25, "Mediano": 1.0, "Grande": 3.0}
PROFUNDIDAD_METROS = {"Superficial": 0.05, "Profundo": 0.10}

# Precios unitarios $/m² - Tabulador General CDMX, julio 2026 (Bacheo Mezcla Asfáltica Templada)
PRECIO_M2_POR_PROFUNDIDAD = {
    "Superficial": 448.45,  # RMQL12AA (5 cm)
    "Profundo": 866.50,     # RMQL12DC (10 cm)
}

ETIQUETA_SEMAFORO = {"Rojo": "🔴 ROJO", "Amarillo": "🟡 AMARILLO", "Verde": "🟢 VERDE"}


# UTILIDADES
def ahora_cdmx() -> datetime:
    # Fecha y hora actual de la Ciudad de México
    return datetime.now(ZONA_HORARIA).replace(tzinfo=None)


def normalizar_texto(texto: str) -> str:
    # Minúsculas y sin acentos, para comparar entradas del usuario
    texto = unicodedata.normalize("NFD", str(texto).strip().lower())
    return "".join(c for c in texto if unicodedata.category(c) != "Mn")


def elegir_opcion(valor, opciones):
    # Devuelve la opción oficial que coincide con `valor` (ignora mayúsculas y acentos), o None
    equivalencias = {normalizar_texto(opcion): opcion for opcion in opciones}
    return equivalencias.get(normalizar_texto(valor))


def distancia_en_km(latitud_a, longitud_a, latitud_b, longitud_b) -> float:
    # Distancia entre dos coordenadas con la fórmula de Haversine
    radio_tierra_km = 6371.0088
    lat_a, lat_b = math.radians(latitud_a), math.radians(latitud_b)
    delta_lat = lat_b - lat_a
    delta_lng = math.radians(longitud_b - longitud_a)
    a = math.sin(delta_lat / 2) ** 2 + math.cos(lat_a) * math.cos(lat_b) * math.sin(delta_lng / 2) ** 2
    return 2 * radio_tierra_km * math.asin(math.sqrt(a))


def coordenadas_validas(latitud: float, longitud: float) -> bool:
    return (math.isfinite(latitud) and math.isfinite(longitud)
            and LATITUD_MINIMA <= latitud <= LATITUD_MAXIMA
            and LONGITUD_MINIMA <= longitud <= LONGITUD_MAXIMA)


def formato_dinero(cantidad: float) -> str:
    return f"${cantidad:,.2f}"


# CLASES DEL DOMINIO

class Bache:
    """Datos de ubicación y registro de un bache."""

    def __init__(self, calle: str, colonia: str, alcaldia: str,
                 latitud: float, longitud: float,
                 id_bache: int = None, fecha_registro: datetime = None):
        # El ID lo asigna MySQL (AUTO_INCREMENT) al guardar el reporte
        self.id_bache = id_bache
        self.calle = calle
        self.colonia = colonia
        self.alcaldia = alcaldia
        self.latitud = float(latitud)
        self.longitud = float(longitud)
        self.fecha_registro = fecha_registro or ahora_cdmx()

    def imprimir_en_consola(self):
        print("=" * 45)
        print(f"ID: {self.id_bache}")
        print(f"Calle: {self.calle}")
        print(f"Colonia: {self.colonia}")
        print(f"Alcaldía: {self.alcaldia}")
        print(f"Coordenadas: {self.latitud:.6f}, {self.longitud:.6f}")
        print(f"Fecha de registro: {self.fecha_registro.strftime('%Y-%m-%d %H:%M')}")


class ReporteBache(Bache):
    # Bache con sus características de riesgo; calcula prioridad, probabilidad y costos

    def __init__(self, calle: str, colonia: str, alcaldia: str,
                 latitud: float, longitud: float,
                 tamano: str, profundidad: str,
                 transporte_publico: str, frecuencia_transito: str,
                 accidentes: str, zona_sensible: str = "No",
                 comentario: str = "", num_reportes: int = 1,
                 estado: str = "Pendiente", id_bache: int = None,
                 fecha_registro: datetime = None, fecha_atencion: datetime = None):
        super().__init__(calle, colonia, alcaldia, latitud, longitud, id_bache, fecha_registro)
        self.tamano = tamano
        self.profundidad = profundidad
        self.transporte_publico = transporte_publico
        self.frecuencia_transito = frecuencia_transito
        self.accidentes = accidentes
        self.zona_sensible = zona_sensible
        self.comentario = comentario or ""
        self.num_reportes = int(num_reportes)
        self.estado = estado
        self.fecha_atencion = fecha_atencion

    # Priorización
    def calcular_ipu(self) -> float:
        """Índice de Prioridad Urbana (0-100): combinación ponderada de criterios."""
        puntaje = (
            PESOS_IPU["tamano"] * SEVERIDAD_POR_TAMANO[self.tamano]
            + PESOS_IPU["profundidad"] * VALOR_POR_PROFUNDIDAD[self.profundidad]
            + PESOS_IPU["transporte_publico"] * (1.0 if self.transporte_publico == "Si" else 0.0)
            + PESOS_IPU["frecuencia_transito"] * VALOR_POR_FRECUENCIA[self.frecuencia_transito]
            + PESOS_IPU["accidentes"] * (1.0 if self.accidentes == "Si" else 0.0)
            + PESOS_IPU["zona_sensible"] * (1.0 if self.zona_sensible == "Si" else 0.0)
            + PESOS_IPU["reportes_ciudadanos"]
            * (min(self.num_reportes, MAXIMO_REPORTES_CONSIDERADOS) / MAXIMO_REPORTES_CONSIDERADOS)
        )
        return round(puntaje * 100, 1)

    def color_semaforo(self) -> str:
        ipu = self.calcular_ipu()
        if ipu >= UMBRAL_SEMAFORO_ROJO:
            return "Rojo"
        if ipu >= UMBRAL_SEMAFORO_AMARILLO:
            return "Amarillo"
        return "Verde"

    def explicar_prioridad(self) -> str:
        # Factores que explican la prioridad (criterios verificables y transparentes)
        factores = [f"tamaño {self.tamano.lower()}", f"daño {self.profundidad.lower()}",
                    f"tránsito {self.frecuencia_transito.lower()}"]
        if self.transporte_publico == "Si":
            factores.append("ruta de transporte público")
        if self.accidentes == "Si":
            factores.append("antecedente de accidentes")
        if self.zona_sensible == "Si":
            factores.append("cerca de zona sensible")
        if self.num_reportes > 1:
            factores.append(f"{self.num_reportes} reportes ciudadanos")
        return ", ".join(factores)

    def probabilidad_siniestro_72h(self) -> float:
        # P(al menos un siniestro en 72 h) = 1 - (1 - p_dia)^3, con p_dia ajustada por factores
        probabilidad_diaria = PROBABILIDAD_DIARIA_BASE[self.frecuencia_transito]
        if self.accidentes == "Si":
            probabilidad_diaria *= 1.5
        if self.profundidad == "Profundo":
            probabilidad_diaria *= 1.3
        if self.tamano == "Grande":
            probabilidad_diaria *= 1.2
        probabilidad_diaria = min(probabilidad_diaria, 0.95)
        return round((1 - (1 - probabilidad_diaria) ** 3) * 100, 2)

    # Degradación (integrales), material y costo
    def factor_de_carga(self) -> float:
        factor = FACTOR_CARGA_POR_FRECUENCIA[self.frecuencia_transito]
        if self.transporte_publico == "Si":
            factor *= FACTOR_CARGA_TRANSPORTE_PUBLICO
        return factor

    def tasa_degradacion(self, mes: float) -> float:
        # r(t) en m³/mes, tasa de pérdida de volumen de asfalto en el mes t
        return (TASA_DEGRADACION_BASE_M3_MES * self.factor_de_carga()
                * (1 + ACELERACION_DEGRADACION_POR_MES * mes))

    def volumen_perdido(self, meses: float) -> float:
        # V(T) = ∫0^T r(t) dt = A·f·(T + B·T²/2)  [m³]
        return (TASA_DEGRADACION_BASE_M3_MES * self.factor_de_carga()
                * (meses + ACELERACION_DEGRADACION_POR_MES * meses ** 2 / 2))

    def area_a_reparar_hoy(self) -> float:
        return AREA_M2_POR_TAMANO[self.tamano]

    def costo_reparacion_hoy(self) -> float:
        # Costo de repararlo ahora (mantenimiento preventivo)
        return self.area_a_reparar_hoy() * PRECIO_M2_POR_PROFUNDIDAD[self.profundidad]

    def comparar_preventivo_vs_correctivo(self, meses: float) -> dict:
        # Compara reparar hoy (preventivo) contra esperar 'meses' y reparar después (correctivo)
        volumen_actual = AREA_M2_POR_TAMANO[self.tamano] * PROFUNDIDAD_METROS[self.profundidad]
        volumen_perdido = self.volumen_perdido(meses)

        # A) Preventivo: se repara hoy con el daño actual
        area_preventivo = self.area_a_reparar_hoy()
        costo_preventivo = self.costo_reparacion_hoy()

        # B) Correctivo: al esperar, el daño crece y requiere bacheo profundo (10 cm).
        #    El bache no se "encoge" con el tiempo, así que el área nunca es menor a la actual.
        area_correctivo = max(
            area_preventivo,
            (volumen_actual + volumen_perdido) / PROFUNDIDAD_METROS["Profundo"],
        )
        costo_correctivo = area_correctivo * PRECIO_M2_POR_PROFUNDIDAD["Profundo"]

        return {
            "volumen_actual": volumen_actual,
            "volumen_perdido": volumen_perdido,
            "area_preventivo": area_preventivo,
            "costo_preventivo": costo_preventivo,
            "area_correctivo": area_correctivo,
            "costo_correctivo": costo_correctivo,
            "ahorro": costo_correctivo - costo_preventivo,
        }

    # Presentación y serialización
    def imprimir_en_consola(self):
        super().imprimir_en_consola()
        print(f"Tamaño del bache: {self.tamano}")
        print(f"Tipo de daño: {self.profundidad}")
        print(f"Transporte público: {self.transporte_publico}")
        print(f"Frecuencia de tránsito: {self.frecuencia_transito}")
        print(f"Incidente previo: {self.accidentes}")
        print(f"Cerca de zona sensible: {self.zona_sensible}")
        print(f"Reportes ciudadanos: {self.num_reportes}")
        print(f"Estado: {self.estado}")
        print(f"Comentario: {self.comentario}")
        print(f"Prioridad (IPU): {self.calcular_ipu()}/100 -> {ETIQUETA_SEMAFORO[self.color_semaforo()]}")
        print(f"Prob. de siniestro a 72 h: {self.probabilidad_siniestro_72h()}%")
        print("=" * 45)

    def a_diccionario(self, incluir_comentario: bool = False) -> dict:
        # Representación lista para JSON. El comentario sólo se incluye si se pide (puede tener datos personales)
        datos = {
            "id_bache": self.id_bache,
            "calle": self.calle,
            "colonia": self.colonia,
            "alcaldia": self.alcaldia,
            "latitud": self.latitud,
            "longitud": self.longitud,
            "fecha_registro": self.fecha_registro.strftime("%Y-%m-%d %H:%M"),
            "tamano": self.tamano,
            "profundidad": self.profundidad,
            "transporte_publico": self.transporte_publico,
            "frecuencia_transito": self.frecuencia_transito,
            "accidentes": self.accidentes,
            "zona_sensible": self.zona_sensible,
            "num_reportes": self.num_reportes,
            "estado": self.estado,
            "ipu": self.calcular_ipu(),
            "semaforo": self.color_semaforo(),
            "prob_siniestro_72h": self.probabilidad_siniestro_72h(),
            "justificacion": self.explicar_prioridad(),
        }
        if incluir_comentario:
            datos["comentario"] = self.comentario
        return datos


@dataclass
class Usuario:
    id_usuario: int
    nombre: str
    correo: str
    contrasena_hash: str
    rol: str = "usuario"
    activo: bool = True

    @property
    def es_administrador(self) -> bool:
        return self.rol == "administrador"


def ranking_por_prioridad(baches, cantidad=None):
    # Ordena baches de mayor a menor IPU con una cola de prioridad (max-heap)
    # heapq es un min-heap: se guarda -IPU para obtener primero el de mayor prioridad.
    # El ID desempata (el reporte más antiguo va primero) y evita comparar objetos.
    cola = [(-bache.calcular_ipu(), bache.id_bache, bache) for bache in baches]
    heapq.heapify(cola)
    ordenados = []
    while cola and (cantidad is None or len(ordenados) < cantidad):
        ordenados.append(heapq.heappop(cola)[2])
    return ordenados


# BASE DE DATOS (Lo que se puso en MySQL). La estructura está en el archivo base_de_datos.sql

class BaseDatos:
    """Conexión y consultas. `vista_baches` (definida en el .sql) ya trae num_reportes."""

    def __init__(self):
        self.conexion = None

    def conectar(self):
        self.conexion = mysql.connector.connect(
            **CONFIG_CONEXION, database=NOMBRE_BASE_DE_DATOS, charset="utf8mb4")

    def cerrar(self):
        if self.conexion and self.conexion.is_connected():
            self.conexion.close()

    def _asegurar_conexion(self):
        if not self.conexion.is_connected():
            self.conexion.reconnect()

    @staticmethod
    def _fila_a_reporte(fila: dict) -> ReporteBache:
        return ReporteBache(
            calle=fila["calle"], colonia=fila["colonia"], alcaldia=fila["alcaldia"],
            latitud=fila["latitud"], longitud=fila["longitud"],
            tamano=fila["tamano"], profundidad=fila["profundidad"],
            transporte_publico=fila["transporte_publico"],
            frecuencia_transito=fila["frecuencia_transito"],
            accidentes=fila["accidentes"], zona_sensible=fila["zona_sensible"],
            comentario=fila["comentario"] or "", num_reportes=fila["num_reportes"],
            estado=fila["estado"], id_bache=fila["id_bache"],
            fecha_registro=fila["fecha_registro"], fecha_atencion=fila["fecha_atencion"],
        )

    def _consultar_filas(self, sql: str, parametros=()) -> list:
        self._asegurar_conexion()
        cursor = self.conexion.cursor(dictionary=True)
        try:
            cursor.execute(sql, parametros)
            return cursor.fetchall()
        finally:
            cursor.close()

    def _consultar_baches(self, sql: str, parametros=()) -> list:
        return [self._fila_a_reporte(fila) for fila in self._consultar_filas(sql, parametros)]

    def _ejecutar(self, sql: str, parametros=()) -> int:
        # Ejecuta INSERT/UPDATE/DELETE con commit; devuelve las filas afectadas
        self._asegurar_conexion()
        cursor = self.conexion.cursor()
        try:
            cursor.execute(sql, parametros)
            self.conexion.commit()
            return cursor.rowcount
        except Error:
            self.conexion.rollback()
            raise
        finally:
            cursor.close()

    # Baches
    def listar_baches(self, estado: str = None) -> list:
        if estado:
            return self._consultar_baches(
                "SELECT * FROM vista_baches WHERE estado = %s ORDER BY id_bache", (estado,))
        return self._consultar_baches("SELECT * FROM vista_baches ORDER BY id_bache")

    def listar_pendientes(self) -> list:
        return self.listar_baches("Pendiente")

    def recientes(self, cantidad: int = 5) -> list:
        return self._consultar_baches(
            "SELECT * FROM vista_baches ORDER BY fecha_registro DESC, id_bache DESC LIMIT %s",
            (cantidad,))

    def buscar_por_ubicacion(self, texto: str) -> list:
        patron = f"%{texto}%"
        return self._consultar_baches(
            "SELECT * FROM vista_baches WHERE calle LIKE %s OR colonia LIKE %s OR alcaldia LIKE %s "
            "ORDER BY id_bache", (patron, patron, patron))

    def buscar_por_id(self, id_bache: int):
        resultado = self._consultar_baches(
            "SELECT * FROM vista_baches WHERE id_bache = %s", (id_bache,))
        return resultado[0] if resultado else None

    def contar_baches(self) -> int:
        return self._consultar_filas("SELECT COUNT(*) AS total FROM baches")[0]["total"]

    def guardar_bache(self, bache: ReporteBache, id_usuario: int = None) -> int:
        # Inserta el bache y su primer reporte ciudadano en una sola transacción
        self._asegurar_conexion()
        cursor = self.conexion.cursor()
        try:
            cursor.execute(
                """INSERT INTO baches (calle, colonia, alcaldia, latitud, longitud, fecha_registro,
                       tamano, profundidad, transporte_publico, frecuencia_transito, accidentes,
                       zona_sensible, estado, comentario, id_usuario_registro)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (bache.calle, bache.colonia, bache.alcaldia, bache.latitud, bache.longitud,
                 bache.fecha_registro, bache.tamano, bache.profundidad, bache.transporte_publico,
                 bache.frecuencia_transito, bache.accidentes, bache.zona_sensible,
                 bache.estado, bache.comentario, id_usuario))
            bache.id_bache = cursor.lastrowid
            cursor.execute(
                "INSERT INTO reportes_ciudadanos (id_bache, id_usuario) VALUES (%s, %s)",
                (bache.id_bache, id_usuario))
            self.conexion.commit()
            bache.num_reportes = 1
            return bache.id_bache
        except Error:
            self.conexion.rollback()
            raise
        finally:
            cursor.close()

    def sumar_reporte(self, id_bache: int, id_usuario: int = None) -> bool:
        # Suma un reporte ciudadano a un bache existente. False si esa cuenta ya lo había reportado
        try:
            self._ejecutar(
                "INSERT INTO reportes_ciudadanos (id_bache, id_usuario) VALUES (%s, %s)",
                (id_bache, id_usuario))
            return True
        except IntegrityError as error:
            if error.errno == errorcode.ER_DUP_ENTRY:
                return False
            raise

    def buscar_duplicados_cercanos(self, latitud: float, longitud: float,
                                   radio_metros: float = RADIO_DUPLICADO_METROS) -> list:
        # Baches pendientes a menos de `radio_metros` del punto, del más cercano al más lejano
        delta_latitud = radio_metros / 111_000
        delta_longitud = radio_metros / (111_000 * math.cos(math.radians(latitud)))
        candidatos = self._consultar_baches(
            "SELECT * FROM vista_baches WHERE estado = 'Pendiente' "
            "AND latitud BETWEEN %s AND %s AND longitud BETWEEN %s AND %s",
            (latitud - delta_latitud, latitud + delta_latitud,
             longitud - delta_longitud, longitud + delta_longitud))
        con_distancia = []
        for candidato in candidatos:
            metros = distancia_en_km(latitud, longitud, candidato.latitud, candidato.longitud) * 1000
            if metros <= radio_metros:
                con_distancia.append((metros, candidato))
        con_distancia.sort(key=lambda par: par[0])
        return [candidato for _, candidato in con_distancia]

    def marcar_atendido(self, id_bache: int) -> bool:
        return self._ejecutar(
            "UPDATE baches SET estado = 'Atendido', fecha_atencion = %s "
            "WHERE id_bache = %s AND estado = 'Pendiente'",
            (ahora_cdmx(), id_bache)) > 0

    def eliminar_bache(self, id_bache: int) -> bool:
        # Borra el bache (y sus reportes ciudadanos, por ON DELETE CASCADE)
        return self._ejecutar("DELETE FROM baches WHERE id_bache = %s", (id_bache,)) > 0

    # Metodos para Usuarios
    @staticmethod
    def _fila_a_usuario(fila: dict) -> Usuario:
        return Usuario(id_usuario=fila["id_usuario"], nombre=fila["nombre"], correo=fila["correo"],
                       contrasena_hash=fila["contrasena_hash"], rol=fila["rol"],
                       activo=bool(fila["activo"]))

    def buscar_usuario_por_correo(self, correo: str):
        filas = self._consultar_filas("SELECT * FROM usuarios WHERE correo = %s", (correo,))
        return self._fila_a_usuario(filas[0]) if filas else None

    def buscar_usuario_por_id(self, id_usuario: int):
        filas = self._consultar_filas("SELECT * FROM usuarios WHERE id_usuario = %s", (id_usuario,))
        return self._fila_a_usuario(filas[0]) if filas else None

    def crear_usuario(self, nombre: str, correo: str, contrasena_hash: str, rol: str = "usuario") -> int:
        self._asegurar_conexion()
        cursor = self.conexion.cursor()
        try:
            cursor.execute(
                "INSERT INTO usuarios (nombre, correo, contrasena_hash, rol) VALUES (%s, %s, %s, %s)",
                (nombre, correo, contrasena_hash, rol))
            self.conexion.commit()
            return cursor.lastrowid
        except Error:
            self.conexion.rollback()
            raise
        finally:
            cursor.close()

    def actualizar_credenciales(self, correo: str, contrasena_hash: str, rol: str) -> bool:
        return self._ejecutar(
            "UPDATE usuarios SET contrasena_hash = %s, rol = %s, activo = 1 WHERE correo = %s",
            (contrasena_hash, rol, correo)) > 0


# CUENTAS DE USUARIO (registro e inicio de sesión)

PATRON_CORREO = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LONGITUD_MINIMA_CONTRASENA = 8


def validar_datos_de_cuenta(nombre: str, correo: str, contrasena: str):
    # Lanza ValueError con un mensaje claro si algo no cumple
    if not 2 <= len(nombre) <= 80:
        raise ValueError("El nombre debe tener entre 2 y 80 caracteres.")
    if len(correo) > 120 or not PATRON_CORREO.match(correo):
        raise ValueError("Escribe un correo electrónico válido.")
    if len(contrasena) < LONGITUD_MINIMA_CONTRASENA:
        raise ValueError(f"La contraseña debe tener al menos {LONGITUD_MINIMA_CONTRASENA} caracteres.")
    if len(contrasena) > 128:
        raise ValueError("La contraseña es demasiado larga (máximo 128 caracteres).")


def registrar_usuario(bd: BaseDatos, nombre: str, correo: str, contrasena: str,
                      rol: str = "usuario") -> Usuario:
    nombre, correo = nombre.strip(), correo.strip().lower()
    validar_datos_de_cuenta(nombre, correo, contrasena)
    if rol not in ROLES:
        raise ValueError("Rol no válido.")
    if bd.buscar_usuario_por_correo(correo):
        raise ValueError("Ya existe una cuenta con ese correo.")
    contrasena_hash = generate_password_hash(contrasena, method="pbkdf2:sha256")
    try:
        id_usuario = bd.crear_usuario(nombre, correo, contrasena_hash, rol)
    except IntegrityError as error:
        if error.errno == errorcode.ER_DUP_ENTRY:
            raise ValueError("Ya existe una cuenta con ese correo.") from error
        raise
    return Usuario(id_usuario, nombre, correo, contrasena_hash, rol, True)


def autenticar_usuario(bd: BaseDatos, correo: str, contrasena: str):
    # Devuelve el Usuario si las credenciales son correctas y la cuenta está activa; si no, None
    usuario = bd.buscar_usuario_por_correo(correo.strip().lower())
    if usuario and usuario.activo and check_password_hash(usuario.contrasena_hash, contrasena):
        return usuario
    return None



# MENÚ DE CONSOLA

def limpiar_pantalla():
    os.system("cls" if os.name == "nt" else "clear")


def pausar():
    input("\nPresiona Enter para continuar...")


def pedir_texto(mensaje: str) -> str:
    while True:
        valor = input(mensaje).strip()
        if valor:
            return valor
        print("  Este campo no puede estar vacío.")


def pedir_opcion(mensaje: str, opciones) -> str:
    while True:
        elegida = elegir_opcion(input(mensaje), opciones)
        if elegida:
            return elegida
        print(f"  Opción no válida. Elige entre: {', '.join(opciones)}")


def pedir_coordenadas() -> tuple:
    print("  (Tip: en Google Maps, clic derecho sobre el bache y copia las coordenadas)")
    while True:
        try:
            latitud = float(input("Latitud (ej. 19.4953): ").strip().replace(",", "."))
            longitud = float(input("Longitud (ej. -99.1198): ").strip().replace(",", "."))
        except ValueError:
            print("  Escribe números válidos.")
            continue
        if coordenadas_validas(latitud, longitud):
            return latitud, longitud
        print("  Las coordenadas quedan fuera de la Ciudad de México. Intenta de nuevo.")


def pedir_id(mensaje: str):
    entrada = input(mensaje).strip()
    if not entrada.isdigit():
        print("El ID debe ser un número.\n")
        return None
    return int(entrada)


def crear_reporte_consola(bd: BaseDatos):
    print("\n--- Nuevo reporte de bache ---")
    calle = pedir_texto("Calle/Avenida: ")
    colonia = pedir_texto("Colonia: ")
    alcaldia = pedir_texto("Alcaldía: ")
    latitud, longitud = pedir_coordenadas()

    # Desduplicación: varios vecinos pueden reportar el mismo bache
    for duplicado in bd.buscar_duplicados_cercanos(latitud, longitud):
        print(f"\nYa existe un reporte pendiente a menos de {RADIO_DUPLICADO_METROS} m "
              f"(ID {duplicado.id_bache}, {duplicado.calle}, bache {duplicado.tamano.lower()}, "
              f"{duplicado.profundidad.lower()}).")
        if pedir_opcion("¿Es el mismo bache? (Si/No): ", SI_NO) == "Si":
            bd.sumar_reporte(duplicado.id_bache)
            duplicado.num_reportes += 1
            print("\n--- Reporte existente actualizado ---")
            duplicado.imprimir_en_consola()
            print("Se sumó tu reporte al bache ya registrado.\n")
            return

    tamano = pedir_opcion("Tamaño del bache (Pequeño/Mediano/Grande): ", TAMANOS)
    profundidad = pedir_opcion("Tipo de daño (Superficial/Profundo): ", PROFUNDIDADES)
    transporte_publico = pedir_opcion("¿Circula transporte público? (Si/No): ", SI_NO)
    frecuencia_transito = pedir_opcion("Frecuencia de tránsito (Diario/Semanal/Ocasional): ",
                                       FRECUENCIAS_TRANSITO)
    accidentes = pedir_opcion("¿Ha causado algún accidente? (Si/No): ", SI_NO)
    zona_sensible = pedir_opcion("¿Está cerca de hospital, escuela o zona de alta afluencia? (Si/No): ", SI_NO)
    comentario = input("Comentario adicional (Opcional): ").strip()

    reporte = ReporteBache(calle, colonia, alcaldia, latitud, longitud, tamano, profundidad,
                           transporte_publico, frecuencia_transito, accidentes, zona_sensible,
                           comentario)
    bd.guardar_bache(reporte)

    print("\n--- Resumen del reporte ---")
    reporte.imprimir_en_consola()
    print("Reporte guardado correctamente en la base de datos.\n")


def ver_reportes_recientes(bd: BaseDatos, cantidad: int = 5):
    # Muestra los últimos 'cantidad' reportes registrados (el más nuevo primero)
    recientes = bd.recientes(cantidad)
    if not recientes:
        print("\nNo hay reportes registrados todavía.\n")
        return
    print(f"\n--- Últimos {len(recientes)} reporte(s) ---")
    for reporte in recientes:
        reporte.imprimir_en_consola()


def buscar_por_ubicacion_consola(bd: BaseDatos):
    # Busca reportes cuya ubicación contenga el texto ingresado (sin importar mayúsculas)
    if bd.contar_baches() == 0:
        print("\nNo hay reportes registrados todavía.\n")
        return
    texto = input("\nEscribe la ubicación (o parte de ella) a buscar: ").strip()
    if not texto:
        print("Debes escribir algo para buscar.\n")
        return
    coincidencias = bd.buscar_por_ubicacion(texto)
    if not coincidencias:
        print(f"No se encontraron reportes con la ubicación: '{texto}'\n")
        return
    print(f"\n--- {len(coincidencias)} coincidencia(s) encontrada(s) ---")
    for reporte in coincidencias:
        reporte.imprimir_en_consola()


def buscar_por_id_consola(bd: BaseDatos):
    # Busca un reporte específico por su ID
    if bd.contar_baches() == 0:
        print("\nNo hay reportes registrados todavía.\n")
        return
    id_buscado = pedir_id("\nEscribe el ID del reporte a buscar: ")
    if id_buscado is None:
        return
    reporte = bd.buscar_por_id(id_buscado)
    if reporte:
        print("\n--- Reporte encontrado ---")
        reporte.imprimir_en_consola()
    else:
        print(f"No se encontró ningún reporte con ID {id_buscado}.\n")


def mostrar_semaforo_prioridad(bd: BaseDatos, cantidad: int = 10):
    # Ranking de baches pendientes por IPU usando una cola de prioridad (max-heap)
    pendientes = bd.listar_pendientes()
    if not pendientes:
        print("\nNo hay reportes pendientes.\n")
        return

    conteo = {"Rojo": 0, "Amarillo": 0, "Verde": 0}
    for bache in pendientes:
        conteo[bache.color_semaforo()] += 1

    print("\n--- SEMÁFORO DE PRIORIDAD DE BACHEO ---")
    print(f"Pendientes: {len(pendientes)}  |  🔴 {conteo['Rojo']}  🟡 {conteo['Amarillo']}  🟢 {conteo['Verde']}")
    print("=" * 45)
    for posicion, bache in enumerate(ranking_por_prioridad(pendientes, cantidad), start=1):
        print(f"{posicion}. ID {bache.id_bache} | {bache.calle}, {bache.colonia} ({bache.alcaldia})")
        print(f"   IPU: {bache.calcular_ipu()}/100 {ETIQUETA_SEMAFORO[bache.color_semaforo()]} "
              f"| Prob. siniestro 72 h: {bache.probabilidad_siniestro_72h()}%")
        print(f"   Justificación: {bache.explicar_prioridad()}")
    print("=" * 45)
    print("Nota: el sistema sugiere; la decisión final es de la autoridad (supervisión humana).")


def estimar_degradacion_consola(bd: BaseDatos):
    # Cálculo integral: volumen de asfalto perdido y comparación preventivo vs correctivo
    id_bache = pedir_id("\nID del reporte a analizar: ")
    if id_bache is None:
        return
    reporte = bd.buscar_por_id(id_bache)
    if not reporte:
        print(f"No se encontró ningún reporte con ID {id_bache}.\n")
        return

    meses_texto = input("¿Cuántos meses se pospondría la intervención? (Enter = 6): ").strip()
    try:
        meses = float(meses_texto) if meses_texto else 6.0
        if meses <= 0 or math.isnan(meses):
            raise ValueError
    except ValueError:
        print("Debes escribir un número de meses mayor a 0.\n")
        return

    estimacion = reporte.comparar_preventivo_vs_correctivo(meses)
    print(f"\n--- Degradación del bache ID {reporte.id_bache} ({reporte.calle}, {reporte.colonia}) ---")
    print(f"Tasa de degradación: r(t) = "
          f"{TASA_DEGRADACION_BASE_M3_MES * reporte.factor_de_carga():.4f}"
          f"·(1 + {ACELERACION_DEGRADACION_POR_MES}·t)  m³/mes")
    print(f"Volumen perdido en {meses:g} meses: V = ∫ r(t) dt = {estimacion['volumen_perdido']:.4f} m³")
    print(f"Volumen actual del bache: {estimacion['volumen_actual']:.4f} m³")
    print("-" * 45)
    print("Estrategia A (preventivo, hoy):")
    print(f"  Superficie a reparar: {estimacion['area_preventivo']:.2f} m²  |  "
          f"Costo: {formato_dinero(estimacion['costo_preventivo'])}")
    print(f"Estrategia B (correctivo, en {meses:g} meses, bacheo profundo):")
    print(f"  Superficie a reparar: {estimacion['area_correctivo']:.2f} m²  |  "
          f"Costo: {formato_dinero(estimacion['costo_correctivo'])}")
    print("-" * 45)
    if estimacion["ahorro"] > 0:
        print(f"El mantenimiento preventivo ahorraría {formato_dinero(estimacion['ahorro'])} (estimación).")
    else:
        print(f"Esperar costaría {formato_dinero(-estimacion['ahorro'])} menos (estimación).")
    print(f"Precios: Tabulador General CDMX julio 2026 "
          f"(${PRECIO_M2_POR_PROFUNDIDAD['Superficial']}/m² y ${PRECIO_M2_POR_PROFUNDIDAD['Profundo']}/m²).")


def marcar_atendido_consola(bd: BaseDatos):
    # Marca un reporte como atendido para sacarlo del ranking de prioridades
    id_bache = pedir_id("\nID del reporte atendido: ")
    if id_bache is None:
        return
    if bd.marcar_atendido(id_bache):
        print(f"Reporte {id_bache} marcado como atendido.\n")
    else:
        print("No existe ese reporte o ya estaba atendido.\n")


def crear_administrador_consola(bd: BaseDatos):
    # Crea (o actualiza) una cuenta administrador sin guardar contraseñas en el código ni en el .sql
    print("\n--- Crear cuenta de administrador ---")
    nombre = pedir_texto("Nombre: ")
    correo = pedir_texto("Correo: ").lower()
    contrasena = getpass.getpass("Contraseña (no se muestra): ")
    if contrasena != getpass.getpass("Repite la contraseña: "):
        print("Las contraseñas no coinciden.\n")
        return
    try:
        if bd.buscar_usuario_por_correo(correo):
            if pedir_opcion("Ese correo ya existe. ¿Actualizar contraseña y dejarlo como administrador? (Si/No): ",
                            SI_NO) == "No":
                return
            validar_datos_de_cuenta(nombre, correo, contrasena)
            bd.actualizar_credenciales(
                correo, generate_password_hash(contrasena, method="pbkdf2:sha256"), "administrador")
        else:
            registrar_usuario(bd, nombre, correo, contrasena, rol="administrador")
    except ValueError as error:
        print(f"No se pudo crear la cuenta: {error}\n")
        return
    print(f"Listo: {correo} ya puede entrar como administrador.\n")


def mostrar_menu():
    print("=" * 45)
    print("   SISTEMA DE REPORTE DE BACHES - CDMX")
    print("   Encargado: Daniel Santana Carbajal")
    print("=" * 45)
    print("1. Realizar un reporte")
    print("2. Ver reportes recientes")
    print("3. Buscar reportes por ubicación")
    print("4. Buscar reporte por ID")
    print("5. Semáforo de prioridad")
    print("6. Estimar degradación y costo")
    print("7. Marcar reporte como atendido")
    print("8. Salir")
    print("=" * 45)


def conectar_o_avisar():
    # Devuelve una Base de Datos conectada o None (explicando al administrador qué revisar)
    bd = BaseDatos()
    try:
        bd.conectar()
        return bd
    except Error as error:
        print(f"No se pudo conectar a MySQL: {error}")
        if error.errno == errorcode.ER_BAD_DB_ERROR:
            print("La base de datos no existe todavía: ejecuta primero base_de_datos.sql.")
        else:
            print("Revisa que MySQL esté encendido y las variables DB_HOST, DB_USER, DB_PASSWORD (archivo .env).")
        return None


def main():
    bd = conectar_o_avisar()
    if bd is None:
        return

    if len(sys.argv) > 1 and sys.argv[1] == "crear-admin":
        try:
            crear_administrador_consola(bd)
        finally:
            bd.cerrar()
        return

    limpiar_pantalla()
    acciones = {
        "1": crear_reporte_consola,
        "2": ver_reportes_recientes,
        "3": buscar_por_ubicacion_consola,
        "4": buscar_por_id_consola,
        "5": mostrar_semaforo_prioridad,
        "6": estimar_degradacion_consola,
        "7": marcar_atendido_consola,
    }

    try:
        while True:
            limpiar_pantalla()
            mostrar_menu()
            opcion = input("Elige una opción (1-8): ").strip()
            limpiar_pantalla()

            if opcion == "8":
                print("\nSaliendo del sistema. ¡Hasta luego!")
                break
            elif opcion in acciones:
                try:
                    acciones[opcion](bd)
                except Error as error:
                    print(f"\nError de base de datos: {error}\n")
                pausar()
            else:
                print("\nOpción no válida, intenta de nuevo.\n")
                pausar()
    finally:
        bd.cerrar()


if __name__ == "__main__":
    main()
