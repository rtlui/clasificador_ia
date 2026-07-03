import os
import json
import bcrypt
import psycopg2
from datetime import datetime
from psycopg2 import sql
from google import genai
from google.genai import types

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "port": int(os.environ.get("DB_PORT", "5432")),
    "dbname": os.environ.get("DB_NAME", "clasificador_ia"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", "postgres"),
}

TIPOS_SOLICITUD = ["Peticion", "Queja", "Sugerencia", "Reclamo", "Denuncia"]
ESTADOS = ["Pendiente", "Progreso", "Resuelta"]
PRIORIDADES = ["Alta", "Media", "Baja"]


def obtener_conexion():
    return psycopg2.connect(**DB_CONFIG)


def insertar_solicitud(tipo_solicitud, titulo, descripcion, prioridad, anexos_lista=None, id_usuario=None):
    if id_usuario is None:
        raise ValueError("id_usuario es requerido para crear una solicitud")

    if tipo_solicitud not in TIPOS_SOLICITUD:
        raise ValueError(f"Tipo de solicitud inválido: {tipo_solicitud}")
    if prioridad not in PRIORIDADES:
        raise ValueError(f"Prioridad inválida: {prioridad}")

    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                query = sql.SQL(
                    "INSERT INTO solicitudes (tipo_solicitud, titulo, descripcion, estado, prioridad, id_usuario) "
                    "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id_solicitud"
                )
                cur.execute(query, (tipo_solicitud, titulo, descripcion, "Pendiente", prioridad, id_usuario))
                id_solicitud = cur.fetchone()[0]

                if anexos_lista:
                    for anexo_contenido, anexo_nombre in anexos_lista:
                        if anexo_contenido is None or not anexo_nombre:
                            continue
                        query_anexo = sql.SQL(
                            "INSERT INTO anexos (id_solicitud, nombre_archivo, archivo) "
                            "VALUES (%s, %s, %s)"
                        )
                        cur.execute(query_anexo, (id_solicitud, anexo_nombre, anexo_contenido))
        return id_solicitud
    finally:
        conn.close()


def construir_prompt(titulo, descripcion):
    return (
        "Clasifica la siguiente solicitud ciudadana de acuerdo a estos criterios:\n\n"
        "TIPO DE SOLICITUD (elige exactamente uno):\n"
        "- Peticiones: el ciudadano solicita un servicio, obra o acción que aún no existe en su comunidad.\n"
        "- Quejas: el ciudadano expresa insatisfacción porque un servicio existente funciona mal o fue interrumpido.\n"
        "- Sugerencias: el ciudadano propone una mejora o idea para el sector público.\n"
        "- Reclamos: el ciudadano exige un derecho o compensación que considera vulnerado, generalmente de forma personal.\n"
        "- Denuncias: el ciudadano reporta una irregularidad, acto ilícito o conducta indebida de un tercero.\n\n"
        "PRIORIDAD (elige exactamente una):\n"
        "- Alta: afecta la salud, seguridad, o derechos fundamentales de personas; requiere atención inmediata.\n"
        "- Media: afecta la calidad de vida o servicios básicos, pero no representa un riesgo inmediato.\n"
        "- Baja: es una mejora deseable pero no urgente; puede atenderse a mediano o largo plazo.\n\n"
        "Responde ÚNICAMENTE con un JSON válido (sin bloques de código) con esta estructura exacta (el tipo tiene que estar en singular ej. Peticiones = Peticion):\n"
        "{\"tipo\": \"NombreTipo\", \"prioridad\": \"NombrePrioridad\"}\n\n"
        f"Título: {titulo}\n"
        f"Descripción: {descripcion}\n"
    )


def extraer_clasificacion(response):
    try:
        text = response.text
    except Exception as exc:
        raise ValueError("Error extrayendo texto. Posible bloqueo de seguridad.") from exc

    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Respuesta no es JSON válido: {text}. Error: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"JSON debe ser un objeto, recibido: {type(data).__name__}")

    if "tipo" not in data or "prioridad" not in data:
        raise ValueError(f"JSON debe contener campos 'tipo' y 'prioridad'. Recibido: {data}")

    tipo = str(data["tipo"]).capitalize()
    prioridad = str(data["prioridad"]).capitalize()

    if tipo not in TIPOS_SOLICITUD:
        raise ValueError(f"Tipo inválido: {tipo}. Válidos: {TIPOS_SOLICITUD}")
    if prioridad not in PRIORIDADES:
        raise ValueError(f"Prioridad inválida: {prioridad}. Válidas: {PRIORIDADES}")

    return tipo, prioridad


def clasificar(titulo, descripcion):
    if not os.environ.get("GEMINI_API_KEY"):
        raise RuntimeError("Necesitas configurar GEMINI_API_KEY como variable de entorno.")

    client = genai.Client()
    prompt_text = construir_prompt(titulo, descripcion)
    print("Enviando texto para clasificación a Gemini 3.1 Flash-Lite...")
    response = client.models.generate_content(
        model="gemini-3.1-flash-lite",
        contents=prompt_text,
        config=types.GenerateContentConfig(temperature=0.0),
    )

    tipo_solicitud, prioridad = extraer_clasificacion(response)
    print(f"Resultado de clasificación: Tipo={tipo_solicitud}, Prioridad={prioridad}")
    return tipo_solicitud, prioridad


def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def guardar_token_verificacion(id_usuario, token):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE usuarios SET token_verificacion = %s WHERE id_usuario = %s",
                    (token, id_usuario)
                )
    finally:
        conn.close()


def verificar_token_email(token):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE usuarios SET verificado = TRUE, token_verificacion = NULL "
                    "WHERE token_verificacion = %s RETURNING id_usuario",
                    (token,)
                )
                row = cur.fetchone()
                return row[0] if row else None
    finally:
        conn.close()


def guardar_token_reset(id_usuario, token, expira):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE usuarios SET token_reset = %s, token_reset_expira = %s WHERE id_usuario = %s",
                    (token, expira, id_usuario)
                )
    finally:
        conn.close()


def validar_token_reset(token):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id_usuario FROM usuarios WHERE token_reset = %s AND token_reset_expira > %s",
                    (token, datetime.utcnow())
                )
                row = cur.fetchone()
                return row[0] if row else None
    finally:
        conn.close()


def actualizar_password(id_usuario, nuevo_hash):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE usuarios SET contrasena = %s, token_reset = NULL, token_reset_expira = NULL WHERE id_usuario = %s",
                    (nuevo_hash, id_usuario)
                )
    finally:
        conn.close()

