import os
import base64
import secrets
import resend
from datetime import datetime, timedelta
from typing import List, Optional

import psycopg2
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field, field_validator

from core import (
    TIPOS_SOLICITUD,
    ESTADOS,
    PRIORIDADES,
    obtener_conexion,
    insertar_solicitud,
    clasificar,
    hash_password,
    verify_password,
    guardar_token_verificacion,
    verificar_token_email,
    guardar_token_reset,
    validar_token_reset,
    actualizar_password,
)

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "ginganguliguliguliwachagingangugingangu")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
resend.api_key = os.environ.get("RESEND_API_KEY")

app = FastAPI(title="Clasificador IA")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UserRegister(BaseModel):
    correo: EmailStr
    nombre_completo: str
    contrasena: str = Field(min_length=8)
    cedula: Optional[str] = None
    telefono: Optional[str] = None

    @field_validator("cedula")
    @classmethod
    def clean_cedula(cls, v):
        if v is not None:
            v = v.replace("-", "").strip()
            if len(v) > 11:
                raise ValueError("Cédula inválida")
        return v

    @field_validator("telefono")
    @classmethod
    def clean_telefono(cls, v):
        if v is not None:
            v = v.replace("-", "").strip()
            if len(v) > 20:
                raise ValueError("Teléfono inválido")
        return v

class UserLogin(BaseModel):
    correo: EmailStr
    contrasena: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    nueva_password: str = Field(min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AnexoUpload(BaseModel):
    nombre_archivo: str
    archivo_base64: str


class SolicitudCreate(BaseModel):
    titulo: str
    descripcion: str
    anexos: Optional[List[AnexoUpload]] = None


class SolicitudSummary(BaseModel):
    id_solicitud: int
    tipo_solicitud: str
    titulo: str
    estado: str
    prioridad: str
    fecha_creacion: datetime


class SolicitudDetail(SolicitudSummary):
    id_usuario: int
    descripcion: str
    fecha_resolucion: Optional[datetime] = None


class AnexoSummary(BaseModel):
    id_anexo: int
    nombre_archivo: str
    fecha_subida: datetime


class UsuarioSummary(BaseModel):
    id_usuario: int
    correo: EmailStr
    cedula: Optional[str] = None
    nombre_completo: str
    telefono: Optional[str] = None
    es_admin: bool
    activo: bool


class UsuarioUpdate(BaseModel):
    es_admin: bool
    activo: bool


class UsuarioSelfUpdate(BaseModel):
    nombre_completo: Optional[str] = None
    telefono: Optional[str] = None
    correo: Optional[EmailStr] = None
    cedula: Optional[str] = None
    contrasena: Optional[str] = Field(None, min_length=8)


class TokenData(BaseModel):
    id_usuario: int
    es_admin: bool


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id_usuario = payload.get("id_usuario")
        es_admin = payload.get("es_admin")
        if id_usuario is None or es_admin is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
        return TokenData(id_usuario=id_usuario, es_admin=es_admin)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")


def get_current_user(request: Request) -> TokenData:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Cabecera de autorización faltante")
    token = auth_header.split(" ", 1)[1].strip()
    return decode_token(token)


def get_current_admin(current_user: TokenData = Depends(get_current_user)) -> TokenData:
    if not current_user.es_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permiso de administrador requerido")
    return current_user


@app.post("/auth/registro", response_model=UsuarioSummary)
def register_user(user: UserRegister):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id_usuario FROM usuarios WHERE correo = %s OR (cedula IS NOT NULL AND cedula = %s)",
                    (user.correo, user.cedula),
                )
                if cur.fetchone():
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Correo o cédula ya registrados")

                hashed_password = hash_password(user.contrasena)
                cur.execute(
                    "INSERT INTO usuarios (correo, cedula, nombre_completo, telefono, contrasena, es_admin, activo) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id_usuario, correo, cedula, nombre_completo, telefono, es_admin, activo",
                    (user.correo, user.cedula, user.nombre_completo, user.telefono, hashed_password, False, True),
                )
                row = cur.fetchone()
                usuario_res = UsuarioSummary(**dict(zip([desc[0] for desc in cur.description], row)))
    finally:
        conn.close()

    # Generate token and save
    token = secrets.token_urlsafe(32)
    guardar_token_verificacion(usuario_res.id_usuario, token)

    # Send email
    verification_link = f"https://clasificadoria.ddns.net/verify?token={token}"
    try:
        resend.Emails.send({
            "from": "onboarding@resend.dev",
            "to": user.correo,
            "subject": "Verifica tu correo electrónico",
            "html": f"<p>Hola {user.nombre_completo},</p><p>Por favor verifica tu correo haciendo clic en el siguiente enlace:</p><p><a href='{verification_link}'>Verificar correo</a></p>"
        })
    except Exception as e:
        print(f"Error enviando correo de verificación: {e}")

    return usuario_res


@app.post("/auth/login", response_model=TokenResponse)
def login_user(user: UserLogin):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id_usuario, contrasena, es_admin, activo, verificado FROM usuarios WHERE correo = %s", (user.correo,))
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Correo o contraseña incorrectos")
                id_usuario, hashed, es_admin, activo, verificado = row
                if not activo:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario inactivo")
                if not verificado:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Debes verificar tu correo antes de iniciar sesión.")
                if not verify_password(user.contrasena, hashed):
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Correo o contraseña incorrectos")

                token = create_access_token({"id_usuario": id_usuario, "es_admin": es_admin})
                return TokenResponse(access_token=token)
    finally:
        conn.close()


@app.get("/verify")
def verify_email(token: str):
    id_usuario = verificar_token_email(token)
    if not id_usuario:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token inválido o expirado")
    return {"message": "Correo verificado exitosamente"}


@app.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id_usuario, nombre_completo FROM usuarios WHERE correo = %s", (payload.email,))
                row = cur.fetchone()
                if not row:
                    # Return success even if not found to prevent email enumeration
                    return {"message": "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña."}
                id_usuario, nombre_completo = row
    finally:
        conn.close()

    token = secrets.token_urlsafe(32)
    expira = datetime.utcnow() + timedelta(hours=1)
    guardar_token_reset(id_usuario, token, expira)

    reset_link = f"https://clasificadoria.ddns.net/reset-password?token={token}"
    try:
        resend.Emails.send({
            "from": "onboarding@resend.dev",
            "to": payload.email,
            "subject": "Restablecer contraseña",
            "html": f"<p>Hola {nombre_completo},</p><p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace (válido por 1 hora):</p><p><a href='{reset_link}'>Restablecer contraseña</a></p>"
        })
    except Exception as e:
        print(f"Error enviando correo de restablecimiento: {e}")

    return {"message": "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña."}


@app.post("/reset-password")
def reset_password(payload: ResetPasswordRequest):
    id_usuario = validar_token_reset(payload.token)
    if not id_usuario:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token inválido o expirado")
    
    nuevo_hash = hash_password(payload.nueva_password)
    actualizar_password(id_usuario, nuevo_hash)
    
    return {"message": "Contraseña actualizada exitosamente"}


@app.post("/solicitudes", response_model=SolicitudSummary)
def create_solicitud(solicitud: SolicitudCreate, current_user: TokenData = Depends(get_current_user)):
    anexos = []
    if solicitud.anexos:
        for item in solicitud.anexos:
            try:
                contenido = base64.b64decode(item.archivo_base64)
            except Exception as exc:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Anexo inválido {item.nombre_archivo}") from exc
            anexos.append((contenido, item.nombre_archivo))

    tipo_solicitud, prioridad = clasificar(solicitud.titulo, solicitud.descripcion)
    id_solicitud = insertar_solicitud(
        tipo_solicitud,
        solicitud.titulo,
        solicitud.descripcion,
        prioridad,
        anexos_lista=anexos,
        id_usuario=current_user.id_usuario,
    )

    return SolicitudSummary(
        id_solicitud=id_solicitud,
        tipo_solicitud=tipo_solicitud,
        titulo=solicitud.titulo,
        estado="Pendiente",
        prioridad=prioridad,
        fecha_creacion=datetime.utcnow(),
    )


@app.get("/solicitudes/mis-solicitudes", response_model=List[SolicitudSummary])
def get_my_solicitudes(current_user: TokenData = Depends(get_current_user)):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id_solicitud, tipo_solicitud, titulo, estado, prioridad, fecha_creacion "
                    "FROM solicitudes WHERE id_usuario = %s ORDER BY fecha_creacion DESC",
                    (current_user.id_usuario,),
                )
                rows = cur.fetchall()
                return [SolicitudSummary(**dict(zip([desc[0] for desc in cur.description], row))) for row in rows]
    finally:
        conn.close()


@app.get("/solicitudes/{id_solicitud}", response_model=SolicitudDetail)
def get_solicitud(id_solicitud: int, current_user: TokenData = Depends(get_current_user)):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                if current_user.es_admin:
                    cur.execute(
                        "SELECT id_solicitud, id_usuario, tipo_solicitud, titulo, descripcion, fecha_creacion, estado, prioridad, fecha_resolucion "
                        "FROM solicitudes WHERE id_solicitud = %s",
                        (id_solicitud,),
                    )
                else:
                    cur.execute(
                        "SELECT id_solicitud, id_usuario, tipo_solicitud, titulo, descripcion, fecha_creacion, estado, prioridad, fecha_resolucion "
                        "FROM solicitudes WHERE id_solicitud = %s AND id_usuario = %s",
                        (id_solicitud, current_user.id_usuario),
                    )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Solicitud no encontrada")
                return SolicitudDetail(**dict(zip([desc[0] for desc in cur.description], row)))
    finally:
        conn.close()


@app.get("/admin/solicitudes", response_model=List[SolicitudSummary])
def admin_list_solicitudes(
    tipo: Optional[str] = None,
    estado: Optional[str] = None,
    prioridad: Optional[str] = None,
    current_user: TokenData = Depends(get_current_admin),
):
    query = "SELECT id_solicitud, tipo_solicitud, titulo, estado, prioridad, fecha_creacion FROM solicitudes"
    params = []
    filters = []
    if tipo:
        if tipo not in TIPOS_SOLICITUD:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tipo inválido")
        filters.append("tipo_solicitud = %s")
        params.append(tipo)
    if estado:
        if estado not in ESTADOS:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Estado inválido")
        filters.append("estado = %s")
        params.append(estado)
    if prioridad:
        if prioridad not in PRIORIDADES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Prioridad inválida")
        filters.append("prioridad = %s")
        params.append(prioridad)
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY fecha_creacion DESC"

    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
                return [SolicitudSummary(**dict(zip([desc[0] for desc in cur.description], row))) for row in rows]
    finally:
        conn.close()


class EstadoUpdate(BaseModel):
    estado: str


@app.put("/admin/solicitudes/{id_solicitud}/estado", response_model=SolicitudDetail)
def admin_update_estado(
    id_solicitud: int,
    payload: EstadoUpdate,
    current_user: TokenData = Depends(get_current_admin),
):
    if payload.estado not in ESTADOS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Estado inválido")
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                fecha_resolucion = datetime.utcnow() if payload.estado == "Resuelta" else None
                cur.execute(
                    "UPDATE solicitudes SET estado = %s, fecha_resolucion = %s WHERE id_solicitud = %s RETURNING "
                    "id_solicitud, id_usuario, tipo_solicitud, titulo, descripcion, fecha_creacion, estado, prioridad, fecha_resolucion",
                    (payload.estado, fecha_resolucion, id_solicitud),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Solicitud no encontrada")
                return SolicitudDetail(**dict(zip([desc[0] for desc in cur.description], row)))
    finally:
        conn.close()


@app.get("/admin/solicitudes/{id_solicitud}/anexos", response_model=List[AnexoSummary])
def admin_list_anexos(id_solicitud: int, current_user: TokenData = Depends(get_current_admin)):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id_anexo, nombre_archivo, fecha_subida FROM anexos WHERE id_solicitud = %s ORDER BY fecha_subida DESC",
                    (id_solicitud,),
                )
                rows = cur.fetchall()
                return [AnexoSummary(**dict(zip([desc[0] for desc in cur.description], row))) for row in rows]
    finally:
        conn.close()


@app.get("/admin/anexos/{id_anexo}/descargar")
def admin_download_anexo(id_anexo: int, current_user: TokenData = Depends(get_current_admin)):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT nombre_archivo, archivo FROM anexos WHERE id_anexo = %s",
                    (id_anexo,),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anexo no encontrado")
                nombre_archivo, archivo = row
                if archivo is None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contenido de anexo no disponible")
                if isinstance(archivo, memoryview):
                    archivo = bytes(archivo)
                return Response(
                    content=archivo,
                    media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{nombre_archivo}"'},
                )
    finally:
        conn.close()


@app.get("/admin/usuarios", response_model=List[UsuarioSummary])
def admin_list_usuarios(current_user: TokenData = Depends(get_current_admin)):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id_usuario, correo, cedula, nombre_completo, telefono, es_admin, activo FROM usuarios ORDER BY id_usuario"
                )
                rows = cur.fetchall()
                return [UsuarioSummary(**dict(zip([desc[0] for desc in cur.description], row))) for row in rows]
    finally:
        conn.close()


@app.put("/admin/usuarios/{id_usuario}", response_model=UsuarioSummary)
def admin_update_usuario(
    id_usuario: int,
    payload: UsuarioUpdate,
    current_user: TokenData = Depends(get_current_admin),
):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE usuarios SET activo = %s, es_admin = %s WHERE id_usuario = %s RETURNING "
                    "id_usuario, correo, cedula, nombre_completo, telefono, es_admin, activo",
                    (payload.activo, payload.es_admin, id_usuario),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
                return UsuarioSummary(**dict(zip([desc[0] for desc in cur.description], row)))
    finally:
        conn.close()


@app.get("/usuario/perfil", response_model=UsuarioSummary)
def get_usuario_perfil(current_user: TokenData = Depends(get_current_user)):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id_usuario, correo, cedula, nombre_completo, telefono, es_admin, activo "
                    "FROM usuarios WHERE id_usuario = %s",
                    (current_user.id_usuario,),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
                return UsuarioSummary(**dict(zip([desc[0] for desc in cur.description], row)))
    finally:
        conn.close()


@app.put("/usuario/perfil", response_model=UsuarioSummary)
def update_usuario_perfil(payload: UsuarioSelfUpdate, current_user: TokenData = Depends(get_current_user)):
    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                updates = []
                params = []

                if payload.nombre_completo is not None:
                    updates.append("nombre_completo = %s")
                    params.append(payload.nombre_completo)

                if payload.telefono is not None:
                    updates.append("telefono = %s")
                    params.append(payload.telefono)

                if payload.correo is not None:
                    updates.append("correo = %s")
                    params.append(payload.correo)

                if payload.cedula is not None:
                    cedula_clean = "".join(payload.cedula.split()).replace("-", "")
                    if len(cedula_clean) > 11:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="La cédula no puede superar los 11 caracteres sin guiones ni espacios."
                        )
                    updates.append("cedula = %s")
                    params.append(cedula_clean)

                if payload.contrasena is not None:
                    if len(payload.contrasena) < 8:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="La contraseña debe tener al menos 8 caracteres."
                        )
                    hashed = hash_password(payload.contrasena)
                    updates.append("contrasena = %s")
                    params.append(hashed)

                if updates:
                    query = (
                        f"UPDATE usuarios SET {', '.join(updates)} WHERE id_usuario = %s "
                        "RETURNING id_usuario, correo, cedula, nombre_completo, telefono, es_admin, activo"
                    )
                    params.append(current_user.id_usuario)
                    try:
                        cur.execute(query, params)
                        row = cur.fetchone()
                    except psycopg2.IntegrityError:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="El correo o la cédula ya están registrados por otro usuario."
                        )
                else:
                    cur.execute(
                        "SELECT id_usuario, correo, cedula, nombre_completo, telefono, es_admin, activo "
                        "FROM usuarios WHERE id_usuario = %s",
                        (current_user.id_usuario,),
                    )
                    row = cur.fetchone()

                if not row:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
                return UsuarioSummary(**dict(zip([desc[0] for desc in cur.description], row)))
    finally:
        conn.close()


