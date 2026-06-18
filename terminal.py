import os
import psycopg2
from core import (
    DB_CONFIG,
    TIPOS_SOLICITUD,
    ESTADOS,
    PRIORIDADES,
    hash_password,
    verify_password,
    obtener_conexion,
    insertar_solicitud,
    clasificar,
)

current_user = None


def registrar_usuario_flow():
    print("--- Registro de nuevo usuario ---")
    correo = solicitar_texto("Correo: ")
    nombre_completo = solicitar_texto("Nombre completo: ")
    cedula = input("Cédula (11 dígitos, opcional): ").strip()
    if cedula and (not cedula.isdigit() or len(cedula) != 11):
        print("Cédula inválida. Debe contener exactamente 11 dígitos numéricos.")
        return
    telefono = input("Teléfono (opcional): ").strip()
    password = input("Contraseña: ")
    password2 = input("Confirmar contraseña: ")
    if password != password2:
        print("Las contraseñas no coinciden.")
        return

    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                if cedula:
                    cur.execute(
                        "SELECT id_usuario FROM usuarios WHERE correo = %s OR cedula = %s",
                        (correo, cedula),
                    )
                else:
                    cur.execute("SELECT id_usuario FROM usuarios WHERE correo = %s", (correo,))

                if cur.fetchone():
                    print("Ya existe un usuario con ese correo o cédula.")
                    return

                hashed = hash_password(password)
                cur.execute(
                    "INSERT INTO usuarios (correo, cedula, nombre_completo, telefono, contrasena, es_admin, activo) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id_usuario",
                    (correo, cedula or None, nombre_completo, telefono or None, hashed, False, True),
                )
                new_id = cur.fetchone()[0]
                print(f"Usuario creado con id: {new_id}")
    except psycopg2.Error as e:
        print(f"Error en base de datos durante registro: {e.pgerror if hasattr(e, 'pgerror') else str(e)}")
    finally:
        conn.close()


def login_flow():
    global current_user
    print("--- Iniciar sesión ---")
    while True:
        choice = input("(l) Iniciar sesión, (r) Registrarse, (q) Salir: ").strip().lower()
        if choice == 'q':
            return False
        if choice == 'r':
            registrar_usuario_flow()
            continue
        if choice != 'l':
            print("Opción inválida.")
            continue

        identificador = input("Cédula o correo: ").strip()
        password = input("Contraseña: ")

        conn = obtener_conexion()
        try:
            with conn:
                with conn.cursor() as cur:
                    if "@" in identificador:
                        cur.execute(
                            "SELECT id_usuario, contrasena, es_admin, activo FROM usuarios WHERE correo = %s",
                            (identificador,),
                        )
                    else:
                        cur.execute(
                            "SELECT id_usuario, contrasena, es_admin, activo FROM usuarios WHERE cedula = %s",
                            (identificador,),
                        )

                    row = cur.fetchone()
                    if not row:
                        print("Usuario no encontrado.")
                        continue
                    id_usuario, hashed, es_admin, activo = row
                    if not activo:
                        print("Usuario inactivo. Contacta al administrador.")
                        continue
                    if not verify_password(password, hashed):
                        print("Contraseña incorrecta.")
                        continue

                    current_user = {"id_usuario": id_usuario, "identificador": identificador, "es_admin": es_admin}
                    print(f"Bienvenido {identificador}!")
                    return True
        except psycopg2.Error as e:
            print(f"Error en base de datos durante login: {e.pgerror if hasattr(e, 'pgerror') else str(e)}")
        finally:
            conn.close()


def solicitar_texto(prompt_text, required=True):
    while True:
        value = input(prompt_text).strip()
        if value or not required:
            return value
        print("Este campo es obligatorio. Por favor ingresa un valor.")


def solicitar_anexos(prompt_text):
    anexos_lista = []
    while True:
        anexos_input = input(prompt_text).strip()
        if not anexos_input:
            if anexos_lista:
                print(f"Se proporcionaron {len(anexos_lista)} anexo(s)")
            else:
                print("No se proporcionaron anexos")
            return anexos_lista if anexos_lista else None

        if anexos_input.startswith("@"):
            path = anexos_input[1:]
            if os.path.isfile(path):
                filename = os.path.basename(path)
                print(f"Leyendo archivo de anexos desde: {path}")
                with open(path, "rb") as file:
                    anexos_lista.append((file.read(), filename))
                print(f"Archivo agregado. Total: {len(anexos_lista)}")
                prompt_text = "Más anexos (@ruta/al/archivo, deja vacío para terminar): "
                continue
            print(f"No se encontró el archivo: {path}. Intenta de nuevo o deja vacío si no aplica.")
            continue
        print("Anexos solo puede ser un archivo especificado con @ruta/al/archivo, o dejar vacío.")


def ejecutar_app():
    print("Conectando a la base de datos clasificador_ia en localhost...")
    titulo = solicitar_texto("Título: ")
    descripcion = solicitar_texto("Descripción: ")
    anexos_lista = solicitar_anexos("Anexos (@ruta/al/archivo, deja vacío si no aplica): ")
    tipo_solicitud, prioridad = clasificar(titulo, descripcion)
    if not current_user:
        raise RuntimeError("Usuario no autenticado. Inicia sesión antes de crear solicitudes.")

    id_solicitud = insertar_solicitud(
        tipo_solicitud,
        titulo,
        descripcion,
        prioridad,
        anexos_lista,
        id_usuario=current_user['id_usuario'],
    )
    print(f"Solicitud insertada con ID: {id_solicitud}, Tipo: {tipo_solicitud}, Prioridad: {prioridad}")


def format_cell(val):
    if val is None:
        return ""
    if isinstance(val, (bytes, bytearray, memoryview)):
        try:
            length = len(val)
        except Exception:
            length = 0
        return f"<BINARY {length} bytes>"
    return str(val)


def clear_terminal():
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass


def obtener_ruta_descarga():
    if "CLASIFICADOR_DOWNLOAD_DIR" in os.environ:
        return os.environ["CLASIFICADOR_DOWNLOAD_DIR"]

    default_dir = os.path.join(os.path.dirname(__file__), "descargas")
    print(f"Ruta de descarga por defecto: {default_dir}")
    custom = input("¿Deseas usar una ruta diferente? (deja vacío para usar default): ").strip()
    if custom:
        if os.path.isdir(custom):
            return custom
        print(f"Directorio no existe: {custom}. Usando default.")
    return default_dir


def generar_nombre_unico(directorio, nombre_archivo):
    ruta_completa = os.path.join(directorio, nombre_archivo)
    if not os.path.exists(ruta_completa):
        return nombre_archivo

    nombre_base, extension = os.path.splitext(nombre_archivo)
    contador = 1
    while True:
        nuevo_nombre = f"{nombre_base}_{contador}{extension}"
        ruta_nueva = os.path.join(directorio, nuevo_nombre)
        if not os.path.exists(ruta_nueva):
            return nuevo_nombre
        contador += 1


def ver_tabla():
    print("Opciones de visualización:")
    print("1. Ver todas las solicitudes")
    print("2. Filtrar por tipo de solicitud")
    print("3. Filtrar por estado")
    print("q. Salir")

    choice = input("Selecciona una opción (o 'q' para salir): ").strip().lower()
    if not choice or choice == "q":
        return

    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                query = "SELECT * FROM solicitudes"
                params = []
                if choice == "1":
                    pass
                elif choice == "2":
                    print("\nTipos disponibles:")
                    for i, t in enumerate(TIPOS_SOLICITUD, start=1):
                        print(f"{i}. {t}")
                    tipo_choice = input("Selecciona un tipo (o 'q' para salir): ").strip()
                    if tipo_choice.lower() == "q":
                        return
                    if tipo_choice.isdigit():
                        idx = int(tipo_choice) - 1
                        if 0 <= idx < len(TIPOS_SOLICITUD):
                            tipo = TIPOS_SOLICITUD[idx]
                        else:
                            print("Selección inválida.")
                            return
                    else:
                        tipo = tipo_choice.capitalize()
                    if tipo not in TIPOS_SOLICITUD:
                        print("Tipo inválido.")
                        return
                    query += " WHERE tipo_solicitud = %s"
                    params.append(tipo)
                elif choice == "3":
                    print("\nEstados disponibles:")
                    for i, e in enumerate(ESTADOS, start=1):
                        print(f"{i}. {e}")
                    estado_choice = input("Selecciona un estado (o 'q' para salir): ").strip()
                    if estado_choice.lower() == "q":
                        return
                    if estado_choice.isdigit():
                        idx = int(estado_choice) - 1
                        if 0 <= idx < len(ESTADOS):
                            estado = ESTADOS[idx]
                        else:
                            print("Selección inválida.")
                            return
                    else:
                        estado = estado_choice.capitalize()
                    if estado not in ESTADOS:
                        print("Estado inválido.")
                        return
                    query += " WHERE estado = %s"
                    params.append(estado)
                else:
                    print("Opción inválida.")
                    return

                limit_input = input("Número de filas a mostrar (enter=100, 'all'=todas): ").strip()
                if limit_input.lower() == "all":
                    pass
                elif limit_input.isdigit():
                    query += " LIMIT %s"
                    params.append(int(limit_input))
                else:
                    query += " LIMIT %s"
                    params.append(100)

                cur.execute(query, params)
                rows = cur.fetchall()
                colnames = [desc[0] for desc in cur.description]

                str_rows = []
                col_widths = [len(c) for c in colnames]
                for r in rows:
                    formatted = []
                    for i, v in enumerate(r):
                        s = format_cell(v)
                        formatted.append(s)
                        if len(s) > col_widths[i]:
                            col_widths[i] = len(s)
                    str_rows.append(formatted)

                clear_terminal()
                print("Tabla: solicitudes\n")
                header = " | ".join(c.ljust(col_widths[i]) for i, c in enumerate(colnames))
                sep = "-+-".join("-" * col_widths[i] for i in range(len(colnames)))
                print(header)
                print(sep)
                for fr in str_rows:
                    print(" | ".join(fr[i].ljust(col_widths[i]) for i in range(len(fr))))

                print(f"\nMostradas {len(rows)} filas de la tabla solicitudes.")
                input("\nPresiona Enter para volver al menú...")
                clear_terminal()
    except psycopg2.Error as e:
        print(f"Error en base de datos: {e.pgerror if hasattr(e, 'pgerror') else str(e)}")
    finally:
        conn.close()


def descargar_anexo():
    print("Descargar anexos")
    id_solicitud_input = input("Ingresa el ID de la solicitud: ").strip()
    if not id_solicitud_input or not id_solicitud_input.isdigit():
        print("ID inválido.")
        return
    id_solicitud = int(id_solicitud_input)
    download_dir = obtener_ruta_descarga()
    try:
        os.makedirs(download_dir, exist_ok=True)
    except Exception as e:
        print(f"Error creando directorio: {e}")
        return

    conn = obtener_conexion()
    try:
        with conn:
            with conn.cursor() as cur:
                query = "SELECT id_anexo, nombre_archivo, archivo FROM anexos WHERE id_solicitud = %s"
                cur.execute(query, (id_solicitud,))
                anexos = cur.fetchall()
                if not anexos:
                    print("No hay anexos para esta solicitud.")
                    return

                print(f"\nAnexos disponibles para solicitud {id_solicitud}:")
                for i, (id_anexo, nombre_archivo, _) in enumerate(anexos, start=1):
                    print(f"{i}. {nombre_archivo} (ID: {id_anexo})")

                choice = input("Selecciona el número del anexo a descargar (o 'q' para salir): ").strip()
                if choice.lower() == "q":
                    return
                if not choice.isdigit():
                    print("Selección inválida.")
                    return

                idx = int(choice) - 1
                if idx < 0 or idx >= len(anexos):
                    print("Selección inválida.")
                    return

                id_anexo, nombre_archivo, archivo = anexos[idx]
                if archivo is None:
                    print("El anexo no tiene datos.")
                    return

                if isinstance(archivo, memoryview):
                    archivo_bytes = bytes(archivo)
                elif isinstance(archivo, bytearray):
                    archivo_bytes = bytes(archivo)
                else:
                    archivo_bytes = archivo

                nombre_seguro = generar_nombre_unico(download_dir, nombre_archivo)
                if nombre_seguro != nombre_archivo:
                    print(f"Archivo '{nombre_archivo}' ya existe. Se guardará como '{nombre_seguro}'")
                out_path = os.path.join(download_dir, nombre_seguro)
                try:
                    with open(out_path, "wb") as f:
                        f.write(archivo_bytes)
                    print(f"Anexo guardado en: {out_path}")
                except Exception as e:
                    print(f"Error guardando archivo: {e}")
    except psycopg2.Error as e:
        print(f"Error en base de datos: {e.pgerror if hasattr(e, 'pgerror') else str(e)}")
    finally:
        conn.close()


def mostrar_menu():
    while True:
        print("\n=== Menú principal ===")
        print("1) Data Entry (ingresar datos)")
        print("2) See Tables (ver tablas)")
        print("3) Get Files (descargar anexos)")
        print("q) Salir")
        opt = input("Selecciona una opción: ").strip().lower()
        if opt == "1":
            clear_terminal()
            try:
                ejecutar_app()
            except Exception as exc:
                print(f"Error: {exc}")
            input("\nPresiona Enter para volver al menú...")
            clear_terminal()
        elif opt == "2":
            clear_terminal()
            try:
                ver_tabla()
            except Exception as exc:
                print(f"Error: {exc}")
                input("\nPresiona Enter para volver al menú...")
                clear_terminal()
        elif opt == "3":
            clear_terminal()
            try:
                descargar_anexo()
            except Exception as exc:
                print(f"Error: {exc}")
            input("\nPresiona Enter para volver al menú...")
            clear_terminal()
        elif opt == "q":
            print("Saliendo...")
            break
        else:
            print("Opción inválida. Intenta de nuevo.")


if __name__ == "__main__":
    try:
        logged = login_flow()
        if logged:
            mostrar_menu()
        else:
            print("No se inició sesión. Saliendo...")
    except Exception as e:
        print(f"Error en la aplicación: {e}")
