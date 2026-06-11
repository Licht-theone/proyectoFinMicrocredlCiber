import sqlite3
import os
import base64
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

DB_FILENAME = 'passwords.db'
SALT_FILENAME = 'salt.bin'


def derive_key(master_password: bytes, salt: bytes) -> bytes:
    """
    Deriva una clave simétrica a partir de la contraseña maestra y la sal usando PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    return key


def init_master_password():
    """
    Inicializa la contraseña maestra y la sal.
    """
    if os.path.exists(SALT_FILENAME):
        print("La sal ya existe. Si deseas cambiar la contraseña maestra, usa la opción correspondiente.")
        return
    salt = os.urandom(16)
    with open(SALT_FILENAME, 'wb') as f:
        f.write(salt)
    print("Sal generada y almacenada.")


def load_salt() -> bytes:
    """
    Carga la sal desde el archivo.
    """
    if not os.path.exists(SALT_FILENAME):
        raise FileNotFoundError("No se encontró el archivo de sal. Ejecuta init.")
    return open(SALT_FILENAME, 'rb').read()


def init_db():
    """
    Crea la base de datos SQLite con la tabla de contraseñas si no existe.
    """
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL,
        username TEXT NOT NULL,
        password BLOB NOT NULL
    )
    ''')
    conn.commit()
    conn.close()
    print("Base de datos inicializada.")


def get_cipher():
    """
    Pide la contraseña maestra al usuario, genera el cifrador.
    """
    salt = load_salt()
    master_pwd = getpass.getpass("Introduce la contraseña maestra: ").encode()
    key = derive_key(master_pwd, salt)
    return Fernet(key)


def add_entry():
    cipher = get_cipher()
    service = input("Servicio: ")
    username = input("Usuario: ")
    pwd = getpass.getpass("Contraseña: ").encode()
    token = cipher.encrypt(pwd)

    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)',
              (service, username, token))
    conn.commit()
    conn.close()
    print("Entrada guardada.")


def list_entries():
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('SELECT id, service, username FROM passwords')
    rows = c.fetchall()
    conn.close()
    print("ID | Servicio | Usuario")
    for row in rows:
        print(f"{row[0]:<3} | {row[1]:<20} | {row[2]}")


def get_entry():
    cipher = get_cipher()
    entry_id = input("ID de la entrada a recuperar: ")
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('SELECT service, username, password FROM passwords WHERE id = ?', (entry_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        print("Entrada no encontrada.")
        return

    service, username, token = row
    pwd = cipher.decrypt(token).decode()
    print(f"Servicio: {service}\nUsuario: {username}\nContraseña: {pwd}")


def delete_entry():
    entry_id = input("ID de la entrada a eliminar: ")
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
    conn.commit()
    conn.close()
    print("Entrada eliminada si existía.")


def change_master_password():
    """
    Permite cambiar la contraseña maestra: descifra y re-cifra todos los datos.
    """
    salt_old = load_salt()
    old_pwd = getpass.getpass("Contraseña maestra actual: ").encode()
    key_old = derive_key(old_pwd, salt_old)
    cipher_old = Fernet(key_old)

    # Solicitar nueva contraseña
    new_pwd = getpass.getpass("Nueva contraseña maestra: ").encode()
    new_salt = os.urandom(16)
    key_new = derive_key(new_pwd, new_salt)
    cipher_new = Fernet(key_new)

    # Re-cifrar todas las contraseñas
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('SELECT id, password FROM passwords')
    rows = c.fetchall()
    for id_, token in rows:
        pwd = cipher_old.decrypt(token)
        new_token = cipher_new.encrypt(pwd)
        c.execute('UPDATE passwords SET password = ? WHERE id = ?', (new_token, id_))
    conn.commit()
    conn.close()

    # Guardar nueva sal
    with open(SALT_FILENAME, 'wb') as f:
        f.write(new_salt)
    print("Contraseña maestra cambiada correctamente.")


def menu():
    init_db()
    while True:
        print("\nGestor de Contraseñas - Opciones:")
        print("1. Inicializar contraseña maestra y sal (solo una vez)")
        print("2. Añadir nueva entrada")
        print("3. Listar entradas")
        print("4. Recuperar contraseña")
        print("5. Eliminar entrada")
        print("6. Cambiar contraseña maestra")
        print("0. Salir")
        choice = input("Selecciona una opción: ")

        if choice == '1':
            init_master_password()
        elif choice == '2':
            add_entry()
        elif choice == '3':
            list_entries()
        elif choice == '4':
            get_entry()
        elif choice == '5':
            delete_entry()
        elif choice == '6':
            change_master_password()
        elif choice == '0':
            break
        else:
            print("Opción no válida.")

if __name__ == '__main__':
    menu()