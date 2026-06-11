# Gestor de Contraseñas en Python (CLI)

Un gestor de contraseñas de línea de comandos (CLI) seguro, desarrollado en Python y respaldado por una base de datos SQLite. Este proyecto fue creado como Proyecto Final de Microcredencial para aplicar conceptos prácticos de criptografía, manejo de bases de datos y seguridad de la información.

## Características

* **Cifrado Fuerte:** Utiliza la librería estándar `cryptography` (AES de 128 bits a través de Fernet).
* **Derivación de Claves Segura:** Implementa `PBKDF2HMAC` con SHA-256 y 390,000 iteraciones junto con una "sal" criptográfica aleatoria para proteger la contraseña maestra contra ataques de fuerza bruta.
* **Almacenamiento Local:** Los datos se guardan localmente de forma estructurada en una base de datos SQLite (`passwords.db`).
* **Gestión Completa (CRUD):** Permite añadir, listar, recuperar y eliminar credenciales.
* **Rotación de Contraseñas:** Incluye un sistema para cambiar la contraseña maestra que descifra y vuelve a cifrar de forma segura toda la bóveda de contraseñas de manera automatizada.

## Arquitectura de Seguridad

1. La **Contraseña Maestra** nunca se almacena en ninguna parte.
2. Al inicializar, se genera una **Sal Criptográfica** (`salt.bin`) de 16 bytes.
3. Se deriva una clave simétrica combinando la contraseña maestra del usuario y la sal usando **PBKDF2**.
4. Cada contraseña guardada se cifra individualmente usando **Fernet**, que garantiza tanto la confidencialidad (cifrado) como la integridad (autenticación) de los datos.

## Instalación y Uso

### Requisitos previos
* Python 3.7 o superior.
* Librería `cryptography`.

# Disclaimer
Este es un proyecto académico y de aprendizaje creado para entender los fundamentos de la criptografía aplicada. Aunque utiliza estándares seguros, para el uso diario personal se recomienda utilizar gestores de contraseñas comerciales o de código abierto auditados por profesionales.
