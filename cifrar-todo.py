import os
import base64
import random
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuración
ARCHIVO_MENSAJES = "mensajes_cifrados.txt"
ARCHIVO_DICCIONARIO = "diccionario.txt"
ITERACIONES = 500_000

def derivar_clave(password, salt, iteraciones=ITERACIONES):
    """Genera una clave AES con PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iteraciones,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def cifrar_mensaje(mensaje, password):
    """Cifra un mensaje con AES y PBKDF2 usando padding PKCS7."""
    salt = os.urandom(16)
    clave = derivar_clave(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Aplicamos padding PKCS7 para que el mensaje sea múltiplo de 16
    padder = padding.PKCS7(128).padder()
    mensaje_padded = padder.update(mensaje.encode()) + padder.finalize()

    cifrado = encryptor.update(mensaje_padded) + encryptor.finalize()
    return base64.b64encode(salt + iv + cifrado).decode()

def main():
    # Verificar si los archivos existen
    if not os.path.exists(ARCHIVO_MENSAJES):
        print(f"❌ ERROR: No se encontró el archivo {ARCHIVO_MENSAJES}")
        return

    if not os.path.exists(ARCHIVO_DICCIONARIO):
        print(f"❌ ERROR: No se encontró el archivo {ARCHIVO_DICCIONARIO}")
        return

    # Leer mensajes originales
    with open(ARCHIVO_MENSAJES, "r", encoding="utf-8") as f:
        mensajes = [line.strip() for line in f if line.strip()]

    # Leer claves desde diccionario.txt
    with open(ARCHIVO_DICCIONARIO, "r", encoding="utf-8") as f:
        claves = [line.strip() for line in f if line.strip()]

    # Generar nombre del archivo de salida con un número aleatorio
    numero = random.randint(1000, 9999)
    archivo_salida = f"mensajes_cifrados_{numero}.txt"

    # Cifrar mensajes con claves aleatorias del diccionario
    with open(archivo_salida, "w", encoding="utf-8") as f:
        for mensaje in mensajes:
            clave = random.choice(claves)  # Elegir clave aleatoria
            mensaje_cifrado = cifrar_mensaje(mensaje, clave)
            f.write(mensaje_cifrado + "\n")

    print(f"✅ Mensajes cifrados guardados en: {archivo_salida}")

if __name__ == "__main__":
    main()
