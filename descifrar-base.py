import base64
import multiprocessing
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Archivos
ARCHIVO_MENSAJES = "mensajes_cifrados_3750.txt"   # <-- Cambia por el archivo que generaste
ARCHIVO_DICCIONARIO = "diccionario.txt"
ITERACIONES = 500_000

def derivar_clave(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERACIONES,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def descifrar_mensaje(mensaje_cifrado, password):
    datos = base64.b64decode(mensaje_cifrado)
    salt, iv, cifrado = datos[:16], datos[16:32], datos[32:]
    clave = derivar_clave(password, salt)
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    descifrado = decryptor.update(cifrado) + decryptor.finalize()

    # Desaplicar padding
    unpadder = padding.PKCS7(128).unpadder()
    mensaje = unpadder.update(descifrado) + unpadder.finalize()

    return mensaje.decode()

def intentar_descifrar(args):
    mensaje_cifrado, claves = args
    for clave in claves:
        try:
            mensaje = descifrar_mensaje(mensaje_cifrado, clave)
            return mensaje, clave
        except:
            continue
    return None, None