import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Ruta del diccionario de contraseñas
diccionario_path = "diccionario.txt"

def derivar_clave(password, salt, iteraciones=5000000):
    """Genera una clave derivada con PBKDF2 usando SHA-256"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # ← CORRECCIÓN: Usar cryptography.hazmat.primitives.hashes
        length=32,
        salt=salt,
        iterations=iteraciones,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def cifrar_mensaje(mensaje, password):
    """Cifra un mensaje con AES y una clave derivada de PBKDF2"""
    salt = os.urandom(16)  # Generar un salt aleatorio
    clave = derivar_clave(password, salt)  # Derivar clave con alto coste computacional

    iv = os.urandom(16)  # Vector de inicialización
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding para que el mensaje sea múltiplo de 16
    padding_len = 16 - (len(mensaje) % 16)
    mensaje += chr(padding_len) * padding_len

    mensaje_cifrado = encryptor.update(mensaje.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + mensaje_cifrado).decode()  # Codificar en Base64



def descifrar_mensaje(mensaje_cifrado, password, iteraciones=500000):
    """Descifra un mensaje cifrado con AES y PBKDF2"""
    datos = base64.b64decode(mensaje_cifrado)
    salt, iv, mensaje_encriptado = datos[:16], datos[16:32], datos[32:]

    clave = derivar_clave(password, salt, iteraciones)  # Coste alto en tiempo
    cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    mensaje_descifrado = decryptor.update(mensaje_encriptado) + decryptor.finalize()
    padding_len = ord(mensaje_descifrado[-1:])
    return mensaje_descifrado[:-padding_len].decode()

def ataque_diccionario(mensaje_cifrado, diccionario_path):
    """Intenta descifrar el mensaje probando cada contraseña del diccionario."""
    with open(diccionario_path, "r", encoding="utf-8") as f:
        posibles_claves = [line.strip() for line in f.readlines()]  # Cargar el diccionario

    for clave in posibles_claves:
        try:
            mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, clave)
            print(f"✅ ¡Contraseña encontrada! → {clave}")
            print(f"🔓 Mensaje descifrado: {mensaje_descifrado}")
            return
        except:
            pass  # La clave no funcionó, sigue con la siguiente

    print("❌ No se encontró la contraseña en el diccionario.")

# EJEMPLO DE PRUEBA
password_real = "mypassword"  # La clave real
mensaje_original = "Este es un mensaje ultra secreto."

# Cifrar el mensaje con la clave real
mensaje_cifrado = cifrar_mensaje(mensaje_original, password_real)
print(f"🔐 Mensaje cifrado: {mensaje_cifrado}\n")

# Intentar descifrar con el diccionario
ataque_diccionario(mensaje_cifrado, diccionario_path)
