import os

# Génération d'une clé de chiffrement aléatoire et sécurisée
def generate_encryption_key():
    return os.urandom(32)  # 32 octets (256 bits) pour AES-256

encryption_key = generate_encryption_key()
