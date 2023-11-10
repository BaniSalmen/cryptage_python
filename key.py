# encryption_key = os.urandom(32): 
        # Cette ligne génère une clé aléatoire de 32 octets (256 bits) en utilisant la fonction os.urandom() de la bibliothèque Python os. 
        # Cette clé est destinée à être utilisée comme clé de chiffrement.

# encryption_key_hex = encryption_key.hex():
        #  Cette ligne convertit la clé générée en étape précédente en une chaîne hexadécimale. 
        # La variable encryption_key_hex contiendra donc une représentation hexadécimale de la clé générée.

# cmd = f'echo -n "{message}" | openssl enc -aes-256-cbc -a -salt -pass pass:{encryption_key_hex}': 
        # Cette ligne construit une commande en utilisant la chaîne de message à chiffrer (message) 
        # et la clé générée (encryption_key_hex) dans la syntaxe de la commande OpenSSL. 
# Voici une explication des parties de la commande :

# echo -n "{message}": Cela imprime le message dans la sortie standard sans inclure de caractère de nouvelle ligne.

# openssl enc -aes-256-cbc -a -salt -pass pass:{encryption_key_hex}: C'est la partie principale de la commande OpenSSL.
#     Elle indique à OpenSSL d'utiliser l'algorithme de chiffrement AES-256-CBC pour chiffrer les données en entrée. 
#     Les options -a indiquent à OpenSSL de produire une sortie encodée en base64 (utile pour les chaînes de texte), 
#     -salt ajoute un sel aléatoire pour renforcer la sécurité,
#     et -pass pass:{encryption_key_hex} spécifie la clé de chiffrement (la clé générée précédemment, convertie en hexadécimal) à utiliser.