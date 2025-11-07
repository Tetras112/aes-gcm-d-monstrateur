"""

Alexandre Marconnot

Démonstrateur pédagogique AES-GCM
- Montre pas à pas le chiffrement et le déchiffrement en mode Galois/Counter (GCM)
- Affiche les valeurs intermédiaires (H, J0, GHASH, TAG, etc.)
- Combine délai automatique et pause manuelle pour présentation orale

Dépendances :
    pip install pycryptodome
"""

import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import struct
import binascii

# --------------------------
# Paramètres de présentation
# --------------------------
DELAY = 2.5        # Délai entre les étapes principales
BLOCK_DELAY = 1.5  # Délai entre les blocs CTR
MANUAL_STEP = True  # Si True, appuyer sur Entrée entre chaque étape

# --------------------------
# Fonctions utilitaires
# --------------------------
def wait(t=DELAY):
    """Pause combinant délai automatique et attente manuelle."""
    if MANUAL_STEP:
        input("\n(Appuyez sur Entrée pour continuer...)")
    else:
        time.sleep(t)

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')

def int_to_bytes(value: int, length=16) -> bytes:
    return value.to_bytes(length, byteorder='big')

def xor_blocks(block_a: bytes, block_b: bytes) -> bytes:
    """XOR entre deux blocs de taille égale."""
    return bytes(x ^ y for x, y in zip(block_a, block_b))

def format_hex(data: bytes) -> str:
    """Affichage lisible en hexadécimal."""
    return binascii.hexlify(data).decode()

# --------------------------
# Multiplication dans GF(2^128)
# --------------------------
R_POLYNOMIAL = 0xE1000000000000000000000000000000

def galois_multiply(x: int, y: int) -> int:
    """Multiplication dans le champ fini GF(2^128)."""
    result = 0
    current = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            result ^= current
        lsb = current & 1
        current >>= 1
        if lsb:
            current ^= R_POLYNOMIAL
    return result & ((1 << 128) - 1)

# --------------------------
# Fonction GHASH
# --------------------------
def ghash(subkey_H: bytes, additional_data: bytes, ciphertext: bytes) -> bytes:
    """Calcul de la fonction GHASH utilisée dans AES-GCM."""
    H_int = bytes_to_int(subkey_H)
    accumulator = 0

    def split_blocks(data):
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            if len(block) < 16:
                block += b'\x00' * (16 - len(block))
            yield block

    for block in split_blocks(additional_data):
        accumulator ^= bytes_to_int(block)
        accumulator = galois_multiply(accumulator, H_int)

    for block in split_blocks(ciphertext):
        accumulator ^= bytes_to_int(block)
        accumulator = galois_multiply(accumulator, H_int)

    len_block = struct.pack(">QQ", len(additional_data) * 8, len(ciphertext) * 8)
    accumulator ^= bytes_to_int(len_block)
    accumulator = galois_multiply(accumulator, H_int)

    return int_to_bytes(accumulator)

# --------------------------
# Gestion du compteur (CTR)
# --------------------------
def increment_counter(counter_block: bytes) -> bytes:
    """Incrémente la partie compteur (les 32 derniers bits)."""
    prefix = counter_block[:12]
    counter_value = int.from_bytes(counter_block[12:], 'big')
    counter_value = (counter_value + 1) & 0xffffffff
    return prefix + counter_value.to_bytes(4, 'big')

# --------------------------
# Chiffrement AES bloc unique (ECB)
# --------------------------
def aes_encrypt_block(key: bytes, input_block: bytes) -> bytes:
    """Chiffrement d’un bloc de 128 bits avec AES-ECB."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(input_block)

# --------------------------
# Démonstration du chiffrement AES-GCM
# --------------------------
def aes_gcm_encrypt_demo(key: bytes, iv: bytes, plaintext: bytes, aad: bytes):
    print("\n========== CHIFFREMENT AES-GCM ==========")
    print("Clé (Key) :", format_hex(key))
    print("IV :", format_hex(iv))
    print("AAD (Additional Authenticated Data) :", format_hex(aad))
    print("Texte clair (Plaintext) :", plaintext)
    wait()

    # Étape 1 : Calcul de la sous-clé H
    subkey_H = aes_encrypt_block(key, b'\x00'*16)
    print("\n[1] Sous-clé H = E_K(0^128) =", format_hex(subkey_H))
    wait()

    # Étape 2 : Initialisation du compteur J0
    initial_counter_J0 = iv + b'\x00\x00\x00\x01'
    print("[2] Bloc initial J0 =", format_hex(initial_counter_J0))
    wait()

    # Étape 3 : Chiffrement CTR
    ciphertext = b''
    counter_block = initial_counter_J0
    print("\n[3] Chiffrement CTR :")
    wait()
    for i in range(0, len(plaintext), 16):
        plaintext_block = plaintext[i:i+16]
        keystream_block = aes_encrypt_block(key, counter_block)
        ciphertext_block = xor_blocks(plaintext_block, keystream_block[:len(plaintext_block)])
        ciphertext += ciphertext_block
        print(f" Bloc {i//16}:")
        print(f"   CTR       = {format_hex(counter_block)}")
        print(f"   Keystream = {format_hex(keystream_block)}")
        print(f"   Plaintext Block         = {format_hex(plaintext_block)}")
        print(f"   Ciphertext Block         = {format_hex(ciphertext_block)}")
        counter_block = increment_counter(counter_block)
        wait(BLOCK_DELAY)

    # Étape 4 : Calcul de GHASH
    ghash_result = ghash(subkey_H, aad, ciphertext)
    print("\n[4] GHASH(AAD, Ciphertext) =", format_hex(ghash_result))
    wait()

    # Étape 5 : Calcul du tag d’authentification
    tag = xor_blocks(aes_encrypt_block(key, initial_counter_J0), ghash_result)
    print("[5] Tag = E_K(J0) XOR GHASH =", format_hex(tag))
    wait()

    return ciphertext, tag, subkey_H, initial_counter_J0

# --------------------------
# Démonstration du déchiffrement AES-GCM
# --------------------------
def aes_gcm_decrypt_demo(key: bytes, iv: bytes, aad: bytes, ciphertext: bytes, tag: bytes, subkey_H: bytes, initial_counter_J0: bytes):
    print("\n========== DÉCHIFFREMENT AES-GCM ==========")
    print("Clé :", format_hex(key))
    print("IV  :", format_hex(iv))
    print("AAD :", format_hex(aad))
    print("Ciphertext :", format_hex(ciphertext))
    print("Tag attendu :", format_hex(tag))
    wait()

    # Étape 1 : Vérification du tag
    print("\n[1] Recalcul du GHASH pour vérification...")
    ghash_computed = ghash(subkey_H, aad, ciphertext)
    print("    GHASH =", format_hex(ghash_computed))
    wait()

    recalculated_tag = xor_blocks(aes_encrypt_block(key, initial_counter_J0), ghash_computed)
    print("[2] Tag recalculé =", format_hex(recalculated_tag))
    if recalculated_tag == tag:
        print("Authentification réussie : tag valide.")
    else:
        print("Authentification échouée : tag invalide !")
    wait()

    # Étape 2 : Déchiffrement CTR
    print("\n[3] Déchiffrement CTR :")
    wait()
    plaintext_recovered = b''
    counter_block = initial_counter_J0
    for i in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[i:i+16]
        keystream_block = aes_encrypt_block(key, counter_block)
        plaintext_block = xor_blocks(ciphertext_block, keystream_block[:len(ciphertext_block)])
        plaintext_recovered += plaintext_block
        print(f" Bloc {i//16}:")
        print(f"   CTR       = {format_hex(counter_block)}")
        print(f"   Keystream = {format_hex(keystream_block)}")
        print(f"   Ciphertext Block         = {format_hex(ciphertext_block)}")
        print(f"   Plaintext Block         = {format_hex(plaintext_block)}")
        counter_block = increment_counter(counter_block)
        wait(BLOCK_DELAY)

    print("\nTexte clair récupéré :", plaintext_recovered)
    wait()
    return plaintext_recovered

# --------------------------
# Exemple d’utilisation
# --------------------------
if __name__ == "__main__":
    aes_key = get_random_bytes(16)
    initialization_vector = get_random_bytes(12)
    additional_authenticated_data = b"AuthDataExample"
    plaintext_message = b"CAEN"

    ciphertext, tag, H, J0 = aes_gcm_encrypt_demo(
        aes_key, initialization_vector, plaintext_message, additional_authenticated_data
    )
    recovered_plaintext = aes_gcm_decrypt_demo(
        aes_key, initialization_vector, additional_authenticated_data, ciphertext, tag, H, J0
    )
