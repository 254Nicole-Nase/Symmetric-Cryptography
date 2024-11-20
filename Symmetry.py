import requests
from Crypto.Util.number import long_to_bytes, bytes_to_long

BASE_URL = "https://aes.cryptohack.org/symmetry/"

def encrypt_flag():
    """Fetches the encrypted flag."""
    response = requests.get(BASE_URL + "encrypt_flag/")
    ciphertext = bytes.fromhex(response.json()["ciphertext"])
    iv = ciphertext[:16]  # Often the IV is prepended to the ciphertext
    actual_ciphertext = ciphertext[16:]
    return actual_ciphertext, iv

def encrypt(plaintext, iv):
    """Fetches the ciphertext for a given plaintext and IV."""
    response = requests.get(BASE_URL + f"encrypt/{plaintext.hex()}/{iv.hex()}/")
    return bytes.fromhex(response.json()["ciphertext"])

def xor(a, b):
    """Performs XOR on two byte arrays."""
    return long_to_bytes(bytes_to_long(a) ^ bytes_to_long(b))

# Step 1: Retrieve the encrypted flag and IV
ciphertext, iv = encrypt_flag()

# Step 2: Encrypt a block of zero bytes with the same IV to obtain the keystream
keystream = encrypt(b"\x00" * len(ciphertext), iv)

# Step 3: XOR the ciphertext with the keystream to recover the plaintext (flag)
plaintext = xor(ciphertext, keystream)

print("Decrypted Flag:", plaintext.decode())

