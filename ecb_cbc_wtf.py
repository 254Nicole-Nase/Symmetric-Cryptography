import requests
from Crypto.Util.strxor import strxor  # A utility to XOR byte strings

BASE_URL = "https://aes.cryptohack.org/ecbcbcwtf"

def get_ciphertext():
    """Fetch the encrypted ciphertext from the server."""
    response = requests.get(f"{BASE_URL}/encrypt_flag/")
    response.raise_for_status()
    return bytes.fromhex(response.json()["ciphertext"])

def decrypt_block(block):
    """Decrypt a single ciphertext block using ECB mode."""
    response = requests.get(f"{BASE_URL}/decrypt/{block.hex()}/")
    response.raise_for_status()
    return bytes.fromhex(response.json()["plaintext"])

def decrypt_flag():
    """Decrypt the flag using the CBC exploit."""
    ciphertext = get_ciphertext()
    block_size = 16  # AES block size
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

    print(f"Ciphertext Blocks: {[block.hex() for block in blocks]}")

    decrypted_flag = b""

    for i in range(len(blocks)):
        if i == 0:
            # The first block uses IV for CBC (assumed to be all-zero in many challenges)
            iv = b"\x00" * block_size
            decrypted_block = decrypt_block(blocks[i])
            plaintext_block = strxor(decrypted_block, iv)
        else:
            # For other blocks, XOR decrypted_block with the previous ciphertext block
            decrypted_block = decrypt_block(blocks[i])
            plaintext_block = strxor(decrypted_block, blocks[i-1])

        print(f"Decrypted Block {i}: {plaintext_block.hex()}")
        decrypted_flag += plaintext_block

    # Try to remove PKCS#7 padding
    try:
        padding_length = decrypted_flag[-1]
        if padding_length < 1 or padding_length > block_size:
            raise ValueError("Invalid padding length")
        # Check if all padding bytes match
        if decrypted_flag[-padding_length:] != bytes([padding_length]) * padding_length:
            raise ValueError("Invalid padding bytes")
        decrypted_flag = decrypted_flag[:-padding_length]
    except ValueError as e:
        print(f"Warning: {e}. Showing raw decrypted flag.")
        return decrypted_flag  # Return raw bytes if padding is invalid

    return decrypted_flag

if __name__ == "__main__":
    flag = decrypt_flag()
    print("Flag (raw bytes):", flag)
    try:
        print("Flag (decoded):", flag.decode())
    except UnicodeDecodeError:
        print("Flag contains non-UTF-8 characters. Process as raw bytes.")

