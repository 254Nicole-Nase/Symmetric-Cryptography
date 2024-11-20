import requests
from Crypto.Util.strxor import strxor

# Base URL for the challenge
BASE_URL = "https://aes.cryptohack.org/flipping_cookie"

# Get a cookie and its IV
def get_cookie():
    response = requests.get(f"{BASE_URL}/get_cookie/")
    response_data = response.json()
    cookie = bytes.fromhex(response_data["cookie"][32:])  # Extract cookie (ciphertext)
    iv = bytes.fromhex(response_data["cookie"][:32])     # Extract IV
    return cookie, iv

# Submit the modified cookie to check admin access
def check_admin(cookie, iv):
    response = requests.get(f"{BASE_URL}/check_admin/{cookie.hex()}/{iv.hex()}/")
    return response.json()

# Flip the bits to make "admin=False" -> "admin=True"
def flip_cookie():
    # Step 1: Get the cookie and IV
    cookie, iv = get_cookie()

    # Step 2: Define target text and desired text
    target_text = b"admin=False;"  # 12 bytes
    desired_text = b"admin=True;"  # 11 bytes

    # Ensure the lengths match for XORing
    if len(target_text) > len(desired_text):
        desired_text = desired_text.ljust(len(target_text), b" ")
    elif len(desired_text) > len(target_text):
        target_text = target_text.ljust(len(desired_text), b" ")

    # Step 3: XOR the target and desired plaintexts to calculate the flipping mask
    flip_mask = strxor(target_text, desired_text)

    # Step 4: Apply the flip mask to the appropriate part of the IV
    modified_iv = iv[:len(flip_mask)]  # First block of the IV
    modified_iv = strxor(modified_iv, flip_mask) + iv[len(flip_mask):]  # Ensure full 16-byte IV

    # Step 5: Submit the modified cookie and IV to check admin access
    result = check_admin(cookie, modified_iv)
    print(result)

# Run the attack
flip_cookie()
