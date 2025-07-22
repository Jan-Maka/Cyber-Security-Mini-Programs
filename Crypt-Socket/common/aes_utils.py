from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

AES_KEY_SIZE = 32

def generate_aes_key():
    return bytearray(get_random_bytes(AES_KEY_SIZE))

def encrypt_with_aes_gcm(key, data):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag

def decrypt_with_aes_gcm(nonce, tag,ciphertext,key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext,tag)
    return plaintext

def unpack_aes_gcm_data(data):
    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    return nonce, tag, ciphertext

def secure_delete_key(key):
    try:
        for i in range(len(key)):
            key[i] = 0
    except Exception as e:
        print(f"Couldn't overwrite secret: {e}")
    finally:
        del key
        import gc
        gc.collect()