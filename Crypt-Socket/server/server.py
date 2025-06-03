import socket
import json
from pathlib import Path
from common.rsa_utils import generate_rsa_key_pair, save_rsa_key_to_file, load_rsa_key_from_file, encrypt_with_rsa, decrypt_with_rsa, generate_x509_certificate, save_certificate
from common.user import User
from common.socket_utils import send_with_flag, recv_with_flag
from common.aes_utils import unpack_aes_gcm_data,decrypt_with_aes_gcm


HOST = '127.0.0.1'      
PORT = 65432
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_KEYS_DIR = Path("server/server_keys")
USER_PUBLIC_KEYS_STORE = Path("server/user_public_keys")
PUBLIC_KEYS_STORE = PROJECT_ROOT / "public_keys"
PUBLIC_KEY_PATH =  SERVER_KEYS_DIR / "server_public.pem"
PRIVATE_KEY_PATH = SERVER_KEYS_DIR / "server_private.pem"
SERVER_PUBLIC_KEY = load_rsa_key_from_file(SERVER_KEYS_DIR / "server_public.pem")
SERVER_PRIVATE_KEY = load_rsa_key_from_file(SERVER_KEYS_DIR / "server_private.pem")
SERVER_CERTIFICATE_STORE = Path("server/certificates")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST,PORT))
server.listen(5)

#Before server is booted up check server RSA keys exist and if not generate keys
def check_server_keys_exist():
    if not PUBLIC_KEY_PATH.exists() or not PRIVATE_KEY_PATH.exists():
        print("**GENERATING SERVER RSA KEYS....**")
        private_key, public_key = generate_rsa_key_pair()
        save_rsa_key_to_file(PRIVATE_KEY_PATH, private_key)
        save_rsa_key_to_file(PUBLIC_KEY_PATH,public_key)
        save_rsa_key_to_file(PUBLIC_KEYS_STORE, public_key)
        print("**SERVER RSA KEYS GENERATED AND SAVED!!**")

check_server_keys_exist()

users = {
}

#Checks the availabilty of a username during registration
def handle_check_user(data, clientsocket):
    username_hash = decrypt_with_rsa(SERVER_PRIVATE_KEY,data).decode()
    if username_hash in users: send_with_flag(clientsocket, "RESPONSE" , b"TAKEN")
    else: send_with_flag(clientsocket, "RESPONSE", b"AVAILABLE")

#Decrypts user details sent over using the aes temp key and saves the data, also saves user public key in server directory 
def handle_register(data,aes_temp_key):
    nonce,tag,ciphertext = unpack_aes_gcm_data(data)
    user_json = decrypt_with_aes_gcm(nonce, tag, ciphertext, aes_temp_key).decode()
    user_data = json.loads(user_json)
    users[user_data["user_id"]] = user_data
    save_rsa_key_to_file(USER_PUBLIC_KEYS_STORE / f"{user_data['username']}_public.pem", user_data["public_key"])
    user_certificate = generate_x509_certificate(user_data["public_key"].encode(), SERVER_PRIVATE_KEY,user_data["username"])
    save_certificate(SERVER_CERTIFICATE_STORE / f"{user_data['username']}_certificate.pem", user_certificate)
    send_with_flag(clientsocket, "CERT", user_certificate)

def register_user_public_key(data):
    pass
def handle_login():
    pass

def handle_send_msg():
    pass

def handle_read_msgs():
    pass

while True:
    clientsocket, address = server.accept()
    aes_temp_reg_key = None
    try:
        while True:
            flag, data = recv_with_flag(clientsocket)

            match flag:
                case "CHECK_USER":
                    handle_check_user(data,clientsocket)
                case "REG_KEY":
                    aes_temp_reg_key = decrypt_with_rsa(SERVER_PRIVATE_KEY, data)
                case "REG":
                    handle_register(data, aes_temp_reg_key)
                    print("\n**USER REGISTERED TO SERVER**\n")
                case "LOGIN":
                    handle_login()
                case "MSG":
                    handle_send_msg()
                case "READ_MSGS":
                    handle_read_msgs()
                case _:
                    print(f"UNKNOWN OPERATION: {flag}")
    except ConnectionError:
        print("Client disconnected or connection lost!")
        clientsocket.close()
    except Exception as e:
        print(f"Unexpected error: {e}")
        clientsocket.close()

    