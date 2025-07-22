import socket
import json
import base64
import secrets
import time
import hmac
import threading
from pathlib import Path
from common.rsa_utils import generate_rsa_key_pair, save_rsa_key_to_file, load_rsa_key_from_file, encrypt_with_rsa, decrypt_with_rsa, generate_x509_certificate, save_certificate, verify_certificate, get_user_public_key_from_certificate, verify_signatrue
from common.user import User
from common.socket_utils import send_with_flag, recv_with_flag, send_aes_encrypted_data_with_flag
from common.aes_utils import unpack_aes_gcm_data,decrypt_with_aes_gcm, generate_aes_key, encrypt_with_aes_gcm, secure_delete_key


HOST = '127.0.0.1'      
PORT = 65432
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_KEYS_DIR = Path("server/server_keys")
USER_PUBLIC_KEYS_STORE = Path("server/user_public_keys")
PUBLIC_KEYS_DIR = Path("public_keys")
PUBLIC_KEY_PATH =  SERVER_KEYS_DIR / "server_public.pem"
PRIVATE_KEY_PATH = SERVER_KEYS_DIR / "server_private.pem"

#Before server is booted up check server RSA keys exist and if not generate keys
def check_server_keys_exist():
    if not PUBLIC_KEY_PATH.exists() or not PRIVATE_KEY_PATH.exists():
        print("**GENERATING SERVER RSA KEYS....**")
        private_key, public_key = generate_rsa_key_pair()
        save_rsa_key_to_file(PRIVATE_KEY_PATH, private_key)
        save_rsa_key_to_file(PUBLIC_KEY_PATH,public_key)
        save_rsa_key_to_file(PUBLIC_KEYS_DIR / "server_public.pem", public_key)
        print("**SERVER RSA KEYS GENERATED AND SAVED!!**")

check_server_keys_exist()

SERVER_PUBLIC_KEY = load_rsa_key_from_file(SERVER_KEYS_DIR / "server_public.pem")
SERVER_PRIVATE_KEY = load_rsa_key_from_file(SERVER_KEYS_DIR / "server_private.pem")
SERVER_CERTIFICATE_STORE = Path("server/certificates")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST,PORT))
server.listen(5)

users = {
}

pending_nonces = {
}

#Issues a nonce for users that are logging in
def issue_nonce(username_hash, client_socket):
    nonce = secrets.token_bytes(32)
    pending_nonces[username_hash] = (nonce, time.time())
    user_public_key = users.get(username_hash)["public_key"]
    encrypted_nonce = encrypt_with_rsa(user_public_key, nonce)
    send_with_flag(client_socket,"NONCE",encrypted_nonce)

#Handles the verification of a nonce and whether or not it has expired
def verify_nonce(username_hash, user_nonce):
    entry = pending_nonces.pop(username_hash, None)
    if not entry:
        return False
    
    issued_nonce, timestamp = entry
    if time.time() - timestamp >  300:
        return False
    return hmac.compare_digest(issued_nonce, user_nonce)


#Checks if a user with the username provided exists
def handle_check_user(data, clientsocket):
    username_hash = decrypt_with_rsa(SERVER_PRIVATE_KEY,data).decode()
    if username_hash in users: send_with_flag(clientsocket, "RESPONSE" , b"EXISTS")
    else: send_with_flag(clientsocket, "RESPONSE", b"AVAILABLE")

#Checks if the password inputed matches for the username inputted
def handle_check_user_pass(data, clientsocket):
    login_details_json = decrypt_with_rsa(SERVER_PRIVATE_KEY, data).decode()
    login_details = json.loads(login_details_json)
    
    username = login_details["username"]
    password = login_details["password"]
    user = users.get(username)

    if User.verify_password(password, base64.b64decode(user["password"].encode('utf-8'))):
        send_with_flag(clientsocket, "RESPONSE", b"MATCHES")
        issue_nonce(username,clientsocket)
    else: 
        send_with_flag(clientsocket, "RESPONSE", b"NO_MATCH")

#Decrypts user details sent over using the aes temp key and saves the data, also saves user public key in server directory 
def handle_register(data,aes_temp_key):
    nonce,tag,ciphertext = unpack_aes_gcm_data(data)
    user_json = decrypt_with_aes_gcm(nonce, tag, ciphertext, aes_temp_key).decode()
    secure_delete_key(aes_temp_key)
    user_data = json.loads(user_json)
    users[user_data["user_id"]] = user_data
    save_rsa_key_to_file(USER_PUBLIC_KEYS_STORE / f"{user_data['username']}_public.pem", user_data["public_key"])
    user_certificate = generate_x509_certificate(user_data["public_key"].encode(), SERVER_PRIVATE_KEY,user_data["username"])
    save_certificate(SERVER_CERTIFICATE_STORE / f"{user_data['username']}_certificate.pem", user_certificate)
    send_with_flag(clientsocket, "CERT", user_certificate)

#Verifys and authenticates credentials and generates a session key which is going to be used for further communication between client and server
def handle_login(data, clientsocket):
    user_data = json.loads(data)
    user_hash = user_data["username_hash"]
    user_cert = base64.b64decode(user_data["user_cert"])
    user_nonce = base64.b64decode(user_data["nonce"])
    signature = base64.b64decode(user_data["signature"])

    is_cert_valid = verify_certificate(user_cert, SERVER_PUBLIC_KEY)
    user_public_key = None

    if is_cert_valid: 
        user_public_key = get_user_public_key_from_certificate(user_cert)
    else: 
        send_with_flag(clientsocket, "LOGIN_FAIL", "***LOGIN FAILED DUE TO INVALID CERTIFICATE!***".encode())
        return
    
    is_signature_valid = verify_signatrue(user_public_key,user_nonce,signature)
    if not is_signature_valid: 
        send_with_flag(clientsocket, "LOGIN_FAIL", "***LOGIN FAILED DUE TO INVALID SIGNATURE!***".encode())
        return
    
    is_nonce_valid = verify_nonce(user_hash,user_nonce)
    if not is_nonce_valid: 
        send_with_flag(clientsocket, "LOGIN_FAIL","***LOGIN FAILED DUE TO EXPIRED OR INVLAID NONCE!***".encode())
        return
    
    user = users.get(user_hash)
    user_payload_json = json.dumps({
        "user_id":user["user_id"],
        "username":user["username"],
        "message_queue":user["message_queue"],
        "public_key":user["public_key"]
    }).encode()

    session_key = generate_aes_key()
    user["session_key"] = session_key
    user["connection"] = clientsocket

    users[user_hash] = user

    send_with_flag(clientsocket, "LOGIN_SESH_KEY", encrypt_with_rsa(user_public_key, session_key))
    nonce,ciphertext,tag = encrypt_with_aes_gcm(session_key,user_payload_json)
    send_aes_encrypted_data_with_flag(clientsocket, "LOGIN_SUCCESS", nonce,tag,ciphertext)

def handle_send_msg(clientsocket, data):
    message_payload = json.loads(data)
    reciever = users.get(message_payload["reciever"])
    sender = users.get(message_payload["sender"])
    msg_dict = {
        "sender": sender["username"],
        "nonce": message_payload["nonce"],
        "tag": message_payload["tag"],
        "ciphertext": message_payload["ciphertext"],
        "temp_key": message_payload["temp_key"],
    }

    reciever["message_queue"].append(msg_dict)
    users[message_payload["reciever"]] = reciever
    send_with_flag(clientsocket, "MSG_SENT", "\n**MESSAGE SENT SECURLEY!**\n".encode())
  
#Checks for logged in user messages and sends them over encrypted with shared session key
def handle_read_msgs(user_id, clientsocket):
    user = users.get(user_id)
    message_queue = user["message_queue"]
    session_key = user["session_key"]
    message_queue_json = json.dumps(message_queue)
    nonce, ciphertext, tag = encrypt_with_aes_gcm(session_key, message_queue_json.encode())
    send_aes_encrypted_data_with_flag(clientsocket, "MESSAGES", nonce, tag, ciphertext)
    user["message_queue"] = []
    users[user_id] = user

def handle_client(clientsocket, address):
    aes_temp_reg_key = None
    try:
        while True:
            flag, data = recv_with_flag(clientsocket)

            match flag:
                case "CHECK_USER":
                    handle_check_user(data,clientsocket)
                case "CHECK_PASS":
                    handle_check_user_pass(data,clientsocket)
                case "REG_KEY":
                    aes_temp_reg_key = bytearray(decrypt_with_rsa(SERVER_PRIVATE_KEY, data))
                case "REG":
                    handle_register(data, aes_temp_reg_key)
                    print("\n**USER REGISTERED TO SERVER**\n")
                case "LOGIN":
                    handle_login(data,clientsocket)
                    print("\n***USER LOGGED IN!***\n")
                case "SEND_MSG":
                    handle_send_msg(clientsocket,data)
                case "READ_MSGS":
                    handle_read_msgs(data.decode(), clientsocket)
                case _:
                    print(f"UNKNOWN OPERATION: {flag}")
    except ConnectionError:
        print("Client disconnected or connection lost!")
        clientsocket.close()
    except Exception as e:
        print(f"Unexpected error: {e}")
        clientsocket.close()


while True:
    clientsocket, address = server.accept()
    client_thread = threading.Thread(target=handle_client, args=(clientsocket,address), daemon=True)
    client_thread.start()    

    