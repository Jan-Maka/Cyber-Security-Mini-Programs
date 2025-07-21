import socket
import json
import base64
import time
from pathlib import Path
from common.rsa_utils import generate_rsa_key_pair, save_rsa_key_to_file, load_rsa_key_from_file, encrypt_with_rsa, save_certificate, load_certficate, sign_data, decrypt_with_rsa, verify_signatrue
from common.user import User
from common.socket_utils import send_with_flag, recv_with_flag, send_aes_encrypted_data_with_flag
from common.aes_utils import generate_aes_key, encrypt_with_aes_gcm, unpack_aes_gcm_data, decrypt_with_aes_gcm

HOST = '127.0.0.1'      
PORT = 65432
PROJECT_ROOT = Path(__file__).resolve().parent.parent
USER_KEYS_DIR = Path("client/user_keys")
PUBLIC_KEYS_STORE = PROJECT_ROOT / "public_keys"
SERVER_PUBLIC_KEY_PATH = PUBLIC_KEYS_STORE / "server_public.pem"
SERVER_PUBLIC_KEY = load_rsa_key_from_file(SERVER_PUBLIC_KEY_PATH)

logged_in_user = None
session_key = None

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.connect((HOST,PORT))

def check_user_exists(username):
    hashed_username = User.hash_username(username)
    encrypted_data = encrypt_with_rsa(SERVER_PUBLIC_KEY,hashed_username.encode())
    send_with_flag(server_sock, "CHECK_USER", encrypted_data)
    flag, response = recv_with_flag(server_sock)
    return response == b"EXISTS"

def check_pass_valid(username, password):
    login_payload = json.dumps({
        "username" : User.hash_username(username),
        "password" : password
    })
    encrypted_data = encrypt_with_rsa(SERVER_PUBLIC_KEY, login_payload.encode())
    send_with_flag(server_sock, "CHECK_PASS", encrypted_data)
    flag, response = recv_with_flag(server_sock)
    return response == b'MATCHES'

def get_nonce():
    flag,response = recv_with_flag(server_sock)
    if flag == "NONCE": return response

# Handles communciation with server when a user is trying to login to the server
def login():
    global logged_in_user
    global session_key
    print("\n**USER LOGIN**\n")
    username_input = ""
    while True:
        username_input = input("Enter username of account: ")
        if not check_user_exists(username_input): print(f"User with  username ({username_input}) doesn't exist!")
        else: break

    while True:
        password_input = input("Enter password for account: ")
        if not check_pass_valid(username_input,password_input): print("Password doesn't match with username inputted!")
        else: break

    user_dir = USER_KEYS_DIR / username_input
    user_private_key = load_rsa_key_from_file(user_dir / "private.pem")
    user_nonce = decrypt_with_rsa(user_private_key,get_nonce())

    user_certificate = load_certficate(user_dir / "cert.pem")
    signed_nonce = sign_data(user_private_key,user_nonce)

    payload = json.dumps({
        "username_hash": User.hash_username(username_input),
        "user_cert": base64.b64encode(user_certificate).decode("utf-8"),
        "nonce": base64.b64encode(user_nonce).decode("utf-8"),
        "signature": base64.b64encode(signed_nonce).decode("utf-8")
    })
    send_with_flag(server_sock,"LOGIN",payload.encode())

    flag,response = recv_with_flag(server_sock)
    if flag == "LOGIN_FAIL":
        print(response.decode())
        login()
        return
    elif flag == "LOGIN_SESH_KEY": 
        session_key = decrypt_with_rsa(user_private_key,response)
        flag, response = recv_with_flag(server_sock)
        if flag == "LOGIN_SUCCESS":
            nonce, tag, ciphertext = unpack_aes_gcm_data(response)
            user_json = decrypt_with_aes_gcm(nonce,tag,ciphertext,session_key).decode()
            logged_in_user = json.loads(user_json)
            logged_in_user["private_key"] = load_rsa_key_from_file(user_dir / "private.pem")
            
            print(f"\n***WELCOME BACK {username_input}!***\n")

#Creates a new user and sends data to the server
def register():
    print("\n**USER REGISTRATION**\n")
    while True:
        username_input = input("Enter a username: ")
        if(check_user_exists(username_input)): print("Username already exists! Please enter another username!")
        else: break
    
    while True:
        password_input = input("Enter a password: ")
        reenter_password = input("Re-enter password: ")
        if reenter_password != password_input: print("Passwords do not match! Please enter a password again!")
        else: break

    #Create directory for the user to store their rsa key pairs
    user_dir = USER_KEYS_DIR / username_input
    user_dir.mkdir(parents=True,exist_ok=True)

    private_key, public_key = generate_rsa_key_pair()

    save_rsa_key_to_file(user_dir / "private.pem" ,private_key)
    save_rsa_key_to_file(user_dir /"public.pem",public_key)
    save_rsa_key_to_file(PUBLIC_KEYS_STORE/ f"{username_input}_public.pem", public_key)

    user = User(username_input, password_input, public_key)

    user_json = json.dumps(user.to_dict())

    aes_key_temp = generate_aes_key()
    send_with_flag(server_sock,"REG_KEY", encrypt_with_rsa(SERVER_PUBLIC_KEY,aes_key_temp))
    nonce, ciphertext, tag = encrypt_with_aes_gcm(aes_key_temp,user_json.encode())
    send_aes_encrypted_data_with_flag(server_sock,"REG",nonce,tag,ciphertext)
    flag, certificate = recv_with_flag(server_sock)
    if flag == "CERT": save_certificate(user_dir / "cert.pem", certificate)

    print("\n**REGISTRATION COMPLETE**\n")

def read_messages():
    print("\n**USER MESSAGES**\n")
    send_with_flag(server_sock, "READ_MSGS", logged_in_user["user_id"].encode())
    flag, response = recv_with_flag(server_sock)
    if flag != "MESSAGES": return

    nonce, tag, ciphertext = unpack_aes_gcm_data(response)
    messages = json.loads(decrypt_with_aes_gcm(nonce,tag,ciphertext, session_key))

    if len(messages) == 0: print("No new messages!")
    for msg in messages:
        temp_msg_key = decrypt_with_rsa(logged_in_user["private_key"],base64.b64decode(msg["temp_key"]))
        message = json.loads(decrypt_with_aes_gcm(base64.b64decode(msg["nonce"]), base64.b64decode(msg["tag"]),base64.b64decode(msg["ciphertext"]), temp_msg_key))

        signed_data = json.dumps({
            "content": message["content"],
            "timestamp": message["timestamp"]
        }).encode()
        
        sender_pub_key = load_rsa_key_from_file(PUBLIC_KEYS_STORE / f"{msg['sender']}_public.pem")
        is_signature_valid = verify_signatrue(sender_pub_key,signed_data,base64.b64decode(message["signature"]))
        
        if is_signature_valid:
            print("--------------------")
            print(f"From: {msg['sender']}")
            print(f"Time: {message['timestamp']}")
            print(f"Message: {message['content']}")
            print("--------------------")
        else:
            print("--------------------")
            print("SIGNATURE NOT VALID MESSAGE ALTERED!")
            print("--------------------")


    print("\n**END OF MESSAGES**\n")

def send_message():
    print("\n**SEND MESSAGE TO USER**\n")

    reciever = ""
    while True:
        reciever = input("Enter the user to message: ")
        if not check_user_exists(reciever): print("USER DOES NOT EXIST")
        else: break

    user_message = input("Enter the message for user: ")
    time_stamp = int(time.time())
    data_to_sign = json.dumps({
        "content": user_message,
        "timestamp": time_stamp
    }).encode()

    signature = sign_data(logged_in_user["private_key"], data_to_sign)
    inner_payload = json.dumps({
        "content": user_message,
        "timestamp": time_stamp,
        "signature": base64.b64encode(signature).decode()
    }).encode()

    msg_temp_key = generate_aes_key()
    print(msg_temp_key)
    nonce, ciphertext, tag = encrypt_with_aes_gcm(msg_temp_key, inner_payload)
    encrypted_temp_key = encrypt_with_rsa(load_rsa_key_from_file(PUBLIC_KEYS_STORE / f"{reciever}_public.pem"),msg_temp_key)

    message_payload = json.dumps({
        "reciever": User.hash_username(reciever),
        "sender": logged_in_user["user_id"],
        "temp_key": base64.b64encode(encrypted_temp_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }).encode()
    
    send_with_flag(server_sock,"SEND_MSG", message_payload)
    flag, data = recv_with_flag(server_sock)
    if flag == "MSG_SENT":  print(data.decode())

def prompt_user_input():
    if logged_in_user is None:
        print("To login enter 'L':")
        print("To Register enter 'R':")
    else:
        print("To read your messages enter: 'READ':")
        print("To send a message to a user enter: 'SEND':")
    print("To Quit type 'QUIT':")
    return input("Command: ")

user_input = prompt_user_input()

while user_input.upper() != "QUIT":
    match user_input.lower():
        case 'l':
            login()
        case 'r':
            register()
        case 'quit':
            pass
        case 'read':
            read_messages()
        case 'send':
            send_message()
        case _:
            print("Invalid input. Please enter 'L' to login or 'R' to register.")

    user_input = prompt_user_input()