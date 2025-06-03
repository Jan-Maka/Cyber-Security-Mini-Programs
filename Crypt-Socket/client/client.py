import socket
import json
from pathlib import Path
from common.rsa_utils import generate_rsa_key_pair, save_rsa_key_to_file, load_rsa_key_from_file, encrypt_with_rsa, save_certificate
from common.user import User
from common.socket_utils import send_with_flag, recv_with_flag, send_aes_encrypted_data_with_flag
from common.aes_utils import generate_aes_key, encrypt_with_aes_gcm

HOST = '127.0.0.1'      
PORT = 65432
PROJECT_ROOT = Path(__file__).resolve().parent.parent
USER_KEYS_DIR = Path("client/user_keys")
PUBLIC_KEYS_STORE = PROJECT_ROOT / "public_keys"
SERVER_PUBLIC_KEY_PATH = PUBLIC_KEYS_STORE / "server_public.pem"
SERVER_PUBLIC_KEY = load_rsa_key_from_file(SERVER_PUBLIC_KEY_PATH)

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.connect((HOST,PORT))


def check_user_exists(username):
    hashed_username = User.hash_username(username)
    encrypted_data = encrypt_with_rsa(SERVER_PUBLIC_KEY,hashed_username.encode())
    send_with_flag(server_sock, "CHECK_USER", encrypted_data)
    flag, response = recv_with_flag(server_sock)
    return response == b"TAKEN"



def login():
    pass

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

    user = User(username_input, password_input, public_key)

    user_json = json.dumps(user.to_dict())

    aes_key_temp = generate_aes_key()
    send_with_flag(server_sock,"REG_KEY", encrypt_with_rsa(SERVER_PUBLIC_KEY,aes_key_temp))
    nonce, ciphertext, tag = encrypt_with_aes_gcm(aes_key_temp,user_json.encode())
    send_aes_encrypted_data_with_flag(server_sock,"REG",nonce,tag,ciphertext)
    flag, certificate = recv_with_flag(server_sock)
    if flag == "CERT": save_certificate(user_dir / "cert.pem", certificate)

    print("\n**REGISTRATION COMPLETE**\n")

def prompt_user_input():
    print("To login enter 'L':")
    print("To Register enter 'R':")
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
        case _:
            print("Invalid input. Please enter 'L' to login or 'R' to register.")

    user_input = prompt_user_input()